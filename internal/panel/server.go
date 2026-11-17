package panel

import (
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net"
	"net/http"
	"path"
	"strings"
	"sync"
	"time"
)

//go:embed all:dist
var distFS embed.FS

const (
	cookieName = "mr_session"
	sessionTTL = 12 * time.Hour
	idleTTL    = 2 * time.Hour
)

type session struct {
	user    string
	expires time.Time
	seen    time.Time
}

// Server serves the panel: auth endpoints, the API behind a session, and
// the single-page app.
type Server struct {
	Users   *Users
	API     http.Handler // api.Server.Handler(true); the panel adds its own auth
	Version string

	mu       sync.Mutex
	sessions map[string]*session
	fails    map[string]*failState
}

type failState struct {
	count int
	until time.Time
}

func (s *Server) init() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sessions == nil {
		s.sessions = map[string]*session{}
		s.fails = map[string]*failState{}
	}
}

// Handler returns the panel routes.
func (s *Server) Handler() http.Handler {
	s.init()
	mux := http.NewServeMux()
	mux.HandleFunc("POST /panel/api/login", s.login)
	mux.HandleFunc("POST /panel/api/logout", s.logout)
	mux.HandleFunc("GET /panel/api/me", s.withSession(s.me))
	mux.HandleFunc("POST /panel/api/password", s.withSession(s.password))
	mux.HandleFunc("GET /panel/api/users", s.withSession(s.listUsers))
	mux.HandleFunc("POST /panel/api/users", s.withSession(s.addUser))
	mux.HandleFunc("DELETE /panel/api/users/{name}", s.withSession(s.deleteUser))
	mux.Handle("/api/", s.withSession(func(w http.ResponseWriter, r *http.Request, u string) {
		r.Header.Set("X-Mahan-User", "panel:"+u)
		s.API.ServeHTTP(w, r)
	}))
	mux.HandleFunc("/", s.static)
	return securityHeaders(mux)
}

func securityHeaders(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hd := w.Header()
		hd.Set("X-Content-Type-Options", "nosniff")
		hd.Set("X-Frame-Options", "DENY")
		hd.Set("Referrer-Policy", "no-referrer")
		hd.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'")
		if r.TLS != nil {
			hd.Set("Strict-Transport-Security", "max-age=31536000")
		}
		h.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func clientIP(r *http.Request) string {
	h, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return h
}

// withSession requires a valid session cookie. State-changing requests must
// also carry X-Requested-With (a cross-site form cannot set it), on top of
// the SameSite=Strict cookie.
func (s *Server) withSession(next func(http.ResponseWriter, *http.Request, string)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(cookieName)
		var user string
		if err == nil {
			s.mu.Lock()
			if ss, ok := s.sessions[c.Value]; ok {
				now := time.Now()
				if now.After(ss.expires) || now.Sub(ss.seen) > idleTTL {
					delete(s.sessions, c.Value)
				} else {
					ss.seen = now
					user = ss.user
				}
			}
			s.mu.Unlock()
		}
		if user == "" {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "not signed in"})
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Header.Get("X-Requested-With") != "mahan-panel" {
			writeJSON(w, http.StatusForbidden, map[string]any{"error": "missing X-Requested-With header"})
			return
		}
		next(w, r, user)
	}
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	s.mu.Lock()
	f := s.fails[ip]
	if f != nil && time.Now().Before(f.until) {
		wait := time.Until(f.until).Round(time.Second)
		s.mu.Unlock()
		writeJSON(w, http.StatusTooManyRequests, map[string]any{"error": "too many failed attempts", "retry_after": int(wait.Seconds())})
		return
	}
	s.mu.Unlock()

	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
		writeJSON(w, 400, map[string]any{"error": "bad request"})
		return
	}
	u, ok := s.Users.Check(strings.TrimSpace(req.Username), req.Password)
	s.mu.Lock()
	defer s.mu.Unlock()
	if !ok {
		if f == nil {
			f = &failState{}
			s.fails[ip] = f
		}
		f.count++
		if f.count >= 5 {
			// 30 s after 5 failures, doubling up to 15 minutes
			d := 30 * time.Second << min(f.count-5, 5)
			f.until = time.Now().Add(min(d, 15*time.Minute))
		}
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "wrong user name or password"})
		return
	}
	delete(s.fails, ip)
	tok := make([]byte, 32)
	_, _ = rand.Read(tok)
	id := hex.EncodeToString(tok)
	now := time.Now()
	// drop expired sessions while we hold the lock
	for k, v := range s.sessions {
		if now.After(v.expires) || now.Sub(v.seen) > idleTTL {
			delete(s.sessions, k)
		}
	}
	s.sessions[id] = &session{user: u.Name, expires: now.Add(sessionTTL), seen: now}
	http.SetCookie(w, &http.Cookie{
		Name: cookieName, Value: id, Path: "/", HttpOnly: true,
		Secure: r.TLS != nil, SameSite: http.SameSiteStrictMode, MaxAge: int(sessionTTL.Seconds()),
	})
	writeJSON(w, 200, map[string]any{"user": u.Name, "must_change": u.MustChange})
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(cookieName); err == nil {
		s.mu.Lock()
		delete(s.sessions, c.Value)
		s.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) me(w http.ResponseWriter, r *http.Request, user string) {
	u, _ := s.Users.Get(user)
	writeJSON(w, 200, map[string]any{"user": user, "must_change": u.MustChange, "version": s.Version})
}

func (s *Server) password(w http.ResponseWriter, r *http.Request, user string) {
	var req struct {
		Current string `json:"current"`
		New     string `json:"new"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
		writeJSON(w, 400, map[string]any{"error": "bad request"})
		return
	}
	if _, ok := s.Users.Check(user, req.Current); !ok {
		writeJSON(w, 403, map[string]any{"error": "current password is wrong"})
		return
	}
	if err := s.Users.SetPassword(user, req.New, false); err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) listUsers(w http.ResponseWriter, r *http.Request, _ string) {
	writeJSON(w, 200, s.Users.List())
}

func (s *Server) addUser(w http.ResponseWriter, r *http.Request, _ string) {
	var req struct {
		Name     string `json:"name"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
		writeJSON(w, 400, map[string]any{"error": "bad request"})
		return
	}
	if err := s.Users.SetPassword(req.Name, req.Password, true); err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) deleteUser(w http.ResponseWriter, r *http.Request, user string) {
	name := r.PathValue("name")
	if name == user {
		writeJSON(w, 400, map[string]any{"error": "you cannot delete yourself"})
		return
	}
	if err := s.Users.Delete(name); err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	// end that user's sessions
	s.mu.Lock()
	for k, v := range s.sessions {
		if v.user == name {
			delete(s.sessions, k)
		}
	}
	s.mu.Unlock()
	writeJSON(w, 200, map[string]any{"ok": true})
}

// static serves the built app; unknown paths get index.html (client routing).
func (s *Server) static(w http.ResponseWriter, r *http.Request) {
	sub, err := fs.Sub(distFS, "dist")
	if err != nil {
		http.Error(w, "panel not built", 500)
		return
	}
	p := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
	if p == "" {
		p = "index.html"
	}
	if st, err := fs.Stat(sub, p); err != nil || st.IsDir() {
		p = "index.html"
	}
	data, err := fs.ReadFile(sub, p)
	if errors.Is(err, fs.ErrNotExist) {
		http.Error(w, "web panel is not built into this binary (make web)", 404)
		return
	}
	if strings.HasPrefix(p, "assets/") {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	} else {
		w.Header().Set("Cache-Control", "no-cache")
	}
	http.ServeContent(w, r, p, time.Time{}, strings.NewReader(string(data)))
}

// RedirectHTTPS sends plain-HTTP visitors to the HTTPS panel.
func RedirectHTTPS(httpsPort string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		if httpsPort != "" && httpsPort != "443" {
			host = net.JoinHostPort(host, httpsPort)
		}
		http.Redirect(w, r, "https://"+host+r.URL.RequestURI(), http.StatusMovedPermanently)
	})
}
