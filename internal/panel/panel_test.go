package panel

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func newTestServer(t *testing.T) (*Server, http.Handler) {
	t.Helper()
	u := &Users{Path: filepath.Join(t.TempDir(), "users.json")}
	if err := u.Load(); err != nil {
		t.Fatal(err)
	}
	api := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("api user=" + r.Header.Get("X-Mahan-User")))
	})
	s := &Server{Users: u, API: api, Version: "test"}
	return s, s.Handler()
}

func do(h http.Handler, method, path, body string, cookie *http.Cookie, hdr map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.RemoteAddr = "192.168.88.10:5555"
	if cookie != nil {
		req.AddCookie(cookie)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestLoginSessionAndCSRF(t *testing.T) {
	_, h := newTestServer(t)
	if r := do(h, "GET", "/api/v1/status", "", nil, nil); r.Code != 401 {
		t.Fatalf("no session: got %d", r.Code)
	}
	r := do(h, "POST", "/panel/api/login", `{"username":"admin","password":"mahan"}`, nil, nil)
	if r.Code != 200 || !strings.Contains(r.Body.String(), `"must_change":true`) {
		t.Fatalf("login: %d %s", r.Code, r.Body)
	}
	var c *http.Cookie
	for _, x := range r.Result().Cookies() {
		if x.Name == cookieName {
			c = x
		}
	}
	if c == nil || !c.HttpOnly || c.SameSite != http.SameSiteStrictMode {
		t.Fatalf("cookie: %+v", c)
	}
	// spoofed user header is replaced
	r = do(h, "GET", "/api/v1/status", "", c, map[string]string{"X-Mahan-User": "root"})
	if r.Code != 200 || r.Body.String() != "api user=panel:admin" {
		t.Fatalf("api via session: %d %q", r.Code, r.Body)
	}
	if r = do(h, "PUT", "/api/v1/config/candidate.json", "{}", c, nil); r.Code != 403 {
		t.Fatalf("PUT without X-Requested-With: %d", r.Code)
	}
	if r = do(h, "PUT", "/api/v1/config/candidate.json", "{}", c, map[string]string{"X-Requested-With": "mahan-panel"}); r.Code != 200 {
		t.Fatalf("PUT with header: %d", r.Code)
	}
	// change password, then the old one stops working
	hdr := map[string]string{"X-Requested-With": "mahan-panel"}
	if r = do(h, "POST", "/panel/api/password", `{"current":"mahan","new":"short"}`, c, hdr); r.Code != 400 {
		t.Fatalf("short password accepted: %d", r.Code)
	}
	if r = do(h, "POST", "/panel/api/password", `{"current":"mahan","new":"Str0ng-pass"}`, c, hdr); r.Code != 200 {
		t.Fatalf("password change: %d %s", r.Code, r.Body)
	}
	if r = do(h, "POST", "/panel/api/login", `{"username":"admin","password":"mahan"}`, nil, nil); r.Code != 401 {
		t.Fatalf("old password still works: %d", r.Code)
	}
	if r = do(h, "POST", "/panel/api/login", `{"username":"admin","password":"Str0ng-pass"}`, nil, nil); r.Code != 200 {
		t.Fatalf("new password: %d", r.Code)
	}
	// logout ends the session
	do(h, "POST", "/panel/api/logout", "", c, nil)
	if r = do(h, "GET", "/panel/api/me", "", c, nil); r.Code != 401 {
		t.Fatalf("session alive after logout: %d", r.Code)
	}
}

func TestLoginLockout(t *testing.T) {
	_, h := newTestServer(t)
	for i := 0; i < 5; i++ {
		do(h, "POST", "/panel/api/login", `{"username":"admin","password":"bad"}`, nil, nil)
	}
	r := do(h, "POST", "/panel/api/login", `{"username":"admin","password":"mahan"}`, nil, nil)
	if r.Code != http.StatusTooManyRequests {
		t.Fatalf("expected lockout, got %d", r.Code)
	}
}

func TestStaticFallback(t *testing.T) {
	_, h := newTestServer(t)
	r := do(h, "GET", "/firewall/filter", "", nil, nil)
	if r.Code != 200 || !strings.Contains(r.Body.String(), "<") {
		t.Fatalf("spa fallback: %d", r.Code)
	}
	if r.Header().Get("Content-Security-Policy") == "" {
		t.Fatal("no CSP header")
	}
}

func TestPasswordHash(t *testing.T) {
	h, err := hashPassword("x-secret-1")
	if err != nil {
		t.Fatal(err)
	}
	if !verifyPassword(h, "x-secret-1") || verifyPassword(h, "x-secret-2") {
		t.Fatal("verify mismatch")
	}
}
