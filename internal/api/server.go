// Package api exposes core-agent over REST. The CLI and the web panel use
// the same endpoints.
//
// The Unix socket is for local root tools and needs no token; the TCP
// listener requires a bearer token.
package api

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/ashayesteh86/MahanRouter/internal/agent"
	"github.com/ashayesteh86/MahanRouter/internal/config"
	"github.com/ashayesteh86/MahanRouter/internal/render"
	"github.com/ashayesteh86/MahanRouter/internal/store"
)

// Server is the HTTP API.
type Server struct {
	Agent   *agent.Agent
	Token   string // required on TCP; empty disables token auth
	Version string
}

const maxBody = 4 << 20

// Handler returns the API routes. trusted=true skips token auth (Unix socket).
func (s *Server) Handler(trusted bool) http.Handler {
	mux := s.Routes()
	if trusted {
		return withUser(mux, "root")
	}
	return s.auth(mux)
}

// Routes returns the API without authentication. The caller must
// authenticate and set X-Mahan-User (the web panel does this).
func (s *Server) Routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/config/candidate.json", s.getCandidateJSON)
	mux.HandleFunc("PUT /api/v1/config/candidate.json", s.putCandidateJSON)
	mux.HandleFunc("GET /api/v1/config/running.json", s.getRunningJSON)
	mux.HandleFunc("GET /api/v1/system", s.system)
	mux.HandleFunc("GET /api/v1/interfaces", s.interfaces)
	mux.HandleFunc("GET /api/v1/routes", s.routes)
	mux.HandleFunc("GET /api/v1/dhcp/leases", s.leases)
	mux.HandleFunc("POST /api/v1/tools", s.tool)
	mux.HandleFunc("GET /api/v1/config/running", s.getRunning)
	mux.HandleFunc("GET /api/v1/config/candidate", s.getCandidate)
	mux.HandleFunc("PUT /api/v1/config/candidate", s.putCandidate)
	mux.HandleFunc("DELETE /api/v1/config/candidate", s.deleteCandidate)
	mux.HandleFunc("POST /api/v1/config/validate", s.validate)
	mux.HandleFunc("GET /api/v1/config/diff", s.diff)
	mux.HandleFunc("GET /api/v1/config/render", s.renderPreview)
	mux.HandleFunc("POST /api/v1/commit", s.commit)
	mux.HandleFunc("POST /api/v1/confirm", s.confirm)
	mux.HandleFunc("GET /api/v1/history", s.history)
	mux.HandleFunc("GET /api/v1/history/{rev}", s.showRev)
	mux.HandleFunc("POST /api/v1/rollback", s.rollback)
	mux.HandleFunc("GET /api/v1/status", s.status)
	mux.HandleFunc("GET /api/v1/firewall/counters", s.counters)
	return mux
}

func withUser(h http.Handler, user string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Header.Set("X-Mahan-User", user)
		h.ServeHTTP(w, r)
	})
}

func (s *Server) auth(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if s.Token == "" || subtle.ConstantTimeCompare([]byte(tok), []byte(s.Token)) != 1 {
			writeErr(w, http.StatusUnauthorized, errors.New("missing or wrong API token"))
			return
		}
		r.Header.Set("X-Mahan-User", "api")
		h.ServeHTTP(w, r)
	})
}

func user(r *http.Request) string {
	if u := r.Header.Get("X-Mahan-User"); u != "" {
		return u
	}
	return "unknown"
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func writeErr(w http.ResponseWriter, code int, err error) {
	body := map[string]any{"error": err.Error()}
	var ve *config.ValidationError
	if errors.As(err, &ve) {
		body["problems"] = ve.Problems
	}
	writeJSON(w, code, body)
}

func writeYAML(w http.ResponseWriter, data []byte) {
	w.Header().Set("Content-Type", "application/yaml")
	_, _ = w.Write(data)
}

func (s *Server) getRunning(w http.ResponseWriter, r *http.Request) {
	data, err := s.Agent.Store.Running()
	if err != nil {
		writeErr(w, 500, err)
		return
	}
	writeYAML(w, data)
}

func (s *Server) getCandidate(w http.ResponseWriter, r *http.Request) {
	data, err := s.Agent.Store.Candidate()
	if err != nil {
		writeErr(w, 500, err)
		return
	}
	writeYAML(w, data)
}

// putCandidate stores a candidate. It must parse; full validation errors
// are returned as a warning so a half-finished edit can still be saved.
func (s *Server) putCandidate(w http.ResponseWriter, r *http.Request) {
	data, err := io.ReadAll(io.LimitReader(r.Body, maxBody))
	if err != nil {
		writeErr(w, 400, err)
		return
	}
	c, err := config.Parse(data)
	if err != nil {
		writeErr(w, 400, err)
		return
	}
	if err := s.Agent.Store.SetCandidate(data); err != nil {
		writeErr(w, 500, err)
		return
	}
	resp := map[string]any{"saved": true, "valid": true}
	if err := config.Validate(c); err != nil {
		resp["valid"] = false
		var ve *config.ValidationError
		if errors.As(err, &ve) {
			resp["problems"] = ve.Problems
		}
	}
	writeJSON(w, 200, resp)
}

func (s *Server) deleteCandidate(w http.ResponseWriter, r *http.Request) {
	if err := s.Agent.Store.DiscardCandidate(); err != nil {
		writeErr(w, 500, err)
		return
	}
	writeJSON(w, 200, map[string]any{"discarded": true})
}

// validate checks the posted document, or the candidate when the body is empty.
func (s *Server) validate(w http.ResponseWriter, r *http.Request) {
	data, _ := io.ReadAll(io.LimitReader(r.Body, maxBody))
	if len(strings.TrimSpace(string(data))) == 0 {
		var err error
		if data, err = s.Agent.Store.Candidate(); err != nil {
			writeErr(w, 500, err)
			return
		}
	}
	if _, _, err := agent.Prepare(data); err != nil {
		writeErr(w, 422, err)
		return
	}
	writeJSON(w, 200, map[string]any{"valid": true})
}

func (s *Server) diff(w http.ResponseWriter, r *http.Request) {
	run, err := s.Agent.Store.Running()
	if err != nil {
		writeErr(w, 500, err)
		return
	}
	cand, err := s.Agent.Store.Candidate()
	if err != nil {
		writeErr(w, 500, err)
		return
	}
	d, err := store.Diff(run, cand, "running", "candidate")
	if err != nil {
		writeErr(w, 500, err)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = io.WriteString(w, d)
}

// renderPreview shows the files the candidate would produce. Secrets
// (WireGuard keys, PPP secrets) are masked.
func (s *Server) renderPreview(w http.ResponseWriter, r *http.Request) {
	data, err := s.Agent.Store.Candidate()
	if err != nil {
		writeErr(w, 500, err)
		return
	}
	_, b, err := agent.Prepare(data)
	if err != nil {
		writeErr(w, 422, err)
		return
	}
	out := map[string]render.File{}
	for p, f := range b {
		if strings.HasPrefix(p, render.SecretsDir) || strings.HasSuffix(p, "-secrets") {
			f.Content = "(secret)"
		}
		out[p] = f
	}
	writeJSON(w, 200, out)
}

type commitReq struct {
	Message        string `json:"message"`
	ConfirmSeconds int    `json:"confirm_seconds"`
}

func (s *Server) commit(w http.ResponseWriter, r *http.Request) {
	var req commitReq
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		writeErr(w, 400, err)
		return
	}
	if req.ConfirmSeconds < 0 || req.ConfirmSeconds > 3600 {
		writeErr(w, 400, errors.New("confirm_seconds must be 0-3600"))
		return
	}
	res, err := s.Agent.Commit(req.Message, user(r), time.Duration(req.ConfirmSeconds)*time.Second)
	if err != nil {
		code := 500
		var ve *config.ValidationError
		switch {
		case errors.Is(err, agent.ErrNoChanges):
			code = 409
		case errors.As(err, &ve):
			code = 422
		}
		body := map[string]any{"error": err.Error()}
		if ve != nil {
			body["problems"] = ve.Problems
		}
		if res != nil {
			body["apply"] = res.Apply
		}
		writeJSON(w, code, body)
		return
	}
	writeJSON(w, 200, res)
}

func (s *Server) confirm(w http.ResponseWriter, r *http.Request) {
	if err := s.Agent.Confirm(); err != nil {
		writeErr(w, 409, err)
		return
	}
	writeJSON(w, 200, map[string]any{"confirmed": true})
}

func (s *Server) history(w http.ResponseWriter, r *http.Request) {
	n, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	revs, err := s.Agent.Store.History(n)
	if err != nil {
		writeErr(w, 500, err)
		return
	}
	writeJSON(w, 200, revs)
}

func (s *Server) showRev(w http.ResponseWriter, r *http.Request) {
	data, err := s.Agent.Store.Show(r.PathValue("rev"))
	if err != nil {
		writeErr(w, 404, err)
		return
	}
	writeYAML(w, data)
}

func (s *Server) rollback(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Revision string `json:"revision"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req); err != nil || req.Revision == "" {
		writeErr(w, 400, errors.New(`body must be {"revision": "<hash or HEAD~N>"}`))
		return
	}
	res, err := s.Agent.Rollback(req.Revision, user(r))
	if err != nil {
		writeErr(w, 500, err)
		return
	}
	writeJSON(w, 200, res)
}

func (s *Server) status(w http.ResponseWriter, r *http.Request) {
	head, _ := s.Agent.Store.Head()
	resp := map[string]any{
		"revision":      head,
		"has_candidate": s.Agent.Store.HasCandidate(),
		"pending":       s.Agent.Pending(),
	}
	if out, err := exec.Command("ip", "-j", "-d", "addr").Output(); err == nil {
		resp["interfaces"] = json.RawMessage(out)
	}
	writeJSON(w, 200, resp)
}

// counters returns packet/byte counters per rule tag (f0, n1, ...).
func (s *Server) counters(w http.ResponseWriter, r *http.Request) {
	out, err := exec.Command("nft", "-j", "list", "table", "inet", "mahan").Output()
	if err != nil {
		writeErr(w, 503, errors.New("firewall table not loaded"))
		return
	}
	res, err := ParseCounters(out)
	if err != nil {
		writeErr(w, 500, err)
		return
	}
	writeJSON(w, 200, res)
}

// Counter is the hit count of one configured rule.
type Counter struct {
	Packets uint64 `json:"packets"`
	Bytes   uint64 `json:"bytes"`
}

// ParseCounters sums nft -j counters by rule tag (a rule rendered for
// both IPv4 and IPv6 has two nft rules with the same tag).
func ParseCounters(nftJSON []byte) (map[string]Counter, error) {
	var doc struct {
		Nftables []map[string]json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal(nftJSON, &doc); err != nil {
		return nil, err
	}
	res := map[string]Counter{}
	for _, item := range doc.Nftables {
		raw, ok := item["rule"]
		if !ok {
			continue
		}
		var rule struct {
			Comment string            `json:"comment"`
			Expr    []json.RawMessage `json:"expr"`
		}
		if json.Unmarshal(raw, &rule) != nil || rule.Comment == "" {
			continue
		}
		tag, _, _ := strings.Cut(rule.Comment, " ")
		for _, e := range rule.Expr {
			var ex struct {
				Counter *Counter `json:"counter"`
			}
			if json.Unmarshal(e, &ex) == nil && ex.Counter != nil {
				c := res[tag]
				c.Packets += ex.Counter.Packets
				c.Bytes += ex.Counter.Bytes
				res[tag] = c
			}
		}
	}
	return res, nil
}
