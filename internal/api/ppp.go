package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/ashayesteh86/MahanRouter/internal/config"
	"github.com/ashayesteh86/MahanRouter/internal/pki"
	"github.com/ashayesteh86/MahanRouter/internal/render"
)

// PPPSession is one connected PPP server client (accel-ppp).
type PPPSession struct {
	Ifname   string `json:"ifname"`
	Username string `json:"username"`
	IP       string `json:"ip"`
	Type     string `json:"type"`
	State    string `json:"state"`
	Uptime   int64  `json:"uptime"`
	From     string `json:"from"`
	RxBytes  uint64 `json:"rx_bytes"`
	TxBytes  uint64 `json:"tx_bytes"`
}

// PPPServerState is the PPP server's live state.
type PPPServerState struct {
	RozanehState
	Sessions []PPPSession `json:"sessions"`
}

func (s *Server) pppStatus(w http.ResponseWriter, r *http.Request) {
	out := []RozanehState{}
	var server *PPPServerState
	data, err := s.Agent.Store.Running()
	if err == nil {
		if c, err := config.Parse(data); err == nil {
			for i := range c.Interfaces {
				ifc := &c.Interfaces[i]
				switch ifc.Type {
				case config.IfPPTP, config.IfSSTP:
					out = append(out, tunnelState(r.Context(), ifc.Name, ifc.Type, render.PPPClientUnit(ifc.Name)))
				case config.IfL2TP:
					st := tunnelState(r.Context(), ifc.Name, ifc.Type, render.XL2TPDUnit)
					out = append(out, st)
				case config.IfEoIP, config.IfEoIPv6:
					out = append(out, tunnelState(r.Context(), ifc.Name, ifc.Type, render.EoIPUnit(ifc.Name)))
				case config.IfL2TPv3, config.IfGRE, config.IfIPIP, config.If6to4, config.IfGRE6:
					st := tunnelState(r.Context(), ifc.Name, ifc.Type, "")
					st.Active = map[bool]string{true: "active", false: "inactive"}[st.Up]
					out = append(out, st)
				}
			}
			if c.PPPServer != nil {
				st := PPPServerState{RozanehState: tunnelState(r.Context(), "", "ppp_server", render.PPPServerUnit), Sessions: []PPPSession{}}
				if st.Active == "active" {
					st.Sessions = pppSessions(r.Context())
				}
				server = &st
			}
		}
	}
	writeJSON(w, 200, map[string]any{"interfaces": out, "server": server, "now": time.Now().Unix()})
}

var accelCols = []string{"ifname", "username", "ip", "type", "state", "uptime-raw", "calling-sid", "rx-bytes-raw", "tx-bytes-raw"}

func accelCmd(ctx context.Context, args ...string) ([]byte, error) {
	host, port, _ := net.SplitHostPort(render.AccelCLI)
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, "accel-cmd", append([]string{"-H", host, "-p", port, "-t", "3"}, args...)...).Output()
}

func pppSessions(ctx context.Context) []PPPSession {
	out := []PPPSession{}
	b, err := accelCmd(ctx, "show", "sessions", strings.Join(accelCols, ","))
	if err != nil {
		return out
	}
	return parseAccelSessions(string(b))
}

// parseAccelSessions reads accel-cmd's table: a header row, a dashed
// line, then one "|"-separated row per session.
func parseAccelSessions(s string) []PPPSession {
	out := []PPPSession{}
	for _, line := range strings.Split(s, "\n") {
		f := strings.Split(line, "|")
		if len(f) != len(accelCols) {
			continue
		}
		for i := range f {
			f[i] = strings.TrimSpace(f[i])
		}
		if f[0] == "ifname" || strings.HasPrefix(f[0], "-") {
			continue
		}
		up, _ := strconv.ParseInt(f[5], 10, 64)
		rx, _ := strconv.ParseUint(f[7], 10, 64)
		tx, _ := strconv.ParseUint(f[8], 10, 64)
		out = append(out, PPPSession{Ifname: f[0], Username: f[1], IP: f[2], Type: f[3], State: f[4], Uptime: up, From: f[6], RxBytes: rx, TxBytes: tx})
	}
	return out
}

var sessIfRe = regexp.MustCompile(`^` + config.PPPServerIf + `[0-9]{1,5}$`)

// pppDisconnect ends one PPP server session (the client may dial again).
func (s *Server) pppDisconnect(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Ifname string `json:"ifname"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
		writeErr(w, 400, err)
		return
	}
	if !sessIfRe.MatchString(req.Ifname) {
		writeErr(w, 422, errors.New("not a PPP server session"))
		return
	}
	if _, err := accelCmd(r.Context(), "terminate", "if", req.Ifname, "hard"); err != nil {
		writeErr(w, 500, err)
		return
	}
	writeJSON(w, 200, map[string]string{"status": "ok"})
}

// pppSSTPCert makes a self-signed certificate for the SSTP server.
func (s *Server) pppSSTPCert(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
		writeErr(w, 400, err)
		return
	}
	cert, key, err := pki.SelfSignedCert(strings.TrimSpace(req.Name), 10*365*24*time.Hour)
	if err != nil {
		writeErr(w, 422, err)
		return
	}
	writeJSON(w, 200, map[string]string{"cert_pem": cert, "key_pem": key})
}
