package api

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
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
	// OpenVPN is the OpenVPN server unit, when it is configured.
	OpenVPN *RozanehState `json:"openvpn,omitempty"`
	// IKEv2 is strongSwan and the clients' interface, when IKEv2 is on.
	IKEv2 *RozanehState `json:"ikev2,omitempty"`
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
				case config.IfOpenVPN:
					out = append(out, tunnelState(r.Context(), ifc.Name, ifc.Type, render.OpenVPNUnit(ifc.Name)))
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
				if c.PPPServer.OpenVPN != nil {
					ov := tunnelState(r.Context(), config.OpenVPNServerIf, "openvpn_server", render.OpenVPNUnit(config.OpenVPNServerIf))
					st.OpenVPN = &ov
					if ov.Active == "active" {
						st.Sessions = append(st.Sessions, openVPNSessions(render.OpenVPNStatus, time.Now())...)
					}
					if !c.PPPServer.Running() {
						// Only OpenVPN: the server is as up as its unit.
						st.Active = ov.Active
					}
				}
				if c.PPPServer.IKEv2On() {
					ik := tunnelState(r.Context(), config.IKEv2ServerIf, "ikev2_server", render.IPsecUnit)
					st.IKEv2 = &ik
					if ik.Active == "active" {
						st.Sessions = append(st.Sessions, ikev2Sessions(r.Context())...)
					}
					if !c.PPPServer.Running() && st.OpenVPN == nil {
						st.Active = ik.Active
					}
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
	if addr, ok := strings.CutPrefix(req.Ifname, ovpnSessPrefix); ok {
		ap, err := netip.ParseAddrPort(addr)
		if err != nil {
			writeErr(w, 422, errors.New("not an OpenVPN session"))
			return
		}
		if err := openVPNKill(r.Context(), ap.String()); err != nil {
			writeErr(w, 500, err)
			return
		}
		writeJSON(w, 200, map[string]string{"status": "ok"})
		return
	}
	if id, ok := strings.CutPrefix(req.Ifname, ikev2SessPrefix); ok {
		if _, err := strconv.ParseUint(id, 10, 32); err != nil {
			writeErr(w, 422, errors.New("not an IKEv2 session"))
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
		defer cancel()
		if err := exec.CommandContext(ctx, "swanctl", "--terminate", "--ike-id", id, "--force", "--timeout", "5").Run(); err != nil {
			writeErr(w, 500, err)
			return
		}
		writeJSON(w, 200, map[string]string{"status": "ok"})
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

// pppIKEv2Cert makes a certificate authority and a server certificate for
// the IKEv2 server.
func (s *Server) pppIKEv2Cert(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
		writeErr(w, 400, err)
		return
	}
	ca, cert, key, err := pki.ServerCertWithCA(strings.TrimSpace(req.Name), 10*365*24*time.Hour)
	if err != nil {
		writeErr(w, 422, err)
		return
	}
	writeJSON(w, 200, map[string]string{"ca_pem": ca, "cert_pem": cert, "key_pem": key})
}

// ovpnSessPrefix marks OpenVPN sessions; the rest is the client's
// address:port, which the management interface kills by.
const ovpnSessPrefix = "ovpn:"

// openVPNSessions reads the server's status file (status-version 2).
func openVPNSessions(file string, now time.Time) []PPPSession {
	out := []PPPSession{}
	b, err := os.ReadFile(file)
	if err != nil {
		return out
	}
	return parseOpenVPNStatus(string(b), now)
}

func parseOpenVPNStatus(s string, now time.Time) []PPPSession {
	out := []PPPSession{}
	col := map[string]int{}
	for _, line := range strings.Split(s, "\n") {
		f := strings.Split(strings.TrimRight(line, "\r"), ",")
		switch {
		case len(f) > 2 && f[0] == "HEADER" && f[1] == "CLIENT_LIST":
			for i, h := range f[2:] {
				col[h] = i + 1
			}
		case len(f) > 1 && f[0] == "CLIENT_LIST" && len(col) > 0:
			get := func(h string) string {
				if i, ok := col[h]; ok && i < len(f) {
					return f[i]
				}
				return ""
			}
			rx, _ := strconv.ParseUint(get("Bytes Received"), 10, 64)
			tx, _ := strconv.ParseUint(get("Bytes Sent"), 10, 64)
			since, _ := strconv.ParseInt(get("Connected Since (time_t)"), 10, 64)
			up := int64(0)
			if since > 0 {
				up = now.Unix() - since
			}
			user := get("Username")
			if user == "" || user == "UNDEF" {
				user = get("Common Name")
			}
			real := get("Real Address")
			from := real
			if ap, err := netip.ParseAddrPort(real); err == nil {
				from = ap.Addr().Unmap().String()
			}
			out = append(out, PPPSession{Ifname: ovpnSessPrefix + real, Username: user, IP: get("Virtual Address"),
				Type: "openvpn", State: "active", Uptime: up, From: from, RxBytes: rx, TxBytes: tx})
		}
	}
	return out
}

// openVPNKill disconnects one client through the management socket.
func openVPNKill(ctx context.Context, addr string) error {
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", render.OpenVPNMgmt)
	if err != nil {
		return err
	}
	defer conn.Close()
	dl, _ := ctx.Deadline()
	_ = conn.SetDeadline(dl)
	rd := bufio.NewReader(conn)
	if _, err := rd.ReadString('\n'); err != nil { // >INFO banner
		return err
	}
	if _, err := fmt.Fprintf(conn, "kill %s\r\n", addr); err != nil {
		return err
	}
	for {
		l, err := rd.ReadString('\n')
		if err != nil {
			return err
		}
		switch {
		case strings.HasPrefix(l, "SUCCESS:"):
			return nil
		case strings.HasPrefix(l, "ERROR:"):
			return errors.New(strings.TrimSpace(strings.TrimPrefix(l, "ERROR:")))
		}
	}
}
