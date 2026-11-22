package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/ashayesteh86/MahanRouter/internal/config"
	"github.com/ashayesteh86/MahanRouter/internal/render"
)

// IPsecChild is one pair of subnets of a site-to-site tunnel.
type IPsecChild struct {
	Name     string `json:"name"`
	State    string `json:"state"`
	LocalTS  string `json:"local_ts"`
	RemoteTS string `json:"remote_ts"`
	BytesIn  uint64 `json:"bytes_in"`
	BytesOut uint64 `json:"bytes_out"`
	ESP      string `json:"esp,omitempty"`
}

// IPsecState is the live state of one site-to-site tunnel.
type IPsecState struct {
	Name string `json:"name"`
	// State is "up" (at least one subnet pair has keys), "connecting"
	// (talking to the peer, no keys yet) or "down".
	State       string       `json:"state"`
	IKEState    string       `json:"ike_state,omitempty"`
	RemoteHost  string       `json:"remote_host,omitempty"`
	RemoteID    string       `json:"remote_id,omitempty"`
	LocalHost   string       `json:"local_host,omitempty"`
	Established uint64       `json:"established,omitempty"` // seconds
	IKE         string       `json:"ike,omitempty"`
	NAT         bool         `json:"nat,omitempty"`
	Children    []IPsecChild `json:"children"`
}

// viciNode is a section of `swanctl --raw` output.
type viciNode struct {
	KV   map[string]string
	List map[string][]string
	Sub  map[string]*viciNode
	// Order keeps the sub-section names as printed.
	Order []string
}

func newViciNode() *viciNode {
	return &viciNode{KV: map[string]string{}, List: map[string][]string{}, Sub: map[string]*viciNode{}}
}

// parseVici reads the text swanctl prints with --raw:
//
//	name {key=value list=[a b] sub {...}}
func parseVici(s string) *viciNode {
	var toks []string
	cur := strings.Builder{}
	flush := func() {
		if cur.Len() > 0 {
			toks = append(toks, cur.String())
			cur.Reset()
		}
	}
	for _, r := range s {
		switch r {
		case '{', '}', '[', ']':
			flush()
			toks = append(toks, string(r))
		case ' ', '\n', '\t', '\r':
			flush()
		default:
			cur.WriteRune(r)
		}
	}
	flush()
	root := newViciNode()
	stack := []*viciNode{root}
	for i := 0; i < len(toks); i++ {
		t := toks[i]
		top := stack[len(stack)-1]
		switch {
		case t == "}":
			if len(stack) > 1 {
				stack = stack[:len(stack)-1]
			}
		case t == "{" || t == "[" || t == "]":
			// stray: ignore
		case i+1 < len(toks) && toks[i+1] == "{":
			n := newViciNode()
			top.Sub[t] = n
			top.Order = append(top.Order, t)
			stack = append(stack, n)
			i++
		case i+1 < len(toks) && toks[i+1] == "[":
			t = strings.TrimSuffix(t, "=") // lists print as key=[a b]
			j := i + 2
			items := []string{}
			for ; j < len(toks) && toks[j] != "]"; j++ {
				items = append(items, toks[j])
			}
			top.List[t] = items
			i = j
		default:
			if k, v, ok := strings.Cut(t, "="); ok {
				top.KV[k] = v
			}
		}
	}
	return root
}

func viciAlg(n *viciNode, keys ...string) string {
	var out []string
	for _, k := range keys {
		if v := n.KV[k]; v != "" {
			if ks := n.KV[strings.TrimSuffix(k, "-alg")+"-keysize"]; ks != "" && strings.HasSuffix(k, "encr-alg") {
				v += "-" + ks
			}
			out = append(out, v)
		}
	}
	return strings.ToLower(strings.Join(out, " / "))
}

// ipsecStates turns `swanctl --list-sas --raw` into one state per tunnel.
func ipsecStates(raw string, names []string) []IPsecState {
	byConn := map[string]*IPsecState{}
	out := make([]IPsecState, len(names))
	for i, n := range names {
		out[i] = IPsecState{Name: n, State: "down", Children: []IPsecChild{}}
		byConn[render.IPsecConnName(n)] = &out[i]
	}
	for _, line := range strings.Split(raw, "\n") {
		root := parseVici(line)
		ev := root.Sub["event"]
		if ev == nil {
			continue
		}
		for _, conn := range ev.Order {
			st, sa := byConn[conn], ev.Sub[conn]
			if st == nil {
				continue
			}
			// Several IKE SAs can exist while one is replaced: keep the best.
			cand := IPsecState{Name: st.Name, State: "connecting", IKEState: sa.KV["state"], Children: []IPsecChild{},
				RemoteHost: sa.KV["remote-host"], RemoteID: sa.KV["remote-id"], LocalHost: sa.KV["local-host"],
				IKE: viciAlg(sa, "encr-alg", "integ-alg", "prf-alg", "dh-group"),
				NAT: sa.KV["nat-local"] == "yes" || sa.KV["nat-remote"] == "yes"}
			cand.Established, _ = strconv.ParseUint(sa.KV["established"], 10, 64)
			if ch := sa.Sub["child-sas"]; ch != nil {
				for _, k := range ch.Order {
					c := ch.Sub[k]
					x := IPsecChild{Name: c.KV["name"], State: c.KV["state"],
						LocalTS: strings.Join(c.List["local-ts"], ", "), RemoteTS: strings.Join(c.List["remote-ts"], ", "),
						ESP: viciAlg(c, "encr-alg", "integ-alg", "dh-group")}
					x.BytesIn, _ = strconv.ParseUint(c.KV["bytes-in"], 10, 64)
					x.BytesOut, _ = strconv.ParseUint(c.KV["bytes-out"], 10, 64)
					cand.Children = append(cand.Children, x)
					if x.State == "INSTALLED" {
						cand.State = "up"
					}
				}
			}
			if st.State == "down" || (cand.State == "up" && st.State != "up") {
				*st = cand
			}
		}
	}
	return out
}

func (s *Server) ipsecStatus(w http.ResponseWriter, r *http.Request) {
	var names []string
	if data, err := s.Agent.Store.Running(); err == nil {
		if c, err := config.Parse(data); err == nil {
			for _, t := range c.IPsecTunnels() {
				names = append(names, t.Name)
			}
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	raw := ""
	if len(names) > 0 {
		b, _ := exec.CommandContext(ctx, "swanctl", "--list-sas", "--raw").Output()
		raw = string(b)
	}
	log := []string{}
	if len(names) > 0 {
		if b, err := exec.CommandContext(ctx, "journalctl", "-u", render.IPsecUnit, "-n", "12", "-o", "short-iso", "--no-pager", "-q").Output(); err == nil {
			for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
				if l != "" {
					log = append(log, l)
				}
			}
		}
	}
	writeJSON(w, 200, map[string]any{"tunnels": ipsecStates(raw, names), "log": log, "now": time.Now().Unix()})
}

// ipsecRestart closes a tunnel and, when this router starts it, opens it
// again. The other side sees a clean delete.
func (s *Server) ipsecRestart(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
		writeErr(w, 400, err)
		return
	}
	var tun *config.IPsecTunnel
	if data, err := s.Agent.Store.Running(); err == nil {
		if c, err := config.Parse(data); err == nil {
			for _, t := range c.IPsecTunnels() {
				if t.Name == req.Name {
					tun = t
				}
			}
		}
	}
	if tun == nil {
		writeErr(w, 404, errors.New("no such running IPsec tunnel"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	conn := render.IPsecConnName(tun.Name)
	// --force: do not wait for an answer from a peer that may be gone.
	// "no matching SAs" is fine: the tunnel was already down.
	_ = exec.CommandContext(ctx, "swanctl", "--terminate", "--ike", conn, "--force", "--timeout", "5").Run()
	if tun.Initiates() {
		for i := range tun.SubnetPairs() {
			// timeout -1: start it and return; the page shows the result.
			_ = exec.CommandContext(ctx, "swanctl", "--initiate", "--child", conn+"-"+strconv.Itoa(i+1), "--timeout", "-1").Run()
		}
	}
	writeJSON(w, 200, map[string]string{"status": "ok"})
}
