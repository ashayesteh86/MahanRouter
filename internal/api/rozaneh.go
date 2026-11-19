package api

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/ashayesteh86/MahanRouter/internal/config"
	"github.com/ashayesteh86/MahanRouter/internal/render"
)

// RozanehPeerState is a server peer's usage from the Rozaneh state file,
// which the server saves every minute.
type RozanehPeerState struct {
	Name      string     `json:"name"`
	PublicKey string     `json:"public_key"`
	IP        string     `json:"ip"`
	DownBytes uint64     `json:"down_bytes"`
	UpBytes   uint64     `json:"up_bytes"`
	LastSeen  *time.Time `json:"last_seen,omitempty"`
	Sessions  int        `json:"sessions"`
}

// RozanehState is the live state of one Rozaneh interface.
type RozanehState struct {
	Name      string             `json:"name"`
	Type      string             `json:"type"`
	Unit      string             `json:"unit"`
	Active    string             `json:"active"` // systemd ActiveState
	Up        bool               `json:"up"`     // tunnel interface exists
	Addresses []string           `json:"addresses"`
	RxBytes   uint64             `json:"rx_bytes"`
	TxBytes   uint64             `json:"tx_bytes"`
	Log       []string           `json:"log"`
	Peers     []RozanehPeerState `json:"peers,omitempty"`
}

func (s *Server) rozanehStatus(w http.ResponseWriter, r *http.Request) {
	out := []RozanehState{}
	data, err := s.Agent.Store.Running()
	if err == nil {
		if c, err := config.Parse(data); err == nil {
			for i := range c.Interfaces {
				ifc := &c.Interfaces[i]
				if ifc.Type == config.IfRozaneh || ifc.Type == config.IfRozanehServer {
					out = append(out, rozanehState(r.Context(), ifc))
				}
			}
		}
	}
	writeJSON(w, 200, map[string]any{"interfaces": out, "now": time.Now().Unix()})
}

func rozanehState(ctx context.Context, ifc *config.Interface) RozanehState {
	st := RozanehState{Name: ifc.Name, Type: ifc.Type, Unit: render.RozanehUnit(ifc), Addresses: []string{}, Log: []string{}}
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	if b, err := exec.CommandContext(ctx, "systemctl", "show", "-P", "ActiveState", st.Unit).Output(); err == nil {
		st.Active = strings.TrimSpace(string(b))
	}
	sys := filepath.Join("/sys/class/net", ifc.Name, "statistics")
	if b, err := os.ReadFile(filepath.Join(sys, "rx_bytes")); err == nil {
		st.Up = true
		st.RxBytes, _ = strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
		b, _ = os.ReadFile(filepath.Join(sys, "tx_bytes"))
		st.TxBytes, _ = strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
	}
	if b, err := exec.CommandContext(ctx, "ip", "-j", "addr", "show", "dev", ifc.Name).Output(); err == nil {
		var a []AddrJSON
		if json.Unmarshal(b, &a) == nil {
			for _, x := range a {
				for _, ai := range x.AddrInfo {
					st.Addresses = append(st.Addresses, ai.Local+"/"+strconv.Itoa(ai.PrefixLen))
				}
			}
		}
	}
	if b, err := exec.CommandContext(ctx, "journalctl", "-u", st.Unit, "-n", "8", "-o", "short-iso", "--no-pager", "-q").Output(); err == nil {
		for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
			if l != "" {
				st.Log = append(st.Log, l)
			}
		}
	}
	if ifc.Type == config.IfRozanehServer {
		var state struct {
			Peers []RozanehPeerState `json:"peers"`
		}
		if b, err := os.ReadFile(filepath.Join(render.RozanehStateDir, ifc.Name, "state.json")); err == nil && json.Unmarshal(b, &state) == nil {
			st.Peers = state.Peers
		}
	}
	return st
}

// AddrJSON is one entry of `ip -j addr`.
type AddrJSON struct {
	AddrInfo []struct {
		Local     string `json:"local"`
		PrefixLen int    `json:"prefixlen"`
	} `json:"addr_info"`
}
