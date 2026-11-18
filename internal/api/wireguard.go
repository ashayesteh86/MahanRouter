package api

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// WireGuard helpers for the panel: key generation (so keys never have to
// be made by hand with wg genkey) and live peer state from `wg show`.

// WGKeypair is a fresh X25519 key pair in WireGuard's base64 form.
type WGKeypair struct {
	PrivateKey   string `json:"private_key"`
	PublicKey    string `json:"public_key"`
	PresharedKey string `json:"preshared_key,omitempty"`
}

// NewWGKeypair makes a clamped X25519 private key and its public key.
func NewWGKeypair(psk bool) (WGKeypair, error) {
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return WGKeypair{}, err
	}
	kp := WGKeypair{
		PrivateKey: base64.StdEncoding.EncodeToString(k.Bytes()),
		PublicKey:  base64.StdEncoding.EncodeToString(k.PublicKey().Bytes()),
	}
	if psk {
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			return WGKeypair{}, err
		}
		kp.PresharedKey = base64.StdEncoding.EncodeToString(b)
	}
	return kp, nil
}

// WGPublicKey derives the public key from a base64 private key.
func WGPublicKey(priv string) (string, error) {
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(priv))
	if err != nil || len(b) != 32 {
		return "", errors.New("not a base64 32-byte WireGuard key")
	}
	// WireGuard clamps the scalar; crypto/ecdh does the same internally.
	k, err := ecdh.X25519().NewPrivateKey(b)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(k.PublicKey().Bytes()), nil
}

func (s *Server) wgKeypair(w http.ResponseWriter, r *http.Request) {
	kp, err := NewWGKeypair(r.URL.Query().Get("psk") == "1")
	if err != nil {
		writeErr(w, 500, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, kp)
}

func (s *Server) wgPubkey(w http.ResponseWriter, r *http.Request) {
	var req struct {
		PrivateKey string `json:"private_key"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
		writeErr(w, 400, err)
		return
	}
	pub, err := WGPublicKey(req.PrivateKey)
	if err != nil {
		writeErr(w, 422, err)
		return
	}
	writeJSON(w, 200, map[string]string{"public_key": pub})
}

// WGPeerState is one peer as the kernel sees it.
type WGPeerState struct {
	PublicKey     string   `json:"public_key"`
	Endpoint      string   `json:"endpoint,omitempty"`
	AllowedIPs    []string `json:"allowed_ips"`
	LastHandshake int64    `json:"last_handshake"` // unix seconds, 0 = never
	RxBytes       int64    `json:"rx_bytes"`
	TxBytes       int64    `json:"tx_bytes"`
}

// WGIfaceState is one WireGuard interface with its peers.
type WGIfaceState struct {
	Name       string        `json:"name"`
	PublicKey  string        `json:"public_key"`
	ListenPort int           `json:"listen_port"`
	Peers      []WGPeerState `json:"peers"`
}

// ParseWGDump reads `wg show all dump`. Interface lines have 5 fields
// (iface, private, public, port, fwmark); peer lines have 9.
func ParseWGDump(data []byte) []WGIfaceState {
	out := []WGIfaceState{}
	idx := map[string]int{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		f := strings.Split(sc.Text(), "\t")
		switch len(f) {
		case 5:
			port, _ := strconv.Atoi(f[3])
			idx[f[0]] = len(out)
			out = append(out, WGIfaceState{Name: f[0], PublicKey: f[2], ListenPort: port, Peers: []WGPeerState{}})
		case 9:
			i, ok := idx[f[0]]
			if !ok {
				continue
			}
			p := WGPeerState{PublicKey: f[1], AllowedIPs: []string{}}
			if f[3] != "(none)" {
				p.Endpoint = f[3]
			}
			if f[4] != "(none)" && f[4] != "" {
				p.AllowedIPs = strings.Split(f[4], ",")
			}
			p.LastHandshake, _ = strconv.ParseInt(f[5], 10, 64)
			p.RxBytes, _ = strconv.ParseInt(f[6], 10, 64)
			p.TxBytes, _ = strconv.ParseInt(f[7], 10, 64)
			out[i].Peers = append(out[i].Peers, p)
		}
	}
	return out
}

func (s *Server) wgStatus(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	data, err := exec.CommandContext(ctx, "wg", "show", "all", "dump").Output()
	if err != nil {
		// no wg tool or no interfaces: an empty list, not an error page
		writeJSON(w, 200, map[string]any{"interfaces": []WGIfaceState{}, "now": time.Now().Unix()})
		return
	}
	writeJSON(w, 200, map[string]any{"interfaces": ParseWGDump(data), "now": time.Now().Unix()})
}
