package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ashayesteh86/MahanRouter/internal/config"
)

// SSHKeypair is a new login key for an SSH tunnel.
type SSHKeypair struct {
	PrivateKey string `json:"private_key"`
	PublicKey  string `json:"public_key"` // the line for the server's authorized_keys
}

// NewSSHKeypair makes an Ed25519 key with ssh-keygen (no passphrase).
func NewSSHKeypair(ctx context.Context, comment string) (*SSHKeypair, error) {
	dir, err := os.MkdirTemp("", "mahan-sshkey-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	f := filepath.Join(dir, "id")
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if out, err := exec.CommandContext(ctx, "ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", comment, "-f", f).CombinedOutput(); err != nil {
		return nil, fmt.Errorf("ssh-keygen: %v: %s", err, bytes.TrimSpace(out))
	}
	priv, err := os.ReadFile(f)
	if err != nil {
		return nil, err
	}
	pub, err := os.ReadFile(f + ".pub")
	if err != nil {
		return nil, err
	}
	return &SSHKeypair{PrivateKey: string(priv), PublicKey: strings.TrimSpace(string(pub))}, nil
}

func (s *Server) sshKeypair(w http.ResponseWriter, r *http.Request) {
	kp, err := NewSSHKeypair(r.Context(), "mahan-router")
	if err != nil {
		writeErr(w, 500, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, kp)
}

// parseKeyscan turns ssh-keyscan output ("host type base64" lines) into
// sorted "type base64" keys.
func parseKeyscan(out string) []string {
	keys := []string{}
	for _, l := range strings.Split(out, "\n") {
		f := strings.Fields(l)
		if len(f) != 3 || strings.HasPrefix(f[0], "#") {
			continue
		}
		if k := f[1] + " " + f[2]; config.SSHHostKeyOK(k) {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	return keys
}

// sshHostKey reads the host keys a server presents right now, so the panel
// can pin them. The answer is only as trustworthy as the path to the
// server at this moment.
func (s *Server) sshHostKey(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Server string `json:"server"`
		Port   int    `json:"port"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
		writeErr(w, 400, err)
		return
	}
	if req.Port == 0 {
		req.Port = config.SSHPort
	}
	// Validate like the config does: the values go to a command line.
	if !config.SSHTargetOK(&config.SSHClient{Server: req.Server, Port: req.Port}) {
		writeErr(w, 422, errors.New("server must be a host name or IP address, port 1-65535"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "ssh-keyscan", "-T", "8", "-p", strconv.Itoa(req.Port), "--", req.Server).Output()
	keys := parseKeyscan(string(out))
	if len(keys) == 0 {
		msg := "no answer from " + net.JoinHostPort(req.Server, strconv.Itoa(req.Port))
		if err != nil && ctx.Err() == nil {
			msg += ": " + err.Error()
		}
		writeErr(w, 502, errors.New(msg))
		return
	}
	writeJSON(w, 200, map[string]any{"host_keys": keys})
}
