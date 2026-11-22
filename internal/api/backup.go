package api

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"time"

	"github.com/ashayesteh86/MahanRouter/internal/config"
)

// A backup is the running configuration: every setting of the router lives
// in it, including keys and passwords. Without a password the file is the
// plain YAML; with one it is a JSON envelope around AES-256-GCM.
const (
	backupFormat  = "mahan-router-backup"
	backupKDF     = "pbkdf2-sha256"
	backupIter    = 600000
	backupMaxIter = 10000000
	backupHead    = "# Mahan Router backup:"
)

// ErrBackupPassword is returned for a missing or wrong backup password.
var ErrBackupPassword = errors.New("the backup password is missing or wrong")

type backupEnvelope struct {
	Format  string `json:"format"`
	Version int    `json:"version"`
	KDF     string `json:"kdf"`
	Iter    int    `json:"iterations"`
	Salt    []byte `json:"salt"`
	Nonce   []byte `json:"nonce"`
	Data    []byte `json:"data"`
}

func backupKey(password string, salt []byte, iter int) (cipher.AEAD, error) {
	key, err := pbkdf2.Key(sha256.New, password, salt, iter, 32)
	if err != nil {
		return nil, err
	}
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(blk)
}

// EncryptBackup wraps a configuration in a password-protected envelope.
func EncryptBackup(plain []byte, password string) ([]byte, error) {
	e := backupEnvelope{Format: backupFormat, Version: 1, KDF: backupKDF, Iter: backupIter,
		Salt: make([]byte, 16), Nonce: make([]byte, 12)}
	if _, err := rand.Read(e.Salt); err != nil {
		return nil, err
	}
	if _, err := rand.Read(e.Nonce); err != nil {
		return nil, err
	}
	gcm, err := backupKey(password, e.Salt, e.Iter)
	if err != nil {
		return nil, err
	}
	e.Data = gcm.Seal(nil, e.Nonce, plain, []byte(backupFormat))
	out, err := json.MarshalIndent(e, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(out, '\n'), nil
}

// IsEncryptedBackup tells an envelope from a plain YAML configuration.
func IsEncryptedBackup(data []byte) bool {
	var e backupEnvelope
	return json.Unmarshal(bytes.TrimSpace(data), &e) == nil && e.Format == backupFormat
}

// DecryptBackup returns the configuration inside a backup file. Plain files
// are returned as they are.
func DecryptBackup(data []byte, password string) ([]byte, error) {
	if !IsEncryptedBackup(data) {
		return data, nil
	}
	var e backupEnvelope
	_ = json.Unmarshal(bytes.TrimSpace(data), &e)
	if e.Version != 1 || e.KDF != backupKDF || e.Iter < 1000 || e.Iter > backupMaxIter || len(e.Nonce) != 12 {
		return nil, errors.New("this backup file format is not supported")
	}
	if password == "" {
		return nil, ErrBackupPassword
	}
	gcm, err := backupKey(password, e.Salt, e.Iter)
	if err != nil {
		return nil, err
	}
	plain, err := gcm.Open(nil, e.Nonce, e.Data, []byte(backupFormat))
	if err != nil {
		return nil, ErrBackupPassword
	}
	return plain, nil
}

var backupNameRe = regexp.MustCompile(`[^A-Za-z0-9_.-]+`)

// backup sends the running configuration as a file to keep.
func (s *Server) backup(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Password string `json:"password"`
	}
	if body, _ := io.ReadAll(io.LimitReader(r.Body, 4096)); len(bytes.TrimSpace(body)) > 0 {
		if err := json.Unmarshal(body, &req); err != nil {
			writeErr(w, 400, err)
			return
		}
	}
	run, err := s.Agent.Store.Running()
	if err != nil {
		writeErr(w, 500, err)
		return
	}
	host := "router"
	if c, err := config.Parse(run); err == nil && c.System.Hostname != "" {
		host = backupNameRe.ReplaceAllString(c.System.Hostname, "-")
	}
	now := time.Now()
	head := fmt.Sprintf("%s %s, version %s, %s\n", backupHead, host, s.Version, now.UTC().Format(time.RFC3339))
	out := append([]byte(head), run...)
	name := fmt.Sprintf("mahan-router-%s-%s", host, now.Format("20060102-1504"))
	if req.Password != "" {
		if out, err = EncryptBackup(out, req.Password); err != nil {
			writeErr(w, 500, err)
			return
		}
		name += ".mrbackup"
	} else {
		name += ".yaml"
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(out)
}

// restore loads a backup file as the candidate. Nothing changes on the
// router until the candidate is committed, like every other edit.
func (s *Server) restore(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Content  string `json:"content"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, maxBody)).Decode(&req); err != nil {
		writeErr(w, 400, err)
		return
	}
	data, err := DecryptBackup([]byte(req.Content), req.Password)
	if errors.Is(err, ErrBackupPassword) {
		writeJSON(w, 400, map[string]any{"error": err.Error(), "need_password": true})
		return
	}
	if err != nil {
		writeErr(w, 400, err)
		return
	}
	// Without our header line a backup of the running config is no change.
	if bytes.HasPrefix(data, []byte(backupHead)) {
		if i := bytes.IndexByte(data, '\n'); i >= 0 {
			data = data[i+1:]
		}
	}
	c, err := config.Parse(data)
	if err != nil {
		writeErr(w, 400, fmt.Errorf("not a Mahan Router backup: %w", err))
		return
	}
	if c.System.Hostname == "" && len(c.Interfaces) == 0 {
		writeErr(w, 400, errors.New("not a Mahan Router backup: the file has no settings"))
		return
	}
	resp := map[string]any{"saved": true, "valid": true, "hostname": c.System.Hostname}
	if run, err := s.Agent.Store.Running(); err == nil && bytes.Equal(run, data) {
		// the backup is what already runs: leave no empty change behind
		if err := s.Agent.Store.DiscardCandidate(); err != nil {
			writeErr(w, 500, err)
			return
		}
		resp["unchanged"] = true
		writeJSON(w, 200, resp)
		return
	}
	if err := s.Agent.Store.SetCandidate(data); err != nil {
		writeErr(w, 500, err)
		return
	}
	if err := config.Validate(c); err != nil {
		resp["valid"] = false
		var ve *config.ValidationError
		if errors.As(err, &ve) {
			resp["problems"] = ve.Problems
		}
	}
	writeJSON(w, 200, resp)
}
