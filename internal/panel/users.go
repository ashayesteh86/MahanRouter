// Package panel serves the web panel: login, sessions, HTTPS and the
// embedded single-page app. The panel talks to the same REST API as mrctl.
package panel

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

// Panel users are separate from Linux accounts. The file holds PBKDF2-SHA256
// hashes; a fresh device has admin/mahan with MustChange set.
const (
	DefaultUser     = "admin"
	DefaultPassword = "mahan"
	pbkdfIter       = 210000
	MinPasswordLen  = 8
)

// User is one panel account.
type User struct {
	Name       string `json:"name"`
	Hash       string `json:"hash"`
	MustChange bool   `json:"must_change,omitempty"`
}

// Users is the panel user file.
type Users struct {
	Path string
	mu   sync.Mutex
	list []User
}

var nameRe = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,31}$`)

// Load reads the file, creating it with the default admin when missing.
func (u *Users) Load() error {
	u.mu.Lock()
	defer u.mu.Unlock()
	data, err := os.ReadFile(u.Path)
	if errors.Is(err, os.ErrNotExist) {
		h, err := hashPassword(DefaultPassword)
		if err != nil {
			return err
		}
		u.list = []User{{Name: DefaultUser, Hash: h, MustChange: true}}
		return u.saveLocked()
	}
	if err != nil {
		return err
	}
	var doc struct {
		Users []User `json:"users"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return fmt.Errorf("%s: %w", u.Path, err)
	}
	u.list = doc.Users
	return nil
}

func (u *Users) saveLocked() error {
	data, err := json.MarshalIndent(map[string]any{"users": u.list}, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(u.Path), 0o755); err != nil {
		return err
	}
	tmp := u.Path + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, u.Path)
}

// Check returns the user when name and password match.
func (u *Users) Check(name, password string) (User, bool) {
	u.mu.Lock()
	defer u.mu.Unlock()
	for _, x := range u.list {
		if x.Name == name {
			return x, verifyPassword(x.Hash, password)
		}
	}
	// spend the same time on unknown names
	verifyPassword("pbkdf2-sha256$210000$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", password)
	return User{}, false
}

// Get returns a user by name.
func (u *Users) Get(name string) (User, bool) {
	u.mu.Lock()
	defer u.mu.Unlock()
	for _, x := range u.list {
		if x.Name == name {
			return x, true
		}
	}
	return User{}, false
}

// List returns user names and flags, without hashes.
func (u *Users) List() []User {
	u.mu.Lock()
	defer u.mu.Unlock()
	out := make([]User, len(u.list))
	for i, x := range u.list {
		out[i] = User{Name: x.Name, MustChange: x.MustChange}
	}
	return out
}

// SetPassword changes (or, with create, adds) a user's password.
func (u *Users) SetPassword(name, password string, create bool) error {
	if !nameRe.MatchString(name) {
		return errors.New("user name: lower-case letters, digits and . _ - (max 32)")
	}
	if len(password) < MinPasswordLen {
		return fmt.Errorf("password must be at least %d characters", MinPasswordLen)
	}
	if password == DefaultPassword {
		return errors.New("choose a password other than the default")
	}
	h, err := hashPassword(password)
	if err != nil {
		return err
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	for i := range u.list {
		if u.list[i].Name == name {
			if create {
				return errors.New("user already exists")
			}
			u.list[i].Hash, u.list[i].MustChange = h, false
			return u.saveLocked()
		}
	}
	if !create {
		return errors.New("no such user")
	}
	u.list = append(u.list, User{Name: name, Hash: h})
	return u.saveLocked()
}

// Delete removes a user; the last user cannot be removed.
func (u *Users) Delete(name string) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	if len(u.list) <= 1 {
		return errors.New("the last user cannot be deleted")
	}
	for i := range u.list {
		if u.list[i].Name == name {
			u.list = append(u.list[:i], u.list[i+1:]...)
			return u.saveLocked()
		}
	}
	return errors.New("no such user")
}

func hashPassword(pw string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key, err := pbkdf2.Key(sha256.New, pw, salt, pbkdfIter, 32)
	if err != nil {
		return "", err
	}
	enc := base64.RawStdEncoding
	return fmt.Sprintf("pbkdf2-sha256$%d$%s$%s", pbkdfIter, enc.EncodeToString(salt), enc.EncodeToString(key)), nil
}

func verifyPassword(stored, pw string) bool {
	parts := strings.Split(stored, "$")
	if len(parts) != 4 || parts[0] != "pbkdf2-sha256" {
		return false
	}
	iter, err := strconv.Atoi(parts[1])
	if err != nil || iter < 1000 {
		return false
	}
	enc := base64.RawStdEncoding
	salt, err1 := enc.DecodeString(parts[2])
	want, err2 := enc.DecodeString(parts[3])
	if err1 != nil || err2 != nil {
		return false
	}
	got, err := pbkdf2.Key(sha256.New, pw, salt, iter, len(want))
	return err == nil && subtle.ConstantTimeCompare(got, want) == 1
}
