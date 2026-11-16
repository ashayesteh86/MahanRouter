// Package store keeps the running configuration in a local Git repository
// and the candidate (uncommitted) configuration next to it.
package store

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const configFile = "config.yaml"

// Store is a Git-backed configuration store.
type Store struct {
	Dir string // e.g. /var/lib/mahan-router
}

// Revision is one committed configuration.
type Revision struct {
	Hash    string    `json:"hash"`
	Short   string    `json:"short"`
	Author  string    `json:"author"`
	Time    time.Time `json:"time"`
	Message string    `json:"message"`
}

func (s *Store) repo() string          { return filepath.Join(s.Dir, "repo") }
func (s *Store) candidatePath() string { return filepath.Join(s.Dir, "candidate.yaml") }

func (s *Store) git(args ...string) ([]byte, error) {
	cmd := exec.Command("git", append([]string{"-C", s.repo()}, args...)...)
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0", "LC_ALL=C")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return out, fmt.Errorf("git %s: %v: %s", strings.Join(args, " "), err, bytes.TrimSpace(stderr.Bytes()))
	}
	return out, nil
}

// Initialized reports whether the repository holds a committed config.
func (s *Store) Initialized() bool {
	_, err := s.git("rev-parse", "--verify", "HEAD")
	return err == nil
}

// Init creates the repository with an initial config.
func (s *Store) Init(initial []byte, message string) error {
	if err := os.MkdirAll(s.repo(), 0o700); err != nil {
		return err
	}
	if _, err := s.git("init", "-q", "-b", "main"); err != nil {
		return err
	}
	for k, v := range map[string]string{"user.name": "mahan-router", "user.email": "agent@mahan-router.local", "commit.gpgsign": "false"} {
		if _, err := s.git("config", k, v); err != nil {
			return err
		}
	}
	_, err := s.Commit(initial, message, "system")
	return err
}

// Running returns the committed configuration.
func (s *Store) Running() ([]byte, error) {
	return os.ReadFile(filepath.Join(s.repo(), configFile))
}

var revRe = regexp.MustCompile(`^[0-9a-fA-F]{4,40}$|^HEAD(~[0-9]{1,4})?$`)

// Show returns the configuration at a revision (hash or HEAD~N).
func (s *Store) Show(rev string) ([]byte, error) {
	if !revRe.MatchString(rev) {
		return nil, errors.New("revision must be a commit hash or HEAD~N")
	}
	return s.git("show", rev+":"+configFile)
}

// Resolve turns a revision into a full hash.
func (s *Store) Resolve(rev string) (string, error) {
	if !revRe.MatchString(rev) {
		return "", errors.New("revision must be a commit hash or HEAD~N")
	}
	out, err := s.git("rev-parse", "--verify", rev+"^{commit}")
	return strings.TrimSpace(string(out)), err
}

// Head returns the current revision hash.
func (s *Store) Head() (string, error) { return s.Resolve("HEAD") }

var authorRe = regexp.MustCompile(`[^a-zA-Z0-9_.@-]`)

// Commit stores a new running config and returns its hash.
func (s *Store) Commit(data []byte, message, author string) (string, error) {
	if err := os.WriteFile(filepath.Join(s.repo(), configFile), data, 0o600); err != nil {
		return "", err
	}
	if _, err := s.git("add", configFile); err != nil {
		return "", err
	}
	if strings.TrimSpace(message) == "" {
		message = "commit"
	}
	a := authorRe.ReplaceAllString(author, "_")
	if a == "" {
		a = "unknown"
	}
	if _, err := s.git("commit", "-q", "--allow-empty", "-m", message, "--author", a+" <"+a+"@mahan-router.local>"); err != nil {
		return "", err
	}
	return s.Head()
}

// History lists the most recent revisions, newest first.
func (s *Store) History(limit int) ([]Revision, error) {
	if limit <= 0 || limit > 1000 {
		limit = 50
	}
	out, err := s.git("log", fmt.Sprintf("-n%d", limit), "--format=%H%x1f%h%x1f%an%x1f%aI%x1f%s")
	if err != nil {
		return nil, err
	}
	var revs []Revision
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		f := strings.Split(line, "\x1f")
		if len(f) != 5 {
			continue
		}
		t, _ := time.Parse(time.RFC3339, f[3])
		revs = append(revs, Revision{Hash: f[0], Short: f[1], Author: f[2], Time: t, Message: f[4]})
	}
	return revs, nil
}

// Candidate returns the candidate config, or the running config when no
// candidate has been loaded.
func (s *Store) Candidate() ([]byte, error) {
	data, err := os.ReadFile(s.candidatePath())
	if os.IsNotExist(err) {
		return s.Running()
	}
	return data, err
}

// HasCandidate reports whether an uncommitted candidate exists.
func (s *Store) HasCandidate() bool {
	_, err := os.Stat(s.candidatePath())
	return err == nil
}

// SetCandidate stores a candidate config.
func (s *Store) SetCandidate(data []byte) error {
	return os.WriteFile(s.candidatePath(), data, 0o600)
}

// DiscardCandidate drops the candidate.
func (s *Store) DiscardCandidate() error {
	err := os.Remove(s.candidatePath())
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

// Diff returns a unified diff from a to b.
func Diff(a, b []byte, labelA, labelB string) (string, error) {
	dir, err := os.MkdirTemp("", "mr-diff-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(dir)
	pa, pb := filepath.Join(dir, "a"), filepath.Join(dir, "b")
	if err := os.WriteFile(pa, a, 0o600); err != nil {
		return "", err
	}
	if err := os.WriteFile(pb, b, 0o600); err != nil {
		return "", err
	}
	cmd := exec.Command("git", "diff", "--no-index", "--no-color", "--src-prefix=", "--dst-prefix=", pa, pb)
	out, err := cmd.Output()
	var ee *exec.ExitError
	if err != nil && !(errors.As(err, &ee) && ee.ExitCode() == 1) {
		return "", err
	}
	s := strings.ReplaceAll(string(out), pa, labelA)
	s = strings.ReplaceAll(s, pb, labelB)
	return s, nil
}
