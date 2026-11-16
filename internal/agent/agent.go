// Package agent is core-agent: it validates, renders and applies the
// configuration, stores every commit, and guards commits with a
// confirm timer that rolls back automatically.
package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/ashayesteh86/MahanRouter/internal/apply"
	"github.com/ashayesteh86/MahanRouter/internal/config"
	"github.com/ashayesteh86/MahanRouter/internal/render"
	"github.com/ashayesteh86/MahanRouter/internal/store"
)

// Agent serialises all configuration changes.
type Agent struct {
	Store   *store.Store
	Applier *apply.Applier
	Log     *slog.Logger

	mu      sync.Mutex
	pending *pendingConfirm
}

type pendingConfirm struct {
	Revision string    `json:"revision"`
	Previous string    `json:"previous"`
	Deadline time.Time `json:"deadline"`
	timer    *time.Timer
}

// PendingInfo describes a commit waiting for confirmation.
type PendingInfo struct {
	Revision string    `json:"revision"`
	Previous string    `json:"previous"`
	Deadline time.Time `json:"deadline"`
	Seconds  int       `json:"seconds_left"`
}

// CommitResult is returned by Commit and Rollback.
type CommitResult struct {
	Revision string        `json:"revision"`
	Apply    *apply.Result `json:"apply"`
	Pending  *PendingInfo  `json:"pending,omitempty"`
}

// ErrNoChanges is returned when the candidate equals the running config.
var ErrNoChanges = errors.New("candidate is identical to the running config")

// Prepare parses, validates and renders a document.
func Prepare(data []byte) (*config.Config, render.Bundle, error) {
	c, err := config.Parse(data)
	if err != nil {
		return nil, nil, err
	}
	if err := config.Validate(c); err != nil {
		return nil, nil, err
	}
	b, err := render.Render(c)
	if err != nil {
		return nil, nil, err
	}
	return c, b, nil
}

// Boot applies the running config (used at startup), creating the
// factory default first if the store is empty.
func (a *Agent) Boot(factory func() *config.Config) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.Store.Initialized() {
		data, err := config.Marshal(factory())
		if err != nil {
			return err
		}
		if _, _, err := Prepare(data); err != nil {
			return fmt.Errorf("factory default is invalid: %w", err)
		}
		if err := a.Store.Init(data, "factory default"); err != nil {
			return err
		}
		a.Log.Info("created factory default configuration")
	}
	if p, ok := a.loadPending(); ok {
		// The agent or device restarted while a commit was unconfirmed:
		// treat it as not confirmed, like a lost management session.
		a.Log.Warn("unconfirmed commit found at boot, rolling back", "revision", p.Revision, "to", p.Previous)
		data, err := a.Store.Show(p.Previous)
		if err == nil {
			_, err = a.Store.Commit(data, "auto-rollback: "+short(p.Revision)+" was not confirmed before restart", "system")
		}
		a.clearPending()
		if err != nil {
			return fmt.Errorf("boot rollback: %w", err)
		}
	}
	data, err := a.Store.Running()
	if err != nil {
		return err
	}
	c, b, err := Prepare(data)
	if err != nil {
		return fmt.Errorf("running config is invalid: %w", err)
	}
	res, err := a.Applier.Apply(c, b)
	if res != nil {
		a.Log.Info("boot apply", "changed", len(res.Changed), "components", res.Components)
	}
	if r := a.Applier.BootLinks(c); len(r) > 0 {
		a.Log.Info("renamed ports", "renames", r)
	}
	return err
}

// Commit applies the candidate. With confirm > 0 the change is rolled
// back unless Confirm is called before the timer runs out.
func (a *Agent) Commit(message, author string, confirm time.Duration) (*CommitResult, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.pending != nil {
		return nil, errors.New("a previous commit is waiting for confirmation; confirm it or let it roll back first")
	}
	cand, err := a.Store.Candidate()
	if err != nil {
		return nil, err
	}
	running, err := a.Store.Running()
	if err != nil {
		return nil, err
	}
	if string(cand) == string(running) {
		return nil, ErrNoChanges
	}
	prev, err := a.Store.Head()
	if err != nil {
		return nil, err
	}
	res, err := a.applyDoc(cand, running)
	if err != nil {
		return &CommitResult{Apply: res}, err
	}
	rev, err := a.Store.Commit(cand, message, author)
	if err != nil {
		return nil, err
	}
	_ = a.Store.DiscardCandidate()
	out := &CommitResult{Revision: rev, Apply: res}
	if confirm > 0 {
		p := &pendingConfirm{Revision: rev, Previous: prev, Deadline: time.Now().Add(confirm)}
		p.timer = time.AfterFunc(confirm, func() { a.autoRollback(p) })
		a.pending = p
		a.savePending(p)
		out.Pending = p.info()
	}
	a.Log.Info("commit", "revision", rev, "author", author, "message", message, "confirm", confirm)
	return out, nil
}

// applyDoc validates and applies data; on any apply failure it restores
// fallback so the device is never left half-configured.
func (a *Agent) applyDoc(data, fallback []byte) (*apply.Result, error) {
	c, b, err := Prepare(data)
	if err != nil {
		return nil, err
	}
	res, err := a.Applier.Apply(c, b)
	if err == nil {
		return res, nil
	}
	a.Log.Error("apply failed, restoring previous config", "err", err)
	if fc, fb, perr := Prepare(fallback); perr == nil {
		if _, rerr := a.Applier.Apply(fc, fb); rerr != nil {
			a.Log.Error("restore after failed apply also failed", "err", rerr)
			return res, fmt.Errorf("%w (restoring the previous config also failed: %v)", err, rerr)
		}
	}
	return res, fmt.Errorf("apply failed, previous config restored: %w", err)
}

func (p *pendingConfirm) info() *PendingInfo {
	return &PendingInfo{Revision: p.Revision, Previous: p.Previous, Deadline: p.Deadline,
		Seconds: int(time.Until(p.Deadline).Seconds())}
}

// Pending returns the commit waiting for confirmation, if any.
func (a *Agent) Pending() *PendingInfo {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.pending == nil {
		return nil
	}
	return a.pending.info()
}

// Confirm keeps a commit made with a confirm timer.
func (a *Agent) Confirm() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.pending == nil {
		return errors.New("nothing to confirm")
	}
	a.pending.timer.Stop()
	a.Log.Info("commit confirmed", "revision", a.pending.Revision)
	a.pending = nil
	a.clearPending()
	return nil
}

func (a *Agent) autoRollback(p *pendingConfirm) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.pending != p {
		return // confirmed meanwhile
	}
	a.pending = nil
	a.clearPending()
	a.Log.Warn("commit not confirmed in time, rolling back", "revision", p.Revision, "to", p.Previous)
	if _, err := a.rollbackLocked(p.Previous, "auto-rollback: "+short(p.Revision)+" was not confirmed", "system"); err != nil {
		a.Log.Error("auto-rollback failed", "err", err)
	}
}

func short(h string) string {
	if len(h) > 8 {
		return h[:8]
	}
	return h
}

// Rollback re-applies an older revision as a new commit.
func (a *Agent) Rollback(rev, author string) (*CommitResult, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.pending != nil {
		a.pending.timer.Stop()
		a.pending = nil
		a.clearPending()
	}
	return a.rollbackLocked(rev, "", author)
}

func (a *Agent) rollbackLocked(rev, message, author string) (*CommitResult, error) {
	full, err := a.Store.Resolve(rev)
	if err != nil {
		return nil, err
	}
	data, err := a.Store.Show(full)
	if err != nil {
		return nil, err
	}
	running, err := a.Store.Running()
	if err != nil {
		return nil, err
	}
	res, err := a.applyDoc(data, running)
	if err != nil {
		return &CommitResult{Apply: res}, err
	}
	if message == "" {
		message = "rollback to " + short(full)
	}
	newRev, err := a.Store.Commit(data, message, author)
	if err != nil {
		return nil, err
	}
	return &CommitResult{Revision: newRev, Apply: res}, nil
}

func (a *Agent) pendingPath() string { return filepath.Join(a.Store.Dir, "pending-confirm.json") }

func (a *Agent) savePending(p *pendingConfirm) {
	data, _ := json.Marshal(p)
	if err := os.WriteFile(a.pendingPath(), data, 0o600); err != nil {
		a.Log.Error("save pending confirm", "err", err)
	}
}

func (a *Agent) loadPending() (*pendingConfirm, bool) {
	data, err := os.ReadFile(a.pendingPath())
	if err != nil {
		return nil, false
	}
	var p pendingConfirm
	if json.Unmarshal(data, &p) != nil || p.Previous == "" {
		return nil, false
	}
	return &p, true
}

func (a *Agent) clearPending() { _ = os.Remove(a.pendingPath()) }
