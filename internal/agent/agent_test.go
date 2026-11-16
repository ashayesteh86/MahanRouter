package agent

import (
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ashayesteh86/MahanRouter/internal/apply"
	"github.com/ashayesteh86/MahanRouter/internal/config"
	"github.com/ashayesteh86/MahanRouter/internal/render"
	"github.com/ashayesteh86/MahanRouter/internal/store"
)

func newAgent(t *testing.T, state, root string, run func(string, ...string) error) *Agent {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	return &Agent{
		Store:   &store.Store{Dir: state},
		Applier: &apply.Applier{Root: root, StateDir: state, Reload: true, Run: run, Log: log},
		Log:     log,
	}
}

func factory() *config.Config {
	return config.FactoryDefault([]config.NIC{{MAC: "52:54:00:00:00:01"}, {MAC: "52:54:00:00:00:02"}})
}

func hostnameDoc(t *testing.T, a *Agent, name string) []byte {
	data, err := a.Store.Running()
	if err != nil {
		t.Fatal(err)
	}
	return []byte(strings.Replace(string(data), "hostname: mahan-router", "hostname: "+name, 1))
}

func readHostname(t *testing.T, root string) string {
	b, err := os.ReadFile(filepath.Join(root, render.HostnameFile))
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(b))
}

func setup(t *testing.T, run func(string, ...string) error) (*Agent, string, string) {
	state, root := t.TempDir(), t.TempDir()
	if run == nil {
		run = func(string, ...string) error { return nil }
	}
	a := newAgent(t, state, root, run)
	if err := a.Boot(factory); err != nil {
		t.Fatal(err)
	}
	return a, state, root
}

func TestBootWritesFactoryDefault(t *testing.T) {
	_, _, root := setup(t, nil)
	if got := readHostname(t, root); got != "mahan-router" {
		t.Fatalf("hostname %q", got)
	}
	nft, _ := os.ReadFile(filepath.Join(root, render.NftablesFile))
	if !strings.Contains(string(nft), "masquerade") {
		t.Fatal("default ruleset missing masquerade")
	}
}

func TestCommitAndRollback(t *testing.T) {
	var calls []string
	a, _, root := setup(t, func(n string, args ...string) error {
		calls = append(calls, n+" "+strings.Join(args, " "))
		return nil
	})
	if _, err := a.Commit("x", "test", 0); !errors.Is(err, ErrNoChanges) {
		t.Fatalf("want ErrNoChanges, got %v", err)
	}
	if err := a.Store.SetCandidate(hostnameDoc(t, a, "edge1")); err != nil {
		t.Fatal(err)
	}
	calls = nil
	res, err := a.Commit("rename", "test", 0)
	if err != nil {
		t.Fatal(err)
	}
	if got := readHostname(t, root); got != "edge1" {
		t.Fatalf("hostname %q", got)
	}
	if len(res.Apply.Components) != 2 || res.Apply.Components[0] != render.CompSystem {
		// hostname changes the system files and the FRR hostname line.
		t.Fatalf("components %v", res.Apply.Components)
	}
	if !strings.HasPrefix(calls[0], "hostname edge1") {
		t.Fatalf("calls %v", calls)
	}
	if a.Store.HasCandidate() {
		t.Fatal("candidate should be cleared after commit")
	}
	if _, err := a.Rollback("HEAD~1", "test"); err != nil {
		t.Fatal(err)
	}
	if got := readHostname(t, root); got != "mahan-router" {
		t.Fatalf("after rollback hostname %q", got)
	}
	revs, _ := a.Store.History(10)
	if len(revs) != 3 || !strings.HasPrefix(revs[0].Message, "rollback to") {
		t.Fatalf("history %+v", revs)
	}
}

func TestConfirmTimeoutRollsBack(t *testing.T) {
	a, _, root := setup(t, nil)
	a.Store.SetCandidate(hostnameDoc(t, a, "edge2"))
	res, err := a.Commit("risky", "test", 150*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if res.Pending == nil {
		t.Fatal("expected pending confirm")
	}
	if _, err := a.Commit("again", "test", 0); err == nil {
		t.Fatal("second commit must wait for confirmation")
	}
	time.Sleep(400 * time.Millisecond)
	if got := readHostname(t, root); got != "mahan-router" {
		t.Fatalf("not rolled back: %q", got)
	}
	if a.Pending() != nil {
		t.Fatal("pending should be cleared")
	}
	revs, _ := a.Store.History(1)
	if !strings.HasPrefix(revs[0].Message, "auto-rollback") {
		t.Fatalf("last message %q", revs[0].Message)
	}
}

func TestConfirmKeeps(t *testing.T) {
	a, _, root := setup(t, nil)
	a.Store.SetCandidate(hostnameDoc(t, a, "edge3"))
	if _, err := a.Commit("ok", "test", 200*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if err := a.Confirm(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(400 * time.Millisecond)
	if got := readHostname(t, root); got != "edge3" {
		t.Fatalf("confirmed change lost: %q", got)
	}
}

func TestRestartDuringConfirmRollsBack(t *testing.T) {
	a, state, root := setup(t, nil)
	a.Store.SetCandidate(hostnameDoc(t, a, "edge4"))
	if _, err := a.Commit("ok", "test", time.Hour); err != nil {
		t.Fatal(err)
	}
	// Simulate a crash/reboot: new agent on the same state.
	b := newAgent(t, state, root, func(string, ...string) error { return nil })
	if err := b.Boot(factory); err != nil {
		t.Fatal(err)
	}
	if got := readHostname(t, root); got != "mahan-router" {
		t.Fatalf("unconfirmed commit survived restart: %q", got)
	}
}

func TestFailedApplyRestores(t *testing.T) {
	fail := false
	a, _, root := setup(t, func(n string, args ...string) error {
		if fail && n == "hostname" && args[0] == "broken" {
			return errors.New("boom")
		}
		return nil
	})
	fail = true
	a.Store.SetCandidate(hostnameDoc(t, a, "broken"))
	if _, err := a.Commit("bad", "test", 0); err == nil || !strings.Contains(err.Error(), "previous config restored") {
		t.Fatalf("want restore error, got %v", err)
	}
	if got := readHostname(t, root); got != "mahan-router" {
		t.Fatalf("files not restored: %q", got)
	}
	revs, _ := a.Store.History(5)
	if len(revs) != 1 {
		t.Fatalf("failed commit must not be stored: %+v", revs)
	}
}

func TestInvalidCandidateRejected(t *testing.T) {
	a, _, _ := setup(t, nil)
	a.Store.SetCandidate([]byte("version: 1\nsystem: { hostname: 'bad name' }\ninterfaces: []\n"))
	_, err := a.Commit("x", "test", 0)
	var ve *config.ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("want validation error, got %v", err)
	}
}
