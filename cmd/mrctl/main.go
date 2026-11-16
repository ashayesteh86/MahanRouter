// Command mrctl is the Mahan Router command line. Most commands talk to
// mahan-agent over its API; validate, render and factory-default also
// work offline on a file.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/ashayesteh86/MahanRouter/internal/agent"
	"github.com/ashayesteh86/MahanRouter/internal/config"
)

const usage = `mrctl: Mahan Router control

Agent commands (local socket, or --url/--token for a remote router):
  show [running|candidate]       print a configuration
  load FILE                      replace the candidate with FILE
  edit                           edit the candidate in $EDITOR
  diff                           running vs candidate
  validate                       validate the candidate
  commit [-m MSG] [--confirm S]  apply the candidate; with --confirm it rolls
                                 back after S seconds unless confirmed
  confirm                        keep a commit made with --confirm
  discard                        drop the candidate
  history [-n N]                 list committed revisions
  show-rev REV                   print the config at a revision
  rollback REV                   re-apply an older revision (hash or HEAD~N)
  status                         revision, pending confirm, interfaces
  counters                       firewall rule hit counters

Offline commands:
  validate FILE                  validate a file
  render FILE [--out DIR]        render a file to DIR (default: print paths)
  factory-default [--sys DIR]    print the default config for this machine
`

type client struct {
	http  *http.Client
	base  string
	token string
}

func newClient(socket, url, token string) *client {
	if url != "" {
		return &client{http: &http.Client{Timeout: 2 * time.Minute}, base: strings.TrimSuffix(url, "/"), token: token}
	}
	tr := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", socket)
	}}
	return &client{http: &http.Client{Transport: tr, Timeout: 2 * time.Minute}, base: "http://agent"}
}

func (c *client) do(method, path string, body io.Reader, ctype string) ([]byte, int, error) {
	req, err := http.NewRequest(method, c.base+path, body)
	if err != nil {
		return nil, 0, err
	}
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("cannot reach mahan-agent: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	return data, resp.StatusCode, err
}

// apiError formats an error response, listing validation problems.
func apiError(data []byte, code int) error {
	var e struct {
		Error    string   `json:"error"`
		Problems []string `json:"problems"`
	}
	if json.Unmarshal(data, &e) != nil || e.Error == "" {
		return fmt.Errorf("HTTP %d: %s", code, bytes.TrimSpace(data))
	}
	if len(e.Problems) > 0 {
		return errors.New("invalid config:\n  - " + strings.Join(e.Problems, "\n  - "))
	}
	return errors.New(e.Error)
}

func (c *client) call(method, path string, body io.Reader, ctype string) ([]byte, error) {
	data, code, err := c.do(method, path, body, ctype)
	if err != nil {
		return nil, err
	}
	if code >= 300 {
		return data, apiError(data, code)
	}
	return data, nil
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	g := flag.NewFlagSet("mrctl", flag.ContinueOnError)
	socket := g.String("socket", "/run/mahan-router/agent.sock", "agent Unix socket")
	url := g.String("url", os.Getenv("MRCTL_URL"), "agent URL for remote access")
	token := g.String("token", os.Getenv("MRCTL_TOKEN"), "API token for --url")
	g.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	if err := g.Parse(args); err != nil {
		return err
	}
	if g.NArg() == 0 {
		g.Usage()
		return errors.New("no command")
	}
	cmd, rest := g.Arg(0), g.Args()[1:]
	c := newClient(*socket, *url, *token)
	printOut := func(data []byte, err error) error {
		if err != nil {
			return err
		}
		os.Stdout.Write(data)
		return nil
	}

	switch cmd {
	case "show":
		which := "running"
		if len(rest) > 0 {
			which = rest[0]
		}
		if which != "running" && which != "candidate" {
			return errors.New("show running|candidate")
		}
		return printOut(c.call("GET", "/api/v1/config/"+which, nil, ""))
	case "show-rev":
		if len(rest) != 1 {
			return errors.New("show-rev REV")
		}
		return printOut(c.call("GET", "/api/v1/history/"+rest[0], nil, ""))
	case "load":
		if len(rest) != 1 {
			return errors.New("load FILE")
		}
		data, err := os.ReadFile(rest[0])
		if err != nil {
			return err
		}
		return putCandidate(c, data)
	case "edit":
		return edit(c)
	case "diff":
		return printOut(c.call("GET", "/api/v1/config/diff", nil, ""))
	case "validate":
		if len(rest) == 1 {
			return validateFile(rest[0])
		}
		if _, err := c.call("POST", "/api/v1/config/validate", nil, ""); err != nil {
			return err
		}
		fmt.Println("candidate is valid")
		return nil
	case "commit":
		f := flag.NewFlagSet("commit", flag.ContinueOnError)
		msg := f.String("m", "", "commit message")
		confirm := f.Int("confirm", 0, "seconds until automatic rollback unless confirmed")
		if _, err := parseAll(f, rest); err != nil {
			return err
		}
		body, _ := json.Marshal(map[string]any{"message": *msg, "confirm_seconds": *confirm})
		data, err := c.call("POST", "/api/v1/commit", bytes.NewReader(body), "application/json")
		if err != nil {
			return err
		}
		var res agent.CommitResult
		_ = json.Unmarshal(data, &res)
		fmt.Printf("committed %s\n", res.Revision)
		if res.Apply != nil {
			fmt.Printf("  reloaded: %s\n", strings.Join(res.Apply.Components, ", "))
			for _, w := range res.Apply.Warnings {
				fmt.Printf("  warning: %s\n", w)
			}
		}
		if res.Pending != nil {
			fmt.Printf("  run 'mrctl confirm' within %d seconds or it rolls back\n", res.Pending.Seconds)
		}
		return nil
	case "confirm":
		if _, err := c.call("POST", "/api/v1/confirm", nil, ""); err != nil {
			return err
		}
		fmt.Println("confirmed")
		return nil
	case "discard":
		_, err := c.call("DELETE", "/api/v1/config/candidate", nil, "")
		return err
	case "history":
		f := flag.NewFlagSet("history", flag.ContinueOnError)
		n := f.Int("n", 20, "number of revisions")
		if err := f.Parse(rest); err != nil {
			return err
		}
		data, err := c.call("GET", fmt.Sprintf("/api/v1/history?limit=%d", *n), nil, "")
		if err != nil {
			return err
		}
		var revs []struct {
			Short, Author, Message string
			Time                   time.Time
		}
		if err := json.Unmarshal(data, &revs); err != nil {
			return err
		}
		for _, r := range revs {
			fmt.Printf("%s  %s  %-10s  %s\n", r.Short, r.Time.Local().Format("2006-01-02 15:04:05"), r.Author, r.Message)
		}
		return nil
	case "rollback":
		if len(rest) != 1 {
			return errors.New("rollback REV")
		}
		body, _ := json.Marshal(map[string]string{"revision": rest[0]})
		data, err := c.call("POST", "/api/v1/rollback", bytes.NewReader(body), "application/json")
		if err != nil {
			return err
		}
		var res agent.CommitResult
		_ = json.Unmarshal(data, &res)
		fmt.Printf("rolled back, new revision %s\n", res.Revision)
		return nil
	case "status":
		return printOut(c.call("GET", "/api/v1/status", nil, ""))
	case "counters":
		return printOut(c.call("GET", "/api/v1/firewall/counters", nil, ""))
	case "render":
		return renderFile(rest)
	case "factory-default":
		f := flag.NewFlagSet("factory-default", flag.ContinueOnError)
		sys := f.String("sys", "/sys/class/net", "sysfs net directory")
		if err := f.Parse(rest); err != nil {
			return err
		}
		nics, err := config.DetectNICs(*sys)
		if err != nil {
			return err
		}
		data, err := config.Marshal(config.FactoryDefault(nics))
		if err != nil {
			return err
		}
		os.Stdout.Write(data)
		return nil
	case "help", "-h", "--help":
		fmt.Print(usage)
		return nil
	}
	return fmt.Errorf("unknown command %q (try mrctl help)", cmd)
}

func putCandidate(c *client, data []byte) error {
	out, err := c.call("PUT", "/api/v1/config/candidate", bytes.NewReader(data), "application/yaml")
	if err != nil {
		return err
	}
	var r struct {
		Valid    bool     `json:"valid"`
		Problems []string `json:"problems"`
	}
	_ = json.Unmarshal(out, &r)
	if r.Valid {
		fmt.Println("candidate saved and valid; review with 'mrctl diff', apply with 'mrctl commit'")
	} else {
		fmt.Println("candidate saved but NOT valid yet:\n  - " + strings.Join(r.Problems, "\n  - "))
	}
	return nil
}

func edit(c *client) error {
	data, err := c.call("GET", "/api/v1/config/candidate", nil, "")
	if err != nil {
		return err
	}
	f, err := os.CreateTemp("", "mrctl-*.yaml")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	f.Write(data)
	f.Close()
	editor := os.Getenv("EDITOR")
	if editor == "" {
		editor = "vi"
	}
	cmd := exec.Command(editor, f.Name())
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		return err
	}
	edited, err := os.ReadFile(f.Name())
	if err != nil {
		return err
	}
	if bytes.Equal(edited, data) {
		fmt.Println("no changes")
		return nil
	}
	return putCandidate(c, edited)
}

func validateFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if _, _, err := agent.Prepare(data); err != nil {
		return err
	}
	fmt.Println(path + ": valid")
	return nil
}

func renderFile(args []string) error {
	f := flag.NewFlagSet("render", flag.ContinueOnError)
	out := f.String("out", "", "write files under this directory")
	pos, err := parseAll(f, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return errors.New("render FILE [--out DIR]")
	}
	data, err := os.ReadFile(pos[0])
	if err != nil {
		return err
	}
	_, b, err := agent.Prepare(data)
	if err != nil {
		return err
	}
	for _, p := range b.Paths() {
		file := b[p]
		if *out == "" {
			fmt.Printf("%-8s %04o %s\n", file.Component, file.Mode, p)
			continue
		}
		dst := filepath.Join(*out, p)
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(dst, []byte(file.Content), os.FileMode(file.Mode)); err != nil {
			return err
		}
	}
	if *out != "" {
		fmt.Printf("rendered %d files under %s\n", len(b), *out)
	}
	return nil
}

// parseAll parses flags that may appear before or after positional args.
func parseAll(f *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := f.Parse(args); err != nil {
			return nil, err
		}
		if f.NArg() == 0 {
			return pos, nil
		}
		pos = append(pos, f.Arg(0))
		args = f.Args()[1:]
	}
}
