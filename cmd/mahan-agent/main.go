// Command mahan-agent is core-agent: it owns the router configuration and
// serves the management API.
package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/ashayesteh86/MahanRouter/internal/agent"
	"github.com/ashayesteh86/MahanRouter/internal/api"
	"github.com/ashayesteh86/MahanRouter/internal/apply"
	"github.com/ashayesteh86/MahanRouter/internal/config"
	"github.com/ashayesteh86/MahanRouter/internal/store"
)

var version = "dev"

func main() {
	stateDir := flag.String("state", "/var/lib/mahan-router", "state directory (config repo, manifest)")
	root := flag.String("root", "/", "filesystem root for rendered files (lab: a temp dir)")
	socket := flag.String("socket", "/run/mahan-router/agent.sock", "Unix socket for local tools")
	listen := flag.String("listen", "", "optional TCP address for the API, e.g. 127.0.0.1:8090")
	tokenFile := flag.String("token-file", "/etc/mahan-router/api-token", "bearer token file for the TCP API")
	noReload := flag.Bool("no-reload", false, "write files but do not reload services (lab mode)")
	flag.Parse()

	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	log.Info("mahan-agent starting", "version", version, "root", *root, "state", *stateDir)

	if err := os.MkdirAll(*stateDir, 0o700); err != nil {
		log.Error("state dir", "err", err)
		os.Exit(1)
	}
	ag := &agent.Agent{
		Store: &store.Store{Dir: *stateDir},
		Applier: &apply.Applier{
			Root: *root, StateDir: *stateDir, Reload: !*noReload, Precheck: true, Log: log,
		},
		Log: log,
	}
	factory := func() *config.Config {
		nics, err := config.DetectNICs("/sys/class/net")
		if err != nil {
			log.Warn("NIC detection failed", "err", err)
		}
		return config.FactoryDefault(nics)
	}
	if err := ag.Boot(factory); err != nil {
		// Keep serving the API so the operator can fix the config.
		log.Error("boot apply failed", "err", err)
	}

	srv := &api.Server{Agent: ag}
	var servers []*http.Server

	_ = os.MkdirAll(filepath.Dir(*socket), 0o750)
	_ = os.Remove(*socket)
	ul, err := net.Listen("unix", *socket)
	if err != nil {
		log.Error("listen unix", "err", err)
		os.Exit(1)
	}
	_ = os.Chmod(*socket, 0o660)
	us := &http.Server{Handler: srv.Handler(true), ReadHeaderTimeout: 10 * time.Second}
	servers = append(servers, us)
	go serve(log, us, ul)

	if *listen != "" {
		tok, err := os.ReadFile(*tokenFile)
		if err != nil || len(strings.TrimSpace(string(tok))) < 16 {
			log.Error("TCP API needs a token of at least 16 characters", "file", *tokenFile)
			os.Exit(1)
		}
		srv.Token = strings.TrimSpace(string(tok))
		tl, err := net.Listen("tcp", *listen)
		if err != nil {
			log.Error("listen tcp", "err", err)
			os.Exit(1)
		}
		ts := &http.Server{Handler: srv.Handler(false), ReadHeaderTimeout: 10 * time.Second}
		servers = append(servers, ts)
		go serve(log, ts, tl)
		log.Info("TCP API listening", "addr", *listen)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()
	sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, s := range servers {
		_ = s.Shutdown(sctx)
	}
	log.Info("stopped")
}

func serve(log *slog.Logger, s *http.Server, l net.Listener) {
	if err := s.Serve(l); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Error("api server", "err", err)
	}
}
