// golantern is the Go port of the lantern CLI/server. Phase-2 build:
// serves the read-side API against an in-memory store (data does not
// persist across restarts). The SQLite store lands in a later phase.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/silvance/golantern/internal/api"
	"github.com/silvance/golantern/internal/project"
	"github.com/silvance/golantern/internal/run"
	"github.com/silvance/golantern/internal/scope"
	"github.com/silvance/golantern/internal/store/memory"
	"github.com/silvance/golantern/internal/workflow"
)

func main() {
	if err := run_(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "golantern:", err)
		os.Exit(1)
	}
}

func run_(args []string) error {
	if len(args) == 0 {
		return usage()
	}
	switch args[0] {
	case "serve":
		return cmdServe(args[1:])
	case "help", "-h", "--help":
		return usage()
	default:
		return fmt.Errorf("unknown command %q; try 'golantern help'", args[0])
	}
}

func usage() error {
	fmt.Println(`golantern - workflow engine for LCVA / OSINT-driven attack-surface discovery

Subcommands:
  serve     Start the HTTP API against an in-memory store.

Run 'golantern serve --help' for flags.`)
	return nil
}

func cmdServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	addr := fs.String("addr", "127.0.0.1:8000", "listen address")
	demo := fs.Bool("seed-demo", false, "preload a demo project before serving")
	if err := fs.Parse(args); err != nil {
		return err
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	st := memory.New()
	if *demo {
		if err := seedDemo(st); err != nil {
			return fmt.Errorf("seed demo: %w", err)
		}
		logger.Info("seeded demo project")
	}

	srv := api.New(st.Projects, st.Scopes, st.Runs)
	srv.Logger = logger

	httpSrv := &http.Server{
		Addr:              *addr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	// Shut down cleanly on SIGINT/SIGTERM so the dev-loop ^C doesn't
	// leak a port. The Python version relies on uvicorn for this; in
	// Go we wire it explicitly.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		logger.Info("listening", slog.String("addr", *addr))
		err := httpSrv.ListenAndServe()
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
			return
		}
		errCh <- nil
	}()

	select {
	case <-ctx.Done():
		logger.Info("shutdown signal received")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := httpSrv.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("shutdown: %w", err)
		}
		return nil
	case err := <-errCh:
		return err
	}
}

// seedDemo writes a small fixture so an operator can poke at the read
// endpoints without first writing through the API. The shape mirrors
// lantern.demo.seed_demo_project at a much smaller scale.
func seedDemo(st *memory.Store) error {
	ctx := context.Background()
	p := &project.Project{
		Name:         "Demo: acme.example",
		Description:  "Seeded demo for the Go read-side server",
		Organization: "Acme Co",
		DefaultScope: scope.KindPassive,
		Mode:         project.ModeAssessment,
	}
	if err := st.Projects.Save(ctx, p); err != nil {
		return err
	}
	for _, r := range []struct {
		pattern string
		kind    scope.RuleKind
	}{
		{"*.acme.example", scope.KindLightActive},
		{"api.acme.example", scope.KindFullActive},
		{"legacy.acme.example", scope.KindDeny},
	} {
		if err := st.Scopes.Add(ctx, &scope.StoredRule{
			ProjectID: p.ID, Rule: scope.Rule{Pattern: r.pattern, Kind: r.kind},
		}); err != nil {
			return err
		}
	}
	ru := &run.Run{
		ProjectID: p.ID,
		Phase:     workflow.PhaseOSINT,
		Status:    run.StatusCompleted,
		Label:     "initial OSINT sweep",
	}
	return st.Runs.Save(ctx, ru)
}
