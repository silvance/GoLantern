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
	"github.com/silvance/golantern/internal/store/sqlite"
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
	dbPath := fs.String("db", "", "SQLite database path; empty uses an in-memory store")
	demo := fs.Bool("seed-demo", false, "preload a demo project before serving")
	if err := fs.Parse(args); err != nil {
		return err
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	var projects project.Repository
	var scopes scope.Repository
	var runs run.Repository

	if *dbPath == "" {
		st := memory.New()
		if *demo {
			if err := seedDemoMemory(st); err != nil {
				return fmt.Errorf("seed demo: %w", err)
			}
			logger.Info("seeded demo project (in-memory store)")
		}
		projects, scopes, runs = st.Projects, st.Scopes, st.Runs
	} else {
		db, err := sqlite.Open(*dbPath)
		if err != nil {
			return err
		}
		defer db.Close()
		if err := sqlite.Migrate(context.Background(), db); err != nil {
			return err
		}
		st := sqlite.NewStore(db)
		if *demo {
			if err := seedDemoSQLite(st); err != nil {
				return fmt.Errorf("seed demo: %w", err)
			}
			logger.Info("seeded demo project", slog.String("db", *dbPath))
		}
		projects, scopes, runs = st.Projects, st.Scopes, st.Runs
	}

	srv := api.New(projects, scopes, runs)
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

// seedFixture is the shared fixture both stores use so the demo data is
// identical regardless of backend. Returns a fresh fixture each call;
// repository.Save assigns IDs.
type seedFixture struct {
	Project *project.Project
	Rules   []*scope.StoredRule
	Run     *run.Run
}

func newSeedFixture() *seedFixture {
	p := &project.Project{
		Name:         "Demo: acme.example",
		Description:  "Seeded demo for the Go read-side server",
		Organization: "Acme Co",
		DefaultScope: scope.KindPassive,
		Mode:         project.ModeAssessment,
	}
	return &seedFixture{
		Project: p,
		Rules: []*scope.StoredRule{
			{Rule: scope.Rule{Pattern: "*.acme.example", Kind: scope.KindLightActive}},
			{Rule: scope.Rule{Pattern: "api.acme.example", Kind: scope.KindFullActive}},
			{Rule: scope.Rule{Pattern: "legacy.acme.example", Kind: scope.KindDeny}},
		},
		Run: &run.Run{
			Phase:  workflow.PhaseOSINT,
			Status: run.StatusCompleted,
			Label:  "initial OSINT sweep",
		},
	}
}

func seedDemoMemory(st *memory.Store) error {
	return seedDemoInto(context.Background(), st.Projects, st.Scopes, st.Runs)
}

func seedDemoSQLite(st *sqlite.Store) error {
	return seedDemoInto(context.Background(), st.Projects, st.Scopes, st.Runs)
}

// seedDemoInto is store-agnostic: it consumes the repository interfaces,
// so adding another backend later (Postgres) doesn't need another seed
// function. Idempotent: a duplicate project from a prior seed surfaces
// as ErrDuplicate and is treated as a no-op.
func seedDemoInto(
	ctx context.Context,
	projects project.Repository,
	scopes scope.Repository,
	runs run.Repository,
) error {
	f := newSeedFixture()
	if err := projects.Save(ctx, f.Project); err != nil {
		if errors.Is(err, project.ErrDuplicate) {
			return nil
		}
		return err
	}
	for _, sr := range f.Rules {
		sr.ProjectID = f.Project.ID
		if err := scopes.Add(ctx, sr); err != nil {
			return err
		}
	}
	f.Run.ProjectID = f.Project.ID
	return runs.Save(ctx, f.Run)
}
