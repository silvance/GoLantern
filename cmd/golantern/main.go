// golantern is the Go port of the lantern CLI/server.
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
	"github.com/silvance/golantern/internal/audit"
	"github.com/silvance/golantern/internal/engine"
	"github.com/silvance/golantern/internal/entity"
	"github.com/silvance/golantern/internal/finding"
	"github.com/silvance/golantern/internal/jobs"
	"github.com/silvance/golantern/internal/project"
	"github.com/silvance/golantern/internal/run"
	"github.com/silvance/golantern/internal/scan"
	"github.com/silvance/golantern/internal/scan/collectors/fixture"
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
  serve     Start the HTTP API.

Run 'golantern serve --help' for flags.`)
	return nil
}

// repos bundles every domain repository the server needs. Kept here so
// the SQLite and in-memory branches return the same shape and the rest
// of cmdServe is store-agnostic.
type repos struct {
	Projects project.Repository
	Scopes   scope.Repository
	Runs     run.Repository
	Audit    audit.Repository
	Entities entity.Repository
	Findings finding.Repository
}

func cmdServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	addr := fs.String("addr", "127.0.0.1:8000", "listen address")
	dbPath := fs.String("db", "", "SQLite database path; empty uses an in-memory store")
	demo := fs.Bool("seed-demo", false, "preload a demo project before serving")
	workers := fs.Int("workers", 2, "number of scan-engine workers")
	if err := fs.Parse(args); err != nil {
		return err
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	r, cleanup, err := openRepos(*dbPath, logger, *demo)
	if err != nil {
		return err
	}
	defer cleanup()

	// Collector registry. cmd/golantern is the one place collectors
	// get wired; new collectors register here as they land.
	reg := scan.NewRegistry()
	reg.Register(fixture.Name, fixture.New)

	// Queue + run-level orchestrator. The queue takes a Handler that
	// closes over engine.ExecuteRun so the queue package keeps no
	// dependency on engine.
	executeRunDeps := engine.ExecuteRunDeps{
		Runs: r.Runs,
		ScanDeps: scan.Deps{
			Runs:     r.Runs,
			Entities: r.Entities,
			Findings: r.Findings,
			// Scope is set per-run by LoadPolicyFn.
		},
		Registry: reg,
		Audit:    r.Audit,
		Logger:   logger,
		LoadPolicyFn: func(ctx context.Context, projectID string) (*scan.Deps, error) {
			pol, err := engine.LoadPolicy(ctx, r.Projects, r.Scopes, projectID)
			if err != nil {
				return nil, err
			}
			return &scan.Deps{Scope: pol}, nil
		},
	}
	q, err := jobs.New(func(ctx context.Context, j jobs.Job) error {
		invocations := make([]engine.Invocation, len(j.Invocations))
		for i, inv := range j.Invocations {
			invocations[i] = engine.Invocation{Tool: inv.Tool, Parameters: inv.Parameters}
		}
		return engine.ExecuteRun(ctx, executeRunDeps, j.RunID, invocations)
	}, jobs.Options{Concurrency: *workers, Logger: logger})
	if err != nil {
		return err
	}
	if err := q.Start(context.Background()); err != nil {
		return err
	}

	srv := api.New(r.Projects, r.Scopes, r.Runs, r.Audit)
	srv.Logger = logger
	srv.Entities = r.Entities
	srv.Findings = r.Findings
	srv.Enqueue = func(ctx context.Context, runID string, invocations []api.ToolInvocation) error {
		jobInvs := make([]jobs.Invocation, len(invocations))
		for i, inv := range invocations {
			jobInvs[i] = jobs.Invocation{Tool: inv.Tool, Parameters: inv.Parameters}
		}
		return q.Submit(ctx, jobs.Job{RunID: runID, Invocations: jobInvs})
	}

	httpSrv := &http.Server{
		Addr:              *addr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

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
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		// HTTP first so no new jobs land, then drain the queue.
		if err := httpSrv.Shutdown(shutdownCtx); err != nil {
			logger.Warn("http shutdown error", slog.Any("err", err))
		}
		if err := q.Shutdown(shutdownCtx); err != nil {
			logger.Warn("queue shutdown error", slog.Any("err", err))
		}
		return nil
	case err := <-errCh:
		return err
	}
}

// openRepos opens (or creates) the configured store and seeds the demo
// fixture when requested. Returns a cleanup func the caller defers.
func openRepos(dbPath string, logger *slog.Logger, seedDemo bool) (*repos, func(), error) {
	if dbPath == "" {
		st := memory.New()
		if seedDemo {
			if err := seedDemoInto(context.Background(), st.Projects, st.Scopes, st.Runs); err != nil {
				return nil, nil, fmt.Errorf("seed demo: %w", err)
			}
			logger.Info("seeded demo project (in-memory store)")
		}
		return &repos{
			Projects: st.Projects, Scopes: st.Scopes, Runs: st.Runs, Audit: st.Audit,
			Entities: st.Entities, Findings: st.Findings,
		}, func() {}, nil
	}

	db, err := sqlite.Open(dbPath)
	if err != nil {
		return nil, nil, err
	}
	if err := sqlite.Migrate(context.Background(), db); err != nil {
		db.Close()
		return nil, nil, err
	}
	st := sqlite.NewStore(db)
	if seedDemo {
		if err := seedDemoInto(context.Background(), st.Projects, st.Scopes, st.Runs); err != nil {
			db.Close()
			return nil, nil, fmt.Errorf("seed demo: %w", err)
		}
		logger.Info("seeded demo project", slog.String("db", dbPath))
	}
	return &repos{
			Projects: st.Projects, Scopes: st.Scopes, Runs: st.Runs, Audit: st.Audit,
			Entities: st.Entities, Findings: st.Findings,
		}, func() {
			db.Close()
		}, nil
}

// seedFixture is the shared demo data. Project/Rules survive in any
// store; the Run is created COMPLETED so it doesn't get re-dispatched
// on each server restart.
type seedFixture struct {
	Project *project.Project
	Rules   []*scope.StoredRule
	Run     *run.Run
}

func newSeedFixture() *seedFixture {
	p := &project.Project{
		Name:         "Demo: acme.example",
		Description:  "Seeded demo for the Go server",
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
