package engine

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/silvance/golantern/internal/audit"
	"github.com/silvance/golantern/internal/events"
	"github.com/silvance/golantern/internal/run"
	"github.com/silvance/golantern/internal/scan"
)

// Invocation is one (tool name, parameters) pair scheduled inside a Run.
type Invocation struct {
	Tool       string
	Parameters map[string]any
}

// ExecuteRunDeps bundles everything the run-level orchestrator needs.
//
// LoadPolicyFn is injected (rather than taking project + scope repos
// directly) so callers can stub the policy in tests without
// round-tripping through repositories. Production callers pass a
// one-line closure around engine.LoadPolicy.
type ExecuteRunDeps struct {
	Runs         run.Repository
	ScanDeps     scan.Deps // Entities/Findings; Scope is overwritten per-run by LoadPolicyFn
	Registry     *scan.Registry
	Audit        audit.Repository // optional
	Bus          *events.Bus      // optional; publishes run.started / run.finished and wires the scan runner
	Logger       *slog.Logger     // defaults to slog.Default
	LoadPolicyFn func(ctx context.Context, projectID string) (*scan.Deps, error)
}

// ExecuteRun runs every invocation in the given list against the Run
// identified by runID, updating the Run's status as it goes. Mirrors
// WorkflowEngine.execute_run from lantern/workflow/engine.py.
//
// Behaviour summary:
//
//   - Refuse to start if the Run is missing or in a terminal status.
//   - Set status -> RUNNING, started_at = now.
//   - For each (tool, params): look up the factory, call
//     scan.Runner.Execute, track failure.
//   - Unknown tool name => mark FAILED with error_summary, continue
//     (Python's "Run-level failure: record it on the Run row and
//     continue rather than re-raising"; re-raising would leave the
//     run stuck RUNNING from the UI's perspective).
//   - Scope policy and scan.Runner are bound to the project at the
//     start; rules added mid-run don't affect already-dispatched
//     invocations. Same as Python.
//   - Aggregate status: any failed/skipped invocation -> Run FAILED;
//     otherwise Run COMPLETED. ToolStatusSkippedOutOfScope counts as
//     failure (matches Python's `tx.status.value == "failed"` check —
//     this catches reachability skips too because the test there is
//     "did anything go wrong").
func ExecuteRun(
	ctx context.Context,
	deps ExecuteRunDeps,
	runID string,
	invocations []Invocation,
) error {
	if deps.Registry == nil {
		return errors.New("engine.ExecuteRun: Registry is required")
	}
	if deps.Runs == nil {
		return errors.New("engine.ExecuteRun: Runs repository is required")
	}
	if deps.LoadPolicyFn == nil {
		return errors.New("engine.ExecuteRun: LoadPolicyFn is required")
	}
	logger := deps.Logger
	if logger == nil {
		logger = slog.Default()
	}

	ru, err := deps.Runs.Get(ctx, runID)
	if err != nil {
		return fmt.Errorf("ExecuteRun: load run: %w", err)
	}
	if ru.Status != run.StatusPending && ru.Status != run.StatusRunning {
		return fmt.Errorf("ExecuteRun: run %s cannot execute from status %q", runID, ru.Status)
	}

	scanDeps, err := deps.LoadPolicyFn(ctx, ru.ProjectID)
	if err != nil {
		return fmt.Errorf("ExecuteRun: load scope policy: %w", err)
	}
	// Merge the per-run scope into the static ScanDeps the caller
	// configured (Entities/Findings/Runs). The caller's Scope field is
	// ignored here on purpose.
	bound := deps.ScanDeps
	bound.Scope = scanDeps.Scope
	if bound.Runs == nil {
		bound.Runs = deps.Runs
	}
	runner, err := scan.NewRunner(bound, logger, deps.Audit)
	if err != nil {
		return fmt.Errorf("ExecuteRun: build runner: %w", err)
	}
	if deps.Bus != nil {
		runner.SetBus(deps.Bus)
	}

	now := time.Now().UTC()
	ru.Status = run.StatusRunning
	if ru.StartedAt == nil {
		ru.StartedAt = &now
	}
	if err := deps.Runs.Save(ctx, ru); err != nil {
		return fmt.Errorf("ExecuteRun: mark running: %w", err)
	}
	if deps.Bus != nil {
		deps.Bus.Publish(events.Event{
			RunID: runID, Kind: events.KindRunStarted,
			Payload: map[string]any{
				"phase":       string(ru.Phase),
				"tool_count":  len(invocations),
				"label":       ru.Label,
			},
		})
	}

	anyFailed := false
	cancelled := false
	for _, inv := range invocations {
		// Cooperative cancellation: a separate request can flip the
		// run row to CANCELLED while we're iterating. Re-fetch before
		// each dispatch so that the next collector doesn't start.
		// Already-in-flight collectors finish naturally — the runner
		// has no signal channel back to us, and trying to kill them
		// mid-write would corrupt their tool-execution row.
		if cur, err := deps.Runs.Get(ctx, runID); err == nil &&
			cur.Status == run.StatusCancelled {
			cancelled = true
			logger.InfoContext(ctx, "run cancelled mid-flight; not dispatching remaining tools",
				slog.String("run_id", runID))
			break
		}
		factory, err := deps.Registry.Get(inv.Tool)
		if err != nil {
			// Unknown tool: don't re-raise (would roll back to the
			// pre-flush state and leave the run stuck RUNNING). Record
			// it on the Run and move on.
			logger.WarnContext(ctx, "unknown collector",
				slog.String("run_id", runID),
				slog.String("tool", inv.Tool))
			ru.ErrorSummary = err.Error()
			anyFailed = true
			continue
		}
		tx, err := runner.Execute(ctx, ru.ProjectID, ru.ID, factory(), inv.Parameters)
		if err != nil {
			// scan.Runner.Execute only returns an error for infra
			// failures (DB unreachable). Tool-level errors land in
			// tx.Status. Record this on the Run and continue so the
			// state machine still terminates.
			logger.ErrorContext(ctx, "runner crashed",
				slog.String("run_id", runID),
				slog.String("tool", inv.Tool),
				slog.Any("err", err))
			ru.ErrorSummary = fmt.Sprintf("runner crashed on %q: %v", inv.Tool, err)
			anyFailed = true
			continue
		}
		if tx.Status == run.ToolStatusFailed || tx.Status == run.ToolStatusSkippedOutOfScope {
			anyFailed = true
		}
	}

	finishedAt := time.Now().UTC()
	ru.FinishedAt = &finishedAt
	switch {
	case cancelled:
		ru.Status = run.StatusCancelled
	case anyFailed:
		ru.Status = run.StatusFailed
	default:
		ru.Status = run.StatusCompleted
	}
	if err := deps.Runs.Save(ctx, ru); err != nil {
		return fmt.Errorf("ExecuteRun: finalize run: %w", err)
	}

	if deps.Audit != nil {
		if err := deps.Audit.Record(ctx, &audit.LogEntry{
			ProjectID: ru.ProjectID,
			Action:    audit.ActionRunFinished,
			Target:    ru.ID,
			Detail: map[string]any{
				"status": string(ru.Status),
				"phase":  string(ru.Phase),
			},
		}); err != nil {
			logger.WarnContext(ctx, "run.finished audit failed",
				slog.String("run_id", runID),
				slog.Any("err", err))
		}
	}
	if deps.Bus != nil {
		deps.Bus.Publish(events.Event{
			RunID: runID, Kind: events.KindRunFinished,
			Payload: map[string]any{
				"phase":  string(ru.Phase),
				"status": string(ru.Status),
			},
		})
	}
	return nil
}
