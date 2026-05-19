package engine_test

import (
	"context"
	"errors"
	"testing"

	"github.com/silvance/golantern/internal/audit"
	"github.com/silvance/golantern/internal/engine"
	"github.com/silvance/golantern/internal/entity"
	"github.com/silvance/golantern/internal/finding"
	"github.com/silvance/golantern/internal/project"
	"github.com/silvance/golantern/internal/run"
	"github.com/silvance/golantern/internal/scan"
	"github.com/silvance/golantern/internal/scan/collectors/fixture"
	"github.com/silvance/golantern/internal/scope"
	"github.com/silvance/golantern/internal/store/memory"
	"github.com/silvance/golantern/internal/workflow"
)

// execSetup builds a memory store with a project, scope rules, a
// PENDING run, a registry containing the fixture collector, and the
// ExecuteRunDeps to drive it.
func execSetup(t *testing.T, rules []scope.Rule) (*memory.Store, *project.Project, *run.Run, engine.ExecuteRunDeps) {
	t.Helper()
	st := memory.New()
	ctx := context.Background()

	p := &project.Project{Name: "X", DefaultScope: scope.KindPassive, Mode: project.ModeAssessment}
	if err := st.Projects.Save(ctx, p); err != nil {
		t.Fatal(err)
	}
	for _, r := range rules {
		if err := st.Scopes.Add(ctx, &scope.StoredRule{ProjectID: p.ID, Rule: r}); err != nil {
			t.Fatal(err)
		}
	}
	ru := &run.Run{ProjectID: p.ID, Phase: workflow.PhaseOSINT, Status: run.StatusPending}
	if err := st.Runs.Save(ctx, ru); err != nil {
		t.Fatal(err)
	}

	reg := scan.NewRegistry()
	reg.Register(fixture.Name, fixture.New)

	deps := engine.ExecuteRunDeps{
		Runs: st.Runs,
		ScanDeps: scan.Deps{
			Runs:     st.Runs,
			Entities: st.Entities,
			Findings: st.Findings,
		},
		Registry: reg,
		Audit:    st.Audit,
		LoadPolicyFn: func(ctx context.Context, projectID string) (*scan.Deps, error) {
			pol, err := engine.LoadPolicy(ctx, st.Projects, st.Scopes, projectID)
			if err != nil {
				return nil, err
			}
			return &scan.Deps{Scope: pol}, nil
		},
	}
	return st, p, ru, deps
}

func TestExecuteRunHappyPath(t *testing.T) {
	st, _, ru, deps := execSetup(t, []scope.Rule{
		{Pattern: "*.example.com", Kind: scope.KindLightActive},
	})
	if err := engine.ExecuteRun(context.Background(), deps, ru.ID, []engine.Invocation{
		{Tool: fixture.Name, Parameters: map[string]any{
			"targets":       []any{"a.example.com", "b.example.com"},
			"finding_title": "OSINT findings",
		}},
	}); err != nil {
		t.Fatal(err)
	}
	got, _ := st.Runs.Get(context.Background(), ru.ID)
	if got.Status != run.StatusCompleted {
		t.Fatalf("status=%s err=%q", got.Status, got.ErrorSummary)
	}
	values, _ := st.Entities.ListValuesByKind(context.Background(), got.ProjectID, entity.KindDomain)
	if len(values) != 2 {
		t.Fatalf("entities persisted=%d, want 2", len(values))
	}
	findings, _ := st.Findings.ListFindings(context.Background(), got.ProjectID)
	if len(findings) != 1 || findings[0].Severity != finding.SeverityLow {
		t.Fatalf("finding wrong: %+v", findings)
	}
	// Final audit row: run.finished newest-first.
	rows, _ := st.Audit.ListByProject(context.Background(), got.ProjectID)
	if rows[0].Action != audit.ActionRunFinished {
		t.Fatalf("audit head should be run.finished, got %q", rows[0].Action)
	}
	if rows[0].Detail["status"] != "completed" {
		t.Fatalf("run.finished detail.status = %v, want completed", rows[0].Detail["status"])
	}
}

func TestExecuteRunUnknownToolMarksFailed(t *testing.T) {
	st, _, ru, deps := execSetup(t, []scope.Rule{
		{Pattern: "*.example.com", Kind: scope.KindLightActive},
	})
	if err := engine.ExecuteRun(context.Background(), deps, ru.ID, []engine.Invocation{
		{Tool: "no_such_collector", Parameters: nil},
	}); err != nil {
		t.Fatal(err)
	}
	got, _ := st.Runs.Get(context.Background(), ru.ID)
	if got.Status != run.StatusFailed {
		t.Fatalf("status=%s, want failed", got.Status)
	}
	if got.ErrorSummary == "" {
		t.Fatal("error_summary should record the unknown-tool failure")
	}
}

func TestExecuteRunFailedToolExecutionFlagsRun(t *testing.T) {
	// Reachable at default (light_active), but the targets don't match
	// any rule, so per-target IsInScope rejects everything. The
	// fixture collector emits zero entities; the runner's zero-emission
	// diagnostic doesn't flip status, but the SKIPPED states do — the
	// fixture doesn't trigger that path either. So we use a collector
	// that returns an error to confirm the run-level aggregation
	// behaviour.
	st, _, ru, deps := execSetup(t, []scope.Rule{
		{Pattern: "*.example.com", Kind: scope.KindLightActive},
	})
	// Substitute a guaranteed-failing collector under a new name.
	deps.Registry.Register("boom", func() scan.Collector { return &errCollector{} })
	if err := engine.ExecuteRun(context.Background(), deps, ru.ID, []engine.Invocation{
		{Tool: "boom"},
	}); err != nil {
		t.Fatal(err)
	}
	got, _ := st.Runs.Get(context.Background(), ru.ID)
	if got.Status != run.StatusFailed {
		t.Fatalf("status=%s, want failed (a failing tx must propagate)", got.Status)
	}
}

func TestExecuteRunRefusesTerminalRun(t *testing.T) {
	st, _, ru, deps := execSetup(t, nil)
	ru.Status = run.StatusCompleted
	_ = st.Runs.Save(context.Background(), ru)
	err := engine.ExecuteRun(context.Background(), deps, ru.ID, nil)
	if err == nil {
		t.Fatal("expected refusal for terminal run")
	}
}

func TestExecuteRunPropagatesLoadPolicyError(t *testing.T) {
	_, _, ru, deps := execSetup(t, nil)
	deps.LoadPolicyFn = func(context.Context, string) (*scan.Deps, error) {
		return nil, errors.New("boom")
	}
	err := engine.ExecuteRun(context.Background(), deps, ru.ID, nil)
	if err == nil {
		t.Fatal("expected error from LoadPolicyFn")
	}
}

func TestExecuteRunRejectsMissingDeps(t *testing.T) {
	if err := engine.ExecuteRun(context.Background(), engine.ExecuteRunDeps{}, "x", nil); err == nil {
		t.Fatal("expected error for empty Deps")
	}
}

// errCollector is a tiny collector that always errors. Used to drive
// the failure-aggregation test without depending on the fixture's
// scope-rejection path.
type errCollector struct{}

func (errCollector) Metadata() scan.Meta {
	return scan.Meta{Name: "boom", Phase: workflow.PhaseOSINT, RequiredScope: scope.KindPassive}
}
func (errCollector) Run(_ context.Context, _ scan.Context) error {
	return errors.New("explicit failure")
}

// TestExecuteRunCancelMidFlight verifies the engine's cooperative
// cancellation: when a separate request marks the run as cancelled
// while a collector is running, the next iteration's pre-check
// stops dispatch and the run ends in StatusCancelled. The already-
// running collector finishes naturally (one tool-execution row).
func TestExecuteRunCancelMidFlight(t *testing.T) {
	st, _, ru, deps := execSetup(t, []scope.Rule{
		{Pattern: "*.example.com", Kind: scope.KindLightActive},
	})
	// Custom registry: the cancelling collector flips the run row
	// during its Run() callback; the next collector should never see
	// a dispatch.
	reg := scan.NewRegistry()
	reg.Register("canceller", func() scan.Collector {
		return &cancellingCollector{runs: st.Runs, runID: ru.ID}
	})
	reg.Register(fixture.Name, fixture.New)
	deps.Registry = reg

	if err := engine.ExecuteRun(context.Background(), deps, ru.ID, []engine.Invocation{
		{Tool: "canceller"},
		{Tool: fixture.Name, Parameters: map[string]any{
			"targets": []any{"a.example.com"},
		}},
	}); err != nil {
		t.Fatal(err)
	}
	got, _ := st.Runs.Get(context.Background(), ru.ID)
	if got.Status != run.StatusCancelled {
		t.Fatalf("status=%s, want cancelled", got.Status)
	}
	// Only the canceller should have a tool execution row; the
	// fixture invocation must have been skipped.
	txs, _ := st.Runs.ListToolExecutions(context.Background(), ru.ID)
	if len(txs) != 1 || txs[0].Tool != "canceller" {
		t.Fatalf("expected 1 tx (canceller), got %+v", txs)
	}
}

type cancellingCollector struct {
	runs  run.Repository
	runID string
}

func (c *cancellingCollector) Metadata() scan.Meta {
	return scan.Meta{Name: "canceller", Phase: workflow.PhaseOSINT, RequiredScope: scope.KindPassive}
}
func (c *cancellingCollector) Run(ctx context.Context, _ scan.Context) error {
	ru, err := c.runs.Get(ctx, c.runID)
	if err != nil {
		return err
	}
	ru.Status = run.StatusCancelled
	return c.runs.Save(ctx, ru)
}
