package scan_test

import (
	"context"
	"errors"
	"strings"
	"testing"

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

// fixtureSetup wires a memory store with a project, the requested
// scope rules, and a Run that the runner can attach to. Returns the
// store plus a Deps-ready runner.
func fixtureSetup(t *testing.T, mode project.Mode, rules []scope.Rule, defaultScope scope.RuleKind, required scope.RuleKind) (
	*memory.Store, *scan.Runner, *project.Project, *run.Run,
) {
	t.Helper()
	st := memory.New()
	ctx := context.Background()

	p := &project.Project{Name: "P", DefaultScope: defaultScope, Mode: mode}
	if err := st.Projects.Save(ctx, p); err != nil {
		t.Fatal(err)
	}
	// Persist the rules through the repo so policy compilation goes
	// through the same code path the API uses.
	for _, r := range rules {
		if err := st.Scopes.Add(ctx, &scope.StoredRule{
			ProjectID: p.ID, Rule: r,
		}); err != nil {
			t.Fatal(err)
		}
	}
	stored, _ := st.Scopes.ListByProject(ctx, p.ID)
	compiled := make([]scope.Rule, len(stored))
	for i, s := range stored {
		compiled[i] = s.Rule
	}
	pol, err := scope.Compile(p.ID, p.DefaultScope, compiled)
	if err != nil {
		t.Fatal(err)
	}

	ru := &run.Run{ProjectID: p.ID, Phase: workflow.PhaseOSINT, Status: run.StatusRunning}
	if err := st.Runs.Save(ctx, ru); err != nil {
		t.Fatal(err)
	}

	r, err := scan.NewRunner(scan.Deps{
		Runs:     st.Runs,
		Entities: st.Entities,
		Findings: st.Findings,
		Scope:    pol,
	}, nil, st.Audit)
	if err != nil {
		t.Fatal(err)
	}
	_ = required // pinned by collector metadata; here for caller readability
	return st, r, p, ru
}

// ----- Registry --------------------------------------------------------

func TestRegistryRegisterAndGet(t *testing.T) {
	reg := scan.NewRegistry()
	reg.Register(fixture.Name, fixture.New)
	f, err := reg.Get(fixture.Name)
	if err != nil {
		t.Fatal(err)
	}
	if f().Metadata().Name != fixture.Name {
		t.Fatalf("factory returned wrong collector")
	}
	if _, err := reg.Get("missing"); err == nil {
		t.Fatal("Get on missing must error")
	}
}

func TestRegistryRegisterEmptyNamePanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic")
		}
	}()
	scan.NewRegistry().Register("", fixture.New)
}

// ----- Runner ----------------------------------------------------------

func TestRunnerHappyPath(t *testing.T) {
	st, runner, p, ru := fixtureSetup(t, project.ModeAssessment,
		[]scope.Rule{{Pattern: "*.example.com", Kind: scope.KindLightActive}},
		scope.KindPassive, scope.KindPassive)
	ctx := context.Background()

	tx, err := runner.Execute(ctx, p.ID, ru.ID, fixture.New(), map[string]any{
		"targets":          []any{"a.example.com", "b.example.com"},
		"finding_title":    "exposed subdomains",
		"finding_severity": "medium",
	})
	if err != nil {
		t.Fatal(err)
	}
	if tx.Status != run.ToolStatusCompleted {
		t.Fatalf("status=%s, want completed (err_summary=%q)", tx.Status, tx.ErrorSummary)
	}
	if tx.EntitiesEmitted != 2 {
		t.Fatalf("entities_emitted=%d, want 2", tx.EntitiesEmitted)
	}
	if tx.FindingsEmitted != 1 {
		t.Fatalf("findings_emitted=%d, want 1", tx.FindingsEmitted)
	}
	if tx.EvidenceEmitted < 2 {
		t.Fatalf("evidence_emitted=%d, want >= 2", tx.EvidenceEmitted)
	}

	// Verify persistence.
	values, _ := st.Entities.ListValuesByKind(ctx, p.ID, entity.KindDomain)
	if len(values) != 2 {
		t.Fatalf("entities persisted=%d, want 2 (got %v)", len(values), values)
	}
	findings, _ := st.Findings.ListFindings(ctx, p.ID)
	if len(findings) != 1 || findings[0].Severity != finding.SeverityMedium {
		t.Fatalf("findings=%+v", findings)
	}
}

func TestRunnerScopeReachabilitySkipsOutOfScope(t *testing.T) {
	// Default passive, no rules; a collector that requires
	// light_active cannot run.
	st := memory.New()
	ctx := context.Background()
	p := &project.Project{Name: "P", DefaultScope: scope.KindPassive, Mode: project.ModeAssessment}
	_ = st.Projects.Save(ctx, p)
	ru := &run.Run{ProjectID: p.ID, Phase: workflow.PhaseOSINT, Status: run.StatusRunning}
	_ = st.Runs.Save(ctx, ru)

	pol, _ := scope.Compile(p.ID, p.DefaultScope, nil)
	runner, err := scan.NewRunner(scan.Deps{
		Runs: st.Runs, Entities: st.Entities, Findings: st.Findings, Scope: pol,
	}, nil, st.Audit)
	if err != nil {
		t.Fatal(err)
	}

	tx, err := runner.Execute(ctx, p.ID, ru.ID, &requireFullActiveCollector{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if tx.Status != run.ToolStatusSkippedOutOfScope {
		t.Fatalf("status=%s, want skipped_out_of_scope", tx.Status)
	}
	if !strings.Contains(tx.ErrorSummary, "full_active") {
		t.Fatalf("error_summary missing scope-kind hint: %q", tx.ErrorSummary)
	}
	// Audit row for the skip.
	rows, _ := st.Audit.ListByProject(ctx, p.ID)
	var sawSkip bool
	for _, r := range rows {
		if r.Action == "collector.skipped_out_of_scope" {
			sawSkip = true
		}
	}
	if !sawSkip {
		t.Fatalf("audit missing skipped_out_of_scope: %+v", rows)
	}
}

func TestRunnerPerTargetFilteringAndZeroEmissionDiagnostic(t *testing.T) {
	// Reachable at default (passive), but ALL targets are out of scope
	// because they don't match any rule and default is passive.
	// Collector emits no entities -> zero-emission diagnostic kicks in
	// since IsInScope rejected every probe.
	st, runner, p, ru := fixtureSetup(t, project.ModeAssessment,
		[]scope.Rule{{Pattern: "*.allowed.example", Kind: scope.KindLightActive}},
		scope.KindDeny, scope.KindLightActive)
	ctx := context.Background()
	_ = st

	// Fixture collector itself requires passive, so reachability passes
	// only when there's a non-deny rule. We added one above. The
	// targets don't match it, so IsInScope rejects them, but the
	// collector is allowed to start.
	tx, err := runner.Execute(ctx, p.ID, ru.ID, fixture.New(), map[string]any{
		"targets": []any{"bad1.test", "bad2.test"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if tx.Status != run.ToolStatusCompleted {
		t.Fatalf("status=%s err=%q", tx.Status, tx.ErrorSummary)
	}
	if tx.EntitiesEmitted != 0 {
		t.Fatalf("expected zero entities, got %d", tx.EntitiesEmitted)
	}
	if !strings.Contains(tx.ErrorSummary, "out of scope") {
		t.Fatalf("zero-emission diagnostic missing: %q", tx.ErrorSummary)
	}
}

func TestRunnerEntityDedup(t *testing.T) {
	st, runner, p, ru := fixtureSetup(t, project.ModeAssessment,
		[]scope.Rule{{Pattern: "*.example.com", Kind: scope.KindLightActive}},
		scope.KindPassive, scope.KindPassive)
	ctx := context.Background()

	// Two probes of the same target — dedup should produce 1 entity row.
	tx, err := runner.Execute(ctx, p.ID, ru.ID, fixture.New(), map[string]any{
		"targets": []any{"a.example.com", "A.EXAMPLE.COM"},
	})
	if err != nil {
		t.Fatal(err)
	}
	// EntitiesEmitted is a counter of emissions, not of unique rows.
	if tx.EntitiesEmitted != 2 {
		t.Fatalf("emissions=%d, want 2", tx.EntitiesEmitted)
	}
	// The persistence layer dedups on canonical value.
	values, _ := st.Entities.ListValuesByKind(ctx, p.ID, entity.KindDomain)
	if len(values) != 1 {
		t.Fatalf("persisted distinct domains=%d, want 1 (case-folded dedup): %v", len(values), values)
	}
}

func TestRunnerRedactsSecretParameters(t *testing.T) {
	_, runner, p, ru := fixtureSetup(t, project.ModeAssessment,
		[]scope.Rule{{Pattern: "*.example.com", Kind: scope.KindLightActive}},
		scope.KindPassive, scope.KindPassive)
	ctx := context.Background()
	tx, err := runner.Execute(ctx, p.ID, ru.ID, fixture.New(), map[string]any{
		"targets":         []any{"a.example.com"},
		"api_key":         "sekrit",
		"GITHUB_PASSWORD": "hunter2",
		"safe_param":      "ok",
	})
	if err != nil {
		t.Fatal(err)
	}
	if tx.Parameters["api_key"] != "***" || tx.Parameters["GITHUB_PASSWORD"] != "***" {
		t.Fatalf("secret-shaped params should be redacted: %+v", tx.Parameters)
	}
	if tx.Parameters["safe_param"] != "ok" {
		t.Fatalf("non-secret param should pass through: %+v", tx.Parameters)
	}
}

func TestRunnerCollectorErrorMapsToFailed(t *testing.T) {
	_, runner, p, ru := fixtureSetup(t, project.ModeAssessment,
		[]scope.Rule{{Pattern: "*.example.com", Kind: scope.KindLightActive}},
		scope.KindPassive, scope.KindPassive)
	tx, err := runner.Execute(context.Background(), p.ID, ru.ID,
		&erroringCollector{err: errors.New("boom")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if tx.Status != run.ToolStatusFailed {
		t.Fatalf("status=%s, want failed", tx.Status)
	}
	if !strings.Contains(tx.ErrorSummary, "boom") {
		t.Fatalf("error_summary missing message: %q", tx.ErrorSummary)
	}
}

func TestRunnerCollectorPanicMapsToFailedWithStack(t *testing.T) {
	_, runner, p, ru := fixtureSetup(t, project.ModeAssessment,
		[]scope.Rule{{Pattern: "*.example.com", Kind: scope.KindLightActive}},
		scope.KindPassive, scope.KindPassive)
	tx, err := runner.Execute(context.Background(), p.ID, ru.ID, &panickingCollector{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if tx.Status != run.ToolStatusFailed {
		t.Fatalf("status=%s, want failed", tx.Status)
	}
	if tx.ErrorDebug == "" {
		t.Fatal("error_debug should hold the recovery stack")
	}
}

func TestRunnerCounterFinalAudit(t *testing.T) {
	st, runner, p, ru := fixtureSetup(t, project.ModeAssessment,
		[]scope.Rule{{Pattern: "*.example.com", Kind: scope.KindLightActive}},
		scope.KindPassive, scope.KindPassive)
	ctx := context.Background()
	_, _ = runner.Execute(ctx, p.ID, ru.ID, fixture.New(), map[string]any{
		"targets":       []any{"a.example.com"},
		"finding_title": "x",
	})
	rows, _ := st.Audit.ListByProject(ctx, p.ID)
	var actions []string
	for _, r := range rows {
		actions = append(actions, r.Action)
	}
	// Newest-first. The runner emits start then finish.
	if len(actions) < 2 || actions[0] != "collector.finish" || actions[1] != "collector.start" {
		t.Fatalf("audit actions sequence wrong: %v", actions)
	}
	for _, r := range rows {
		if r.Action == "collector.finish" {
			if r.Detail["entities_emitted"] == nil {
				t.Fatalf("collector.finish detail missing counters: %+v", r.Detail)
			}
		}
	}
}

func TestNewRunnerRejectsMissingDeps(t *testing.T) {
	if _, err := scan.NewRunner(scan.Deps{}, nil, nil); err == nil {
		t.Fatal("expected error for empty Deps")
	}
}

func TestStoreArtifactStubbed(t *testing.T) {
	_, runner, p, ru := fixtureSetup(t, project.ModeAssessment,
		[]scope.Rule{{Pattern: "*.example.com", Kind: scope.KindLightActive}},
		scope.KindPassive, scope.KindPassive)
	tx, _ := runner.Execute(context.Background(), p.ID, ru.ID,
		&artifactCollector{}, nil)
	if tx.Status != run.ToolStatusFailed {
		t.Fatalf("status=%s, want failed (artifact not implemented)", tx.Status)
	}
}

// ----- helper test collectors -----------------------------------------

type requireFullActiveCollector struct{}

func (requireFullActiveCollector) Metadata() scan.Meta {
	return scan.Meta{Name: "needs_full_active", Phase: workflow.PhaseExposure, RequiredScope: scope.KindFullActive}
}
func (requireFullActiveCollector) Run(_ context.Context, _ scan.Context) error { return nil }

type erroringCollector struct{ err error }

func (erroringCollector) Metadata() scan.Meta {
	return scan.Meta{Name: "errs", Phase: workflow.PhaseOSINT, RequiredScope: scope.KindPassive}
}
func (c erroringCollector) Run(_ context.Context, _ scan.Context) error { return c.err }

type panickingCollector struct{}

func (panickingCollector) Metadata() scan.Meta {
	return scan.Meta{Name: "panics", Phase: workflow.PhaseOSINT, RequiredScope: scope.KindPassive}
}
func (panickingCollector) Run(_ context.Context, _ scan.Context) error {
	panic("intentional test panic")
}

type artifactCollector struct{}

func (artifactCollector) Metadata() scan.Meta {
	return scan.Meta{Name: "art", Phase: workflow.PhaseOSINT, RequiredScope: scope.KindPassive}
}
func (artifactCollector) Run(_ context.Context, cctx scan.Context) error {
	_, err := cctx.StoreArtifact([]byte("hello"), "x.bin", "application/octet-stream")
	return err
}
