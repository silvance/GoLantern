package dnsx

import (
	"context"
	"testing"

	"github.com/silvance/golantern/internal/entity"
	"github.com/silvance/golantern/internal/finding"
	"github.com/silvance/golantern/internal/project"
	"github.com/silvance/golantern/internal/run"
	"github.com/silvance/golantern/internal/scan"
	"github.com/silvance/golantern/internal/scope"
	"github.com/silvance/golantern/internal/store/memory"
	"github.com/silvance/golantern/internal/subprocess"
	"github.com/silvance/golantern/internal/workflow"
)

func setup(t *testing.T) (*memory.Store, *project.Project, *run.Run, *scan.Runner) {
	t.Helper()
	st := memory.New()
	ctx := context.Background()
	p := &project.Project{Name: "P", DefaultScope: scope.KindPassive, Mode: project.ModeAssessment}
	_ = st.Projects.Save(ctx, p)
	rules := []scope.Rule{{Pattern: "*.example.com", Kind: scope.KindLightActive}}
	_ = st.Scopes.Add(ctx, &scope.StoredRule{ProjectID: p.ID, Rule: rules[0]})
	pol, _ := scope.Compile(p.ID, p.DefaultScope, rules)
	ru := &run.Run{ProjectID: p.ID, Phase: workflow.PhaseValidation, Status: run.StatusRunning}
	_ = st.Runs.Save(ctx, ru)
	runner, _ := scan.NewRunner(scan.Deps{
		Runs: st.Runs, Entities: st.Entities, Findings: st.Findings, Scope: pol,
	}, nil, st.Audit)
	return st, p, ru, runner
}

func TestDnsxResolvesAndDetectsDangling(t *testing.T) {
	// Three names: one resolves, one is dangling, one is missing.
	stdout := `{"host":"alive.example.com","a":["10.0.0.1"],"aaaa":["::1"]}
{"host":"dangling.example.com","cname":["target.elsewhere.com"]}
{"host":"chained.example.com","a":["10.0.0.2"],"cname":["other.example.com"]}
`
	stub := func(_ context.Context, _ subprocess.Spec) (subprocess.Result, error) {
		return subprocess.Result{Stdout: []byte(stdout)}, nil
	}
	c := newWithRunner(stub)
	st, p, ru, runner := setup(t)
	tx, err := runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{
		"names": []any{"alive.example.com", "dangling.example.com", "chained.example.com", "missing.example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if tx.Status != run.ToolStatusCompleted {
		t.Fatalf("status=%s err=%q", tx.Status, tx.ErrorSummary)
	}
	// IP entities: 10.0.0.1, 10.0.0.2, ::1 = 3.
	ips, _ := st.Entities.ListValuesByKind(context.Background(), p.ID, entity.KindIP)
	if len(ips) != 3 {
		t.Fatalf("IPs=%v, want 3", ips)
	}
	// One MEDIUM finding for the dangling CNAME.
	findings, _ := st.Findings.ListFindings(context.Background(), p.ID)
	if len(findings) != 1 || findings[0].Severity != finding.SeverityMedium {
		t.Fatalf("findings=%+v", findings)
	}
}

func TestDnsxNoNamesIsSilentSuccess(t *testing.T) {
	stub := func(_ context.Context, _ subprocess.Spec) (subprocess.Result, error) {
		t.Fatal("subprocess should not be called")
		return subprocess.Result{}, nil
	}
	c := newWithRunner(stub)
	_, p, ru, runner := setup(t)
	tx, err := runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	if tx.Status != run.ToolStatusCompleted {
		t.Fatalf("status=%s", tx.Status)
	}
}
