package testssl

import (
	"context"
	"os"
	"testing"

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
	ru := &run.Run{ProjectID: p.ID, Phase: workflow.PhaseExposure, Status: run.StatusRunning}
	_ = st.Runs.Save(ctx, ru)
	runner, _ := scan.NewRunner(scan.Deps{
		Runs: st.Runs, Entities: st.Entities, Findings: st.Findings, Scope: pol,
	}, nil, st.Audit)
	return st, p, ru, runner
}

const sampleEntries = `[
  {"id":"cert_expiration","finding":"expires in 2 days","severity":"HIGH"},
  {"id":"BREACH","finding":"vulnerable","severity":"CRITICAL"},
  {"id":"TLS_1_0","finding":"supported","severity":"LOW"},
  {"id":"cipher_list","finding":"info: 25 ciphers","severity":"INFO"}
]`

func TestTestSslMapsSeverities(t *testing.T) {
	stub := func(_ context.Context, spec subprocess.Spec) (subprocess.Result, error) {
		// Find the -jsonfile-pretty arg and write our canned body there.
		var jsonOut string
		for i, a := range spec.Args {
			if a == "--jsonfile-pretty" && i+1 < len(spec.Args) {
				jsonOut = spec.Args[i+1]
			}
		}
		if jsonOut == "" {
			t.Fatal("stub: --jsonfile-pretty not found")
		}
		if err := os.WriteFile(jsonOut, []byte(sampleEntries), 0o644); err != nil {
			t.Fatal(err)
		}
		return subprocess.Result{}, nil
	}
	c := newWithRunner(stub)
	st, p, ru, runner := setup(t)
	_, _ = runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{
		"targets":      []any{"https://api.example.com"},
		"min_severity": "medium", // suppresses LOW
	})
	findings, _ := st.Findings.ListFindings(context.Background(), p.ID)
	// HIGH + CRITICAL pass; LOW is below floor; INFO never a finding. -> 2 findings.
	if len(findings) != 2 {
		t.Fatalf("findings=%d, want 2: %+v", len(findings), findings)
	}
	bySev := map[finding.Severity]int{}
	for _, f := range findings {
		bySev[f.Severity]++
	}
	if bySev[finding.SeverityHigh] != 1 || bySev[finding.SeverityCritical] != 1 {
		t.Fatalf("severity counts: %+v", bySev)
	}
}

func TestTestSslNoTargetsFails(t *testing.T) {
	stub := func(_ context.Context, _ subprocess.Spec) (subprocess.Result, error) {
		return subprocess.Result{}, nil
	}
	c := newWithRunner(stub)
	_, p, ru, runner := setup(t)
	tx, _ := runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{})
	if tx.Status != run.ToolStatusFailed {
		t.Fatalf("status=%s", tx.Status)
	}
}
