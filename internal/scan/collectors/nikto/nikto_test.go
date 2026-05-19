package nikto

import (
	"context"
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

const sampleReport = `{
  "vulnerabilities":[
    {"id":"1","msg":"/.git/HEAD: Git repository exposed","uri":"/.git/HEAD"},
    {"id":"2","msg":"OpenSSL version 1.0.1 outdated"},
    {"id":"3","msg":"Apache server signature shown"}
  ]
}`

func TestNiktoSeverityHeuristic(t *testing.T) {
	stub := func(_ context.Context, _ subprocess.Spec) (subprocess.Result, error) {
		return subprocess.Result{Stdout: []byte(sampleReport)}, nil
	}
	c := newWithRunner(stub)
	st, p, ru, runner := setup(t)
	_, _ = runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{
		"targets": []any{"https://www.example.com"},
	})
	findings, _ := st.Findings.ListFindings(context.Background(), p.ID)
	if len(findings) != 3 {
		t.Fatalf("findings=%d", len(findings))
	}
	bySev := map[finding.Severity]int{}
	for _, f := range findings {
		bySev[f.Severity]++
	}
	if bySev[finding.SeverityHigh] != 1 || bySev[finding.SeverityMedium] != 1 || bySev[finding.SeverityLow] != 1 {
		t.Fatalf("severity counts wrong: %+v", bySev)
	}
}

func TestNiktoNoTargets(t *testing.T) {
	stub := func(_ context.Context, _ subprocess.Spec) (subprocess.Result, error) { return subprocess.Result{}, nil }
	c := newWithRunner(stub)
	_, p, ru, runner := setup(t)
	tx, _ := runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{})
	if tx.Status != run.ToolStatusFailed {
		t.Fatalf("status=%s", tx.Status)
	}
}

func TestClassifySeverity(t *testing.T) {
	cases := []struct {
		msg  string
		want finding.Severity
	}{
		{"SQL injection in id param", finding.SeverityHigh},
		{"/.git/HEAD found", finding.SeverityHigh},
		{"Server is outdated", finding.SeverityMedium},
		{"Server signature exposed", finding.SeverityMedium},
		{"Just an info message", finding.SeverityLow},
	}
	for _, c := range cases {
		if got := classifySeverity(c.msg); got != c.want {
			t.Errorf("classifySeverity(%q)=%s, want %s", c.msg, got, c.want)
		}
	}
}
