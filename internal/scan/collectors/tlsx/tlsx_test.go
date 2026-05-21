package tlsx

import (
	"context"
	"testing"

	"github.com/silvance/golantern/internal/entity"
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
	p := &project.Project{Name: "P", DefaultScope: scope.KindDeny, Mode: project.ModeAssessment}
	_ = st.Projects.Save(ctx, p)
	rules := []scope.Rule{
		{Pattern: "example.com", Kind: scope.KindPassive},
		{Pattern: "*.example.com", Kind: scope.KindPassive},
	}
	for _, r := range rules {
		_ = st.Scopes.Add(ctx, &scope.StoredRule{ProjectID: p.ID, Rule: r})
	}
	pol, _ := scope.Compile(p.ID, p.DefaultScope, rules)
	ru := &run.Run{ProjectID: p.ID, Phase: workflow.PhaseEnrichment, Status: run.StatusRunning}
	_ = st.Runs.Save(ctx, ru)
	runner, _ := scan.NewRunner(scan.Deps{
		Runs: st.Runs, Entities: st.Entities, Findings: st.Findings, Scope: pol,
	}, nil, st.Audit)
	return st, p, ru, runner
}

type stubRunner struct {
	stdout string
}

func (s *stubRunner) run(_ context.Context, spec subprocess.Spec) (subprocess.Result, error) {
	_ = spec
	return subprocess.Result{Stdout: []byte(s.stdout)}, nil
}

func TestTlsxExtractsSANs(t *testing.T) {
	stub := &stubRunner{stdout: `
{"host":"www.example.com","ip":"1.2.3.4","port":"443","subject_cn":"www.example.com","subject_an":["www.example.com","api.example.com","cdn.example.com","*.example.com","not-a-host"],"issuer_dn":"Let's Encrypt"}
`}
	c := newWithRunner(stub.run)
	st, p, ru, runner := setup(t)
	tx, err := runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{
		"targets": []any{"www.example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if tx.Status != run.ToolStatusCompleted {
		t.Fatalf("status=%s err=%q", tx.Status, tx.ErrorSummary)
	}
	values, _ := st.Entities.ListValuesByKind(context.Background(), p.ID, entity.KindSubdomain)
	have := map[string]bool{}
	for _, v := range values {
		have[v] = true
	}
	if !have["api.example.com"] || !have["cdn.example.com"] {
		t.Fatalf("missing extracted SAN subs: %v", values)
	}
	for _, bad := range []string{"*.example.com", "not-a-host"} {
		if have[bad] {
			t.Fatalf("unwanted value %q leaked: %v", bad, values)
		}
	}
}

func TestTlsxOutOfScopeSANsFiltered(t *testing.T) {
	stub := &stubRunner{stdout: `
{"host":"www.example.com","subject_cn":"www.example.com","subject_an":["api.example.com","secret.other-corp.net"]}
`}
	c := newWithRunner(stub.run)
	st, p, ru, runner := setup(t)
	_, _ = runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{
		"targets": []any{"www.example.com"},
	})
	values, _ := st.Entities.ListValuesByKind(context.Background(), p.ID, entity.KindSubdomain)
	have := map[string]bool{}
	for _, v := range values {
		have[v] = true
	}
	if have["secret.other-corp.net"] {
		t.Fatalf("out-of-scope SAN leaked: %v", values)
	}
	if !have["api.example.com"] {
		t.Fatalf("in-scope SAN missing: %v", values)
	}
}

func TestTlsxNoTargetsFails(t *testing.T) {
	c := newWithRunner((&stubRunner{}).run)
	_, p, ru, runner := setup(t)
	tx, _ := runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{})
	if tx.Status != run.ToolStatusFailed {
		t.Fatalf("status=%s", tx.Status)
	}
}
