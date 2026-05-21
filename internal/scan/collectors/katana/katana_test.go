package katana

import (
	"context"
	"strings"
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
	p := &project.Project{Name: "P", DefaultScope: scope.KindPassive, Mode: project.ModeBugBounty}
	_ = st.Projects.Save(ctx, p)
	rules := []scope.Rule{{Pattern: "*.example.com", Kind: scope.KindFullActive}, {Pattern: "example.com", Kind: scope.KindFullActive}}
	for _, r := range rules {
		_ = st.Scopes.Add(ctx, &scope.StoredRule{ProjectID: p.ID, Rule: r})
	}
	pol, _ := scope.Compile(p.ID, p.DefaultScope, rules)
	ru := &run.Run{ProjectID: p.ID, Phase: workflow.PhaseExposure, Status: run.StatusRunning}
	_ = st.Runs.Save(ctx, ru)
	runner, _ := scan.NewRunner(scan.Deps{
		Runs: st.Runs, Entities: st.Entities, Findings: st.Findings, Scope: pol,
	}, nil, st.Audit)
	return st, p, ru, runner
}

type stubRunner struct {
	stdout  string
	gotArgs []string
}

func (s *stubRunner) run(_ context.Context, spec subprocess.Spec) (subprocess.Result, error) {
	s.gotArgs = append([]string(nil), spec.Args...)
	return subprocess.Result{Stdout: []byte(s.stdout)}, nil
}

func TestKatanaModernShape(t *testing.T) {
	stub := &stubRunner{stdout: `
{"endpoint":"https://example.com/foo","method":"GET"}
{"endpoint":"https://example.com/bar","method":"POST","response":{"status_code":200}}
{"endpoint":"https://out-of-scope.test/x","method":"GET"}
`}
	c := newWithRunner(stub.run)
	st, p, ru, runner := setup(t)
	tx, err := runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{
		"targets": []any{"https://example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if tx.Status != run.ToolStatusCompleted {
		t.Fatalf("status=%s err=%q", tx.Status, tx.ErrorSummary)
	}
	values, _ := st.Entities.ListValuesByKind(context.Background(), p.ID, entity.KindURL)
	have := map[string]bool{}
	for _, v := range values {
		have[v] = true
	}
	if !have["https://example.com/foo"] || !have["https://example.com/bar"] {
		t.Fatalf("missing expected URLs: %v", values)
	}
	if have["https://out-of-scope.test/x"] {
		t.Fatalf("out-of-scope URL leaked: %v", values)
	}
}

func TestKatanaLegacyNestedShape(t *testing.T) {
	stub := &stubRunner{stdout: `
{"request":{"endpoint":"https://example.com/api/v1","method":"GET"},"response":{"status_code":200}}
`}
	c := newWithRunner(stub.run)
	st, p, ru, runner := setup(t)
	_, _ = runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{
		"targets": []any{"https://example.com"},
	})
	values, _ := st.Entities.ListValuesByKind(context.Background(), p.ID, entity.KindURL)
	have := map[string]bool{}
	for _, v := range values {
		have[v] = true
	}
	if !have["https://example.com/api/v1"] {
		t.Fatalf("legacy shape not parsed: %v", values)
	}
}

func TestKatanaJSCrawlFlag(t *testing.T) {
	stub := &stubRunner{}
	c := newWithRunner(stub.run)
	_, p, ru, runner := setup(t)
	_, _ = runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{
		"targets":  []any{"https://example.com"},
		"js_crawl": false,
	})
	got := strings.Join(stub.gotArgs, " ")
	if strings.Contains(got, "-jc") {
		t.Fatalf("expected no -jc when js_crawl=false; got %v", stub.gotArgs)
	}
}

func TestKatanaNoTargetsFails(t *testing.T) {
	c := newWithRunner((&stubRunner{}).run)
	_, p, ru, runner := setup(t)
	tx, _ := runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{})
	if tx.Status != run.ToolStatusFailed {
		t.Fatalf("status=%s", tx.Status)
	}
}
