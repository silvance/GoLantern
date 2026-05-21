package whatweb

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
	p := &project.Project{Name: "P", DefaultScope: scope.KindPassive, Mode: project.ModeAssessment}
	_ = st.Projects.Save(ctx, p)
	rules := []scope.Rule{{Pattern: "*.example.com", Kind: scope.KindLightActive}, {Pattern: "example.com", Kind: scope.KindLightActive}}
	for _, r := range rules {
		_ = st.Scopes.Add(ctx, &scope.StoredRule{ProjectID: p.ID, Rule: r})
	}
	pol, _ := scope.Compile(p.ID, p.DefaultScope, rules)
	ru := &run.Run{ProjectID: p.ID, Phase: workflow.PhaseValidation, Status: run.StatusRunning}
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

func TestWhatwebParsesPlugins(t *testing.T) {
	// One JSON object per line — whatweb --log-json-verbose default.
	stub := &stubRunner{stdout: `
{"target":"https://www.example.com","http_status":200,"plugins":{"nginx":{"version":["1.18.0"]},"PHP":{"version":["7.4.3"]},"WordPress":{"version":["6.4.2"]},"HTML5":{}}}
{"target":"https://out-of-scope.test","http_status":200,"plugins":{"nginx":{"version":["1.0"]}}}
`}
	c := newWithRunner(stub.run)
	st, p, ru, runner := setup(t)
	tx, err := runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{
		"targets": []any{"https://www.example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if tx.Status != run.ToolStatusCompleted {
		t.Fatalf("status=%s err=%q", tx.Status, tx.ErrorSummary)
	}
	techs, _ := st.Entities.ListValuesByKind(context.Background(), p.ID, entity.KindTechnology)
	have := map[string]bool{}
	for _, v := range techs {
		have[v] = true
	}
	for _, want := range []string{"nginx/1.18.0", "PHP/7.4.3", "WordPress/6.4.2", "HTML5"} {
		if !have[want] {
			t.Errorf("missing tech %q: %v", want, techs)
		}
	}
	if have["nginx/1.0"] {
		t.Errorf("out-of-scope tech leaked: %v", techs)
	}
}

func TestWhatwebArrayShape(t *testing.T) {
	stub := &stubRunner{stdout: `[
		{"target":"https://www.example.com","plugins":{"nginx":{"version":["1.18.0"]}}}
	]`}
	c := newWithRunner(stub.run)
	st, p, ru, runner := setup(t)
	_, _ = runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{
		"targets": []any{"https://www.example.com"},
	})
	techs, _ := st.Entities.ListValuesByKind(context.Background(), p.ID, entity.KindTechnology)
	if len(techs) != 1 || techs[0] != "nginx/1.18.0" {
		t.Fatalf("array shape not parsed: %v", techs)
	}
}

func TestWhatwebNoTargetsFails(t *testing.T) {
	c := newWithRunner((&stubRunner{}).run)
	_, p, ru, runner := setup(t)
	tx, _ := runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{})
	if tx.Status != run.ToolStatusFailed {
		t.Fatalf("status=%s", tx.Status)
	}
}
