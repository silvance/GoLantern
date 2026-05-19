package historicalurls

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
	rules := []scope.Rule{{Pattern: "example.com", Kind: scope.KindPassive}}
	_ = st.Scopes.Add(ctx, &scope.StoredRule{ProjectID: p.ID, Rule: rules[0]})
	pol, _ := scope.Compile(p.ID, p.DefaultScope, rules)
	ru := &run.Run{ProjectID: p.ID, Phase: workflow.PhaseAssetDiscovery, Status: run.StatusRunning}
	_ = st.Runs.Save(ctx, ru)
	runner, _ := scan.NewRunner(scan.Deps{
		Runs: st.Runs, Entities: st.Entities, Findings: st.Findings, Scope: pol,
	}, nil, st.Audit)
	return st, p, ru, runner
}

func TestHistoricalUrlsHappyPath(t *testing.T) {
	out := `https://api.example.com/old
https://www.example.com/foo
http://other.test/leak
https://api.example.com/old
not-a-url
`
	stub := func(_ context.Context, _ subprocess.Spec) (subprocess.Result, error) {
		return subprocess.Result{Stdout: []byte(out)}, nil
	}
	c := newWithRunner(stub)
	st, p, ru, runner := setup(t)
	// Seed a known SUBDOMAIN so the CHILD_OF wiring exercises.
	_, _ = st.Entities.Upsert(context.Background(), p.ID, entity.KindSubdomain, "api.example.com", nil)
	tx, err := runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{
		"domains": []any{"example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if tx.Status != run.ToolStatusCompleted {
		t.Fatalf("status=%s err=%q", tx.Status, tx.ErrorSummary)
	}
	urls, _ := st.Entities.ListValuesByKind(context.Background(), p.ID, entity.KindURL)
	// Expect 2 unique in-tree URLs (api + www); other.test dropped;
	// non-URL line dropped; duplicate deduped.
	if len(urls) != 2 {
		t.Fatalf("URLs=%v, want 2", urls)
	}
	rels, _ := st.Entities.ListRelationsByProject(context.Background(), p.ID)
	var childOf int
	for _, r := range rels {
		if r.Kind == entity.RelChildOf {
			childOf++
		}
	}
	if childOf != 1 {
		t.Fatalf("CHILD_OF relations=%d, want 1 (api hit)", childOf)
	}
}

func TestHistoricalUrlsRejectsUnknownBinary(t *testing.T) {
	stub := func(_ context.Context, _ subprocess.Spec) (subprocess.Result, error) { return subprocess.Result{}, nil }
	c := newWithRunner(stub)
	_, p, ru, runner := setup(t)
	tx, _ := runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{
		"binary":  "evil-binary",
		"domains": []any{"example.com"},
	})
	if tx.Status != run.ToolStatusFailed {
		t.Fatalf("status=%s", tx.Status)
	}
}

func TestHistoricalUrlsMaxDomainsCap(t *testing.T) {
	calls := 0
	stub := func(_ context.Context, _ subprocess.Spec) (subprocess.Result, error) {
		calls++
		return subprocess.Result{Stdout: []byte{}}, nil
	}
	c := newWithRunner(stub)
	st := memory.New()
	ctx := context.Background()
	p := &project.Project{Name: "P", DefaultScope: scope.KindPassive, Mode: project.ModeAssessment}
	_ = st.Projects.Save(ctx, p)
	rule := scope.Rule{Pattern: "*.test", Kind: scope.KindPassive}
	_ = st.Scopes.Add(ctx, &scope.StoredRule{ProjectID: p.ID, Rule: rule})
	pol, _ := scope.Compile(p.ID, p.DefaultScope, []scope.Rule{rule})
	ru := &run.Run{ProjectID: p.ID, Phase: workflow.PhaseAssetDiscovery, Status: run.StatusRunning}
	_ = st.Runs.Save(ctx, ru)
	runner, _ := scan.NewRunner(scan.Deps{
		Runs: st.Runs, Entities: st.Entities, Findings: st.Findings, Scope: pol,
	}, nil, st.Audit)
	_, _ = runner.Execute(ctx, p.ID, ru.ID, c, map[string]any{
		"domains":     []any{"a.test", "b.test", "c.test", "d.test"},
		"max_domains": 2,
	})
	if calls != 2 {
		t.Fatalf("calls=%d, want 2 (max_domains cap)", calls)
	}
}
