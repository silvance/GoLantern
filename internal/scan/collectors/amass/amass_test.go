package amass

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
	p := &project.Project{Name: "P", DefaultScope: scope.KindPassive, Mode: project.ModeAssessment}
	_ = st.Projects.Save(ctx, p)
	rules := []scope.Rule{{Pattern: "example.com", Kind: scope.KindPassive}}
	for _, r := range rules {
		_ = st.Scopes.Add(ctx, &scope.StoredRule{ProjectID: p.ID, Rule: r})
	}
	pol, _ := scope.Compile(p.ID, p.DefaultScope, rules)
	ru := &run.Run{ProjectID: p.ID, Phase: workflow.PhaseAssetDiscovery, Status: run.StatusRunning}
	_ = st.Runs.Save(ctx, ru)
	runner, _ := scan.NewRunner(scan.Deps{
		Runs: st.Runs, Entities: st.Entities, Findings: st.Findings, Scope: pol,
	}, nil, st.Audit)
	return st, p, ru, runner
}

type stubRunner struct {
	byDomain map[string]string
	gotArgs  [][]string
}

func (s *stubRunner) run(_ context.Context, spec subprocess.Spec) (subprocess.Result, error) {
	s.gotArgs = append(s.gotArgs, append([]string(nil), spec.Args...))
	var domain string
	for i, a := range spec.Args {
		if a == "-d" && i+1 < len(spec.Args) {
			domain = spec.Args[i+1]
		}
	}
	return subprocess.Result{Stdout: []byte(s.byDomain[domain])}, nil
}

func TestAmassHappyPath(t *testing.T) {
	stub := &stubRunner{byDomain: map[string]string{
		"example.com": "mail.example.com\napi.example.com\nout-of-tree.test\nmail.example.com",
	}}
	c := newWithRunner(stub.run)
	st, p, ru, runner := setup(t)
	tx, err := runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{
		"domains": []any{"example.com"},
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
	if !have["mail.example.com"] || !have["api.example.com"] {
		t.Fatalf("missing expected subs: %v", values)
	}
	if have["out-of-tree.test"] {
		t.Fatalf("out-of-tree leak: %v", values)
	}
	// Dedup: mail.example.com appears twice in output, should only land once.
	count := 0
	for _, v := range values {
		if v == "mail.example.com" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("dedup failed: %d copies of mail.example.com", count)
	}
}

func TestAmassPassiveByDefault(t *testing.T) {
	stub := &stubRunner{byDomain: map[string]string{"example.com": ""}}
	c := newWithRunner(stub.run)
	_, p, ru, runner := setup(t)
	_, _ = runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{
		"domains": []any{"example.com"},
	})
	got := strings.Join(stub.gotArgs[0], " ")
	if !strings.Contains(got, "-passive") {
		t.Fatalf("expected -passive flag by default; got %v", stub.gotArgs[0])
	}
	if strings.Contains(got, "-active") {
		t.Fatalf("active flag should not be set by default: %v", stub.gotArgs[0])
	}
}

func TestAmassActiveFlag(t *testing.T) {
	stub := &stubRunner{byDomain: map[string]string{"example.com": ""}}
	c := newWithRunner(stub.run)
	_, p, ru, runner := setup(t)
	_, _ = runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{
		"domains": []any{"example.com"},
		"active":  true,
	})
	got := strings.Join(stub.gotArgs[0], " ")
	if !strings.Contains(got, "-active") {
		t.Fatalf("expected -active flag; got %v", stub.gotArgs[0])
	}
}

func TestAmassNoDomainsFails(t *testing.T) {
	c := newWithRunner((&stubRunner{}).run)
	_, p, ru, runner := setup(t)
	tx, _ := runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{})
	if tx.Status != run.ToolStatusFailed {
		t.Fatalf("status=%s", tx.Status)
	}
}
