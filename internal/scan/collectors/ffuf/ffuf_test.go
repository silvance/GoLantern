package ffuf

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

const sampleReport = `{
  "results": [
    {"url":"https://www.example.com/admin","status":200,"length":1024,"words":42},
    {"url":"https://www.example.com/api","status":401,"length":12,"words":1}
  ]
}`

func TestFfufHappyPath(t *testing.T) {
	stub := func(_ context.Context, spec subprocess.Spec) (subprocess.Result, error) {
		if !contains(spec.Args, "-u") {
			t.Errorf("missing -u")
		}
		return subprocess.Result{Stdout: []byte(sampleReport)}, nil
	}
	c := newWithRunner(stub)
	st, p, ru, runner := setup(t)
	tx, err := runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{
		"targets":  []any{"https://www.example.com/FUZZ"},
		"wordlist": "/tmp/wl.txt",
	})
	if err != nil {
		t.Fatal(err)
	}
	if tx.Status != run.ToolStatusCompleted {
		t.Fatalf("status=%s err=%q", tx.Status, tx.ErrorSummary)
	}
	urls, _ := st.Entities.ListValuesByKind(context.Background(), p.ID, entity.KindURL)
	if len(urls) != 2 {
		t.Fatalf("URLs=%v, want 2", urls)
	}
}

func TestFfufAutoAppendsFUZZ(t *testing.T) {
	var got string
	stub := func(_ context.Context, spec subprocess.Spec) (subprocess.Result, error) {
		for i, a := range spec.Args {
			if a == "-u" && i+1 < len(spec.Args) {
				got = spec.Args[i+1]
			}
		}
		return subprocess.Result{Stdout: []byte(`{"results":[]}`)}, nil
	}
	c := newWithRunner(stub)
	_, p, ru, runner := setup(t)
	_, _ = runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{
		"targets":  []any{"https://www.example.com"}, // no FUZZ
		"wordlist": "/tmp/wl.txt",
	})
	if got != "https://www.example.com/FUZZ" {
		t.Fatalf("auto-append wrong: %q", got)
	}
}

func TestFfufExtensionsForwarded(t *testing.T) {
	var gotExts []string
	stub := func(_ context.Context, spec subprocess.Spec) (subprocess.Result, error) {
		for i, a := range spec.Args {
			if a == "-e" && i+1 < len(spec.Args) {
				gotExts = append(gotExts, spec.Args[i+1])
			}
		}
		return subprocess.Result{Stdout: []byte(`{"results":[]}`)}, nil
	}
	c := newWithRunner(stub)
	_, p, ru, runner := setup(t)
	_, _ = runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{
		"targets":    []any{"https://www.example.com/FUZZ"},
		"wordlist":   "/tmp/wl.txt",
		"extensions": []any{"php", ".bak", "old"},
	})
	want := []string{".php", ".bak", ".old"}
	if strings.Join(gotExts, ",") != strings.Join(want, ",") {
		t.Fatalf("extensions=%v, want %v", gotExts, want)
	}
}

func TestFfufNoTargetsFails(t *testing.T) {
	stub := func(_ context.Context, _ subprocess.Spec) (subprocess.Result, error) {
		t.Fatal("should not run")
		return subprocess.Result{}, nil
	}
	c := newWithRunner(stub)
	_, p, ru, runner := setup(t)
	tx, _ := runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{
		"wordlist": "/tmp/wl.txt",
	})
	if tx.Status != run.ToolStatusFailed {
		t.Fatalf("status=%s", tx.Status)
	}
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}
