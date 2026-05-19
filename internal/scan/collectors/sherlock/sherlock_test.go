package sherlock

import (
	"context"
	"os"
	"path/filepath"
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
	rules := []scope.Rule{{Pattern: "*", Kind: scope.KindPassive}}
	_ = st.Scopes.Add(ctx, &scope.StoredRule{ProjectID: p.ID, Rule: rules[0]})
	pol, _ := scope.Compile(p.ID, p.DefaultScope, rules)
	ru := &run.Run{ProjectID: p.ID, Phase: workflow.PhaseOSINT, Status: run.StatusRunning}
	_ = st.Runs.Save(ctx, ru)
	runner, _ := scan.NewRunner(scan.Deps{
		Runs: st.Runs, Entities: st.Entities, Findings: st.Findings, Scope: pol,
	}, nil, st.Audit)
	return st, p, ru, runner
}

const sampleCSV = `name,url_user,exists,http_status
GitHub,https://github.com/alice,Claimed,200
Twitter,https://twitter.com/alice,Claimed,200
Reddit,https://reddit.com/u/alice,Available,404
LinkedIn,https://linkedin.com/in/alice,Claimed,200
`

func TestSherlockHappyPath(t *testing.T) {
	stub := func(_ context.Context, spec subprocess.Spec) (subprocess.Result, error) {
		var folder, username string
		for i, a := range spec.Args {
			if a == "--folderoutput" && i+1 < len(spec.Args) {
				folder = spec.Args[i+1]
			}
		}
		username = spec.Args[len(spec.Args)-1]
		if folder == "" || username == "" {
			t.Fatal("missing --folderoutput or positional username")
		}
		if err := os.WriteFile(filepath.Join(folder, username+".csv"), []byte(sampleCSV), 0o644); err != nil {
			t.Fatal(err)
		}
		return subprocess.Result{}, nil
	}
	c := newWithRunner(stub)
	st, p, ru, runner := setup(t)
	tx, _ := runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{
		"username": "alice",
	})
	if tx.Status != run.ToolStatusCompleted {
		t.Fatalf("status=%s err=%q", tx.Status, tx.ErrorSummary)
	}
	urls, _ := st.Entities.ListValuesByKind(context.Background(), p.ID, entity.KindURL)
	if len(urls) != 3 {
		t.Fatalf("urls=%v, want 3 (Claimed only)", urls)
	}
	people, _ := st.Entities.ListValuesByKind(context.Background(), p.ID, entity.KindPerson)
	if len(people) != 1 || people[0] != "alice" {
		t.Fatalf("people=%v", people)
	}
}

func TestSherlockRejectsInvalidUsername(t *testing.T) {
	c := newWithRunner(func(_ context.Context, _ subprocess.Spec) (subprocess.Result, error) {
		t.Fatal("should not invoke subprocess")
		return subprocess.Result{}, nil
	})
	_, p, ru, runner := setup(t)
	tx, _ := runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{
		"username": "alice smith", // space — rejected
	})
	if tx.Status != run.ToolStatusFailed {
		t.Fatalf("status=%s", tx.Status)
	}
}

func TestSherlockMissingUsername(t *testing.T) {
	c := newWithRunner(func(_ context.Context, _ subprocess.Spec) (subprocess.Result, error) {
		return subprocess.Result{}, nil
	})
	_, p, ru, runner := setup(t)
	tx, _ := runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{})
	if tx.Status != run.ToolStatusFailed {
		t.Fatalf("status=%s", tx.Status)
	}
}
