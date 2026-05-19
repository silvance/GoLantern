package theharvester

import (
	"context"
	"os"
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
	ru := &run.Run{ProjectID: p.ID, Phase: workflow.PhaseOSINT, Status: run.StatusRunning}
	_ = st.Runs.Save(ctx, ru)
	runner, _ := scan.NewRunner(scan.Deps{
		Runs: st.Runs, Entities: st.Entities, Findings: st.Findings, Scope: pol,
	}, nil, st.Audit)
	return st, p, ru, runner
}

// stubRunner extracts the -f basename from the args, then writes a
// canned JSON file there before returning success — emulating what
// theHarvester does on disk.
func stubRunner(t *testing.T, body string) runnerFn {
	t.Helper()
	return func(_ context.Context, spec subprocess.Spec) (subprocess.Result, error) {
		var basename string
		for i, a := range spec.Args {
			if a == "-f" && i+1 < len(spec.Args) {
				basename = spec.Args[i+1]
			}
		}
		if basename == "" {
			t.Fatal("stubRunner: -f basename not found")
		}
		if err := os.WriteFile(basename+".json", []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return subprocess.Result{}, nil
	}
}

const sampleBody = `{
  "hosts": ["api.example.com", "www.example.com:1.2.3.4", "8.8.8.8", "out.of.scope.test"],
  "emails": ["alice@example.com", "bob@api.example.com", "stranger@elsewhere.com"],
  "people": ["Alice Smith", "Bob Jones"]
}`

func TestTheHarvesterHappyPath(t *testing.T) {
	c := newWithRunner(stubRunner(t, sampleBody))
	st, p, ru, runner := setup(t)
	_, err := runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{
		"domain": "example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	subs, _ := st.Entities.ListValuesByKind(context.Background(), p.ID, entity.KindSubdomain)
	if len(subs) != 2 {
		t.Fatalf("subdomains=%v, want 2 (api + www; bare IP + out-of-tree dropped)", subs)
	}
	emails, _ := st.Entities.ListValuesByKind(context.Background(), p.ID, entity.KindEmail)
	if len(emails) != 2 {
		t.Fatalf("emails=%v, want 2 (alice + bob; stranger dropped)", emails)
	}
	people, _ := st.Entities.ListValuesByKind(context.Background(), p.ID, entity.KindPerson)
	if len(people) != 2 {
		t.Fatalf("people=%v, want 2", people)
	}
}

func TestTheHarvesterMissingDomain(t *testing.T) {
	c := newWithRunner(stubRunner(t, "{}"))
	_, p, ru, runner := setup(t)
	tx, _ := runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{})
	if tx.Status != run.ToolStatusFailed {
		t.Fatalf("status=%s", tx.Status)
	}
}

func TestTheHarvesterMissingOutputFile(t *testing.T) {
	c := newWithRunner(func(_ context.Context, _ subprocess.Spec) (subprocess.Result, error) {
		// Don't write the file -> collector should error.
		return subprocess.Result{}, nil
	})
	_, p, ru, runner := setup(t)
	tx, _ := runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{
		"domain": "example.com",
	})
	if tx.Status != run.ToolStatusFailed {
		t.Fatalf("status=%s", tx.Status)
	}
}
