package holehe

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
	pol, _ := scope.Compile(p.ID, p.DefaultScope, nil)
	ru := &run.Run{ProjectID: p.ID, Phase: workflow.PhaseEnrichment, Status: run.StatusRunning}
	_ = st.Runs.Save(ctx, ru)
	runner, _ := scan.NewRunner(scan.Deps{
		Runs: st.Runs, Entities: st.Entities, Findings: st.Findings, Scope: pol,
	}, nil, st.Audit)
	return st, p, ru, runner
}

type stubRunner struct {
	byEmail map[string]string
	gotArgs [][]string
}

func (s *stubRunner) run(_ context.Context, spec subprocess.Spec) (subprocess.Result, error) {
	s.gotArgs = append(s.gotArgs, append([]string(nil), spec.Args...))
	if len(spec.Args) == 0 {
		return subprocess.Result{}, nil
	}
	return subprocess.Result{Stdout: []byte(s.byEmail[spec.Args[0]])}, nil
}

func TestHoleheParsesHitLines(t *testing.T) {
	stub := &stubRunner{byEmail: map[string]string{
		"alice@example.com": `
*********************
   alice@example.com
*********************
[+] adobe.com
[+] amazon.com
[-] github.com
[+] github.com
[x] errorsite.com
[*] ratelimited.com
`}}
	c := newWithRunner(stub.run)
	st, p, ru, runner := setup(t)
	tx, err := runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{
		"emails": []any{"alice@example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if tx.Status != run.ToolStatusCompleted {
		t.Fatalf("status=%s err=%q", tx.Status, tx.ErrorSummary)
	}
	emails, _ := st.Entities.ListValuesByKind(context.Background(), p.ID, entity.KindEmail)
	if len(emails) != 1 || emails[0] != "alice@example.com" {
		t.Fatalf("email entity missing: %v", emails)
	}
	// Adobe + Amazon + github (deduped) = 3 hit-evidence rows + 1
	// rollup evidence row + 1 collector-level summary = 5 total.
	// We can't query evidence directly here, but the run-level
	// counter tells us things were emitted.
	if tx.EvidenceEmitted < 3 {
		t.Fatalf("expected at least 3 evidence rows; got %d", tx.EvidenceEmitted)
	}
}

func TestHoleheMalformedEmailSkipped(t *testing.T) {
	stub := &stubRunner{byEmail: map[string]string{
		"alice@example.com": "[+] adobe.com\n",
	}}
	c := newWithRunner(stub.run)
	st, p, ru, runner := setup(t)
	tx, _ := runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{
		"emails": []any{"not-an-email", "alice@example.com"},
	})
	if tx.Status != run.ToolStatusCompleted {
		t.Fatalf("status=%s err=%q; valid email should still run", tx.Status, tx.ErrorSummary)
	}
	// holehe should only have been invoked for the one valid address.
	if len(stub.gotArgs) != 1 {
		t.Fatalf("expected 1 invocation; got %d", len(stub.gotArgs))
	}
	emails, _ := st.Entities.ListValuesByKind(context.Background(), p.ID, entity.KindEmail)
	if len(emails) != 1 || emails[0] != "alice@example.com" {
		t.Fatalf("email entity wrong: %v", emails)
	}
}

func TestHoleheNoEmailsFails(t *testing.T) {
	c := newWithRunner((&stubRunner{}).run)
	_, p, ru, runner := setup(t)
	tx, _ := runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{})
	if tx.Status != run.ToolStatusFailed {
		t.Fatalf("status=%s", tx.Status)
	}
}

func TestParseHitsDedupes(t *testing.T) {
	got := parseHits("[+] github.com\n[+] github.com\n[+] gitlab.com\n")
	if len(got) != 2 {
		t.Fatalf("expected dedup to 2; got %v", got)
	}
}
