package smtpuserenum

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
	p := &project.Project{Name: "P", DefaultScope: scope.KindLightActive, Mode: project.ModeAssessment}
	_ = st.Projects.Save(ctx, p)
	pol, _ := scope.Compile(p.ID, p.DefaultScope, nil)
	ru := &run.Run{ProjectID: p.ID, Phase: workflow.PhaseExposure, Status: run.StatusRunning}
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

func TestSmtpUserEnumExtractsHits(t *testing.T) {
	stub := &stubRunner{stdout: `
Starting smtp-user-enum v1.2
mail.example.com: admin exists
mail.example.com: root exists
mail.example.com: nosuch (no such user)
mail.example.com: backup exists
mail.example.com: admin exists
`}
	c := newWithRunner(stub.run)
	st, p, ru, runner := setup(t)
	tx, err := runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{
		"targets":   []any{"mail.example.com"},
		"usernames": []any{"admin", "root", "backup", "nosuch"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if tx.Status != run.ToolStatusCompleted {
		t.Fatalf("status=%s err=%q", tx.Status, tx.ErrorSummary)
	}
	emails, _ := st.Entities.ListValuesByKind(context.Background(), p.ID, entity.KindEmail)
	have := map[string]bool{}
	for _, e := range emails {
		have[e] = true
	}
	for _, want := range []string{"admin@mail.example.com", "root@mail.example.com", "backup@mail.example.com"} {
		if !have[want] {
			t.Errorf("missing %q: %v", want, emails)
		}
	}
	if have["nosuch@mail.example.com"] {
		t.Errorf("non-existent user leaked: %v", emails)
	}
	fs, _ := st.Findings.ListFindings(context.Background(), p.ID)
	if len(fs) != 1 {
		t.Fatalf("expected 1 finding; got %d", len(fs))
	}
}

func TestSmtpUserEnumRequiresUsernames(t *testing.T) {
	c := newWithRunner((&stubRunner{}).run)
	_, p, ru, runner := setup(t)
	tx, _ := runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{
		"targets": []any{"mail.example.com"},
	})
	if tx.Status != run.ToolStatusFailed {
		t.Fatalf("status=%s; missing usernames should fail", tx.Status)
	}
}

func TestSmtpUserEnumRejectsBadUsernames(t *testing.T) {
	c := newWithRunner((&stubRunner{}).run)
	_, p, ru, runner := setup(t)
	tx, _ := runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{
		"targets":   []any{"mail.example.com"},
		"usernames": []any{"a; cat /etc/passwd", "$()"},
	})
	if tx.Status != run.ToolStatusFailed {
		t.Fatalf("status=%s; all-invalid usernames should fail", tx.Status)
	}
}

func TestParseHitsDedupes(t *testing.T) {
	out := parseHits("mail: foo exists\nmail: foo exists\nmail: bar exists\n")
	if len(out) != 2 {
		t.Fatalf("expected 2; got %v", out)
	}
}
