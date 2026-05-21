package naabu

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
	rules := []scope.Rule{{Pattern: "host.example.com", Kind: scope.KindLightActive}}
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
	stdout  string
	stdin   []byte
	gotArgs []string
}

func (s *stubRunner) run(_ context.Context, spec subprocess.Spec) (subprocess.Result, error) {
	s.gotArgs = append([]string(nil), spec.Args...)
	s.stdin = append([]byte(nil), spec.Stdin...)
	return subprocess.Result{Stdout: []byte(s.stdout)}, nil
}

func TestNaabuHappyPath(t *testing.T) {
	stub := &stubRunner{stdout: `
{"host":"host.example.com","ip":"1.2.3.4","port":443,"protocol":"tcp","tls":true}
{"host":"host.example.com","ip":"1.2.3.4","port":80,"protocol":"tcp"}
{"host":"out-of-scope.test","ip":"5.6.7.8","port":22}
`}
	c := newWithRunner(stub.run)
	st, p, ru, runner := setup(t)
	tx, err := runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{
		"targets": []any{"host.example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if tx.Status != run.ToolStatusCompleted {
		t.Fatalf("status=%s err=%q", tx.Status, tx.ErrorSummary)
	}
	values, _ := st.Entities.ListValuesByKind(context.Background(), p.ID, entity.KindService)
	have := map[string]bool{}
	for _, v := range values {
		have[v] = true
	}
	if !have["host.example.com:443/tls"] {
		t.Fatalf("missing 443 service: %v", values)
	}
	if !have["host.example.com:80/open"] {
		t.Fatalf("missing 80 service: %v", values)
	}
	// Out-of-scope rows in naabu output get dropped by the per-row
	// IsInScope recheck — defense in depth against misconfigured runs.
	if have["out-of-scope.test:22/open"] {
		t.Fatalf("out-of-scope row leaked: %v", values)
	}
}

func TestNaabuPortsTop1000(t *testing.T) {
	stub := &stubRunner{}
	c := newWithRunner(stub.run)
	_, p, ru, runner := setup(t)
	_, _ = runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{
		"targets": []any{"host.example.com"},
		"ports":   "top-1000",
	})
	got := strings.Join(stub.gotArgs, " ")
	if !strings.Contains(got, "-top-ports 1000") {
		t.Fatalf("expected -top-ports 1000; got %v", stub.gotArgs)
	}
}

func TestNaabuStdinTargets(t *testing.T) {
	stub := &stubRunner{}
	c := newWithRunner(stub.run)
	_, p, ru, runner := setup(t)
	_, _ = runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{
		"targets": []any{"host.example.com"},
	})
	if !strings.Contains(string(stub.stdin), "host.example.com") {
		t.Fatalf("expected target on stdin; got %q", stub.stdin)
	}
}

func TestNaabuNoTargetsFails(t *testing.T) {
	c := newWithRunner((&stubRunner{}).run)
	_, p, ru, runner := setup(t)
	tx, _ := runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{})
	if tx.Status != run.ToolStatusFailed {
		t.Fatalf("status=%s", tx.Status)
	}
}
