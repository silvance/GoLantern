package john

import (
	"context"
	"strings"
	"testing"

	"github.com/silvance/golantern/internal/finding"
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
	p := &project.Project{Name: "P", DefaultScope: scope.KindPassive, Mode: project.ModeCTF}
	_ = st.Projects.Save(ctx, p)
	pol, _ := scope.Compile(p.ID, p.DefaultScope, nil)
	ru := &run.Run{ProjectID: p.ID, Phase: workflow.PhaseExposure, Status: run.StatusRunning}
	_ = st.Runs.Save(ctx, ru)
	runner, _ := scan.NewRunner(scan.Deps{
		Runs: st.Runs, Entities: st.Entities, Findings: st.Findings, Scope: pol,
	}, nil, st.Audit)
	return st, p, ru, runner
}

// stubRunner emulates john. Two invocations expected: the crack
// pass (which produces nothing) and --show (which returns the
// cracked pairs from the pot file).
type stubRunner struct {
	showOutput string
	gotArgs    [][]string
}

func (s *stubRunner) run(_ context.Context, spec subprocess.Spec) (subprocess.Result, error) {
	s.gotArgs = append(s.gotArgs, append([]string(nil), spec.Args...))
	for _, a := range spec.Args {
		if a == "--show" {
			return subprocess.Result{Stdout: []byte(s.showOutput)}, nil
		}
	}
	// Crack pass — return nothing, success.
	return subprocess.Result{}, nil
}

func TestJohnEmitsCrackedFindings(t *testing.T) {
	stub := &stubRunner{showOutput: `alice:Summer2024!:1001:1001:Alice User:/home/alice:/bin/bash
bob:hunter2:1002:1002::/home/bob:/bin/bash

2 password hashes cracked, 0 left
`}
	c := newWithRunner(stub.run)
	st, p, ru, runner := setup(t)
	tx, err := runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{
		"hashes": []any{
			"alice:$6$salt$abc123...",
			"bob:$6$salt$def456...",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if tx.Status != run.ToolStatusCompleted {
		t.Fatalf("status=%s err=%q", tx.Status, tx.ErrorSummary)
	}
	fs, _ := st.Findings.ListFindings(context.Background(), p.ID)
	if len(fs) != 2 {
		t.Fatalf("expected 2 findings; got %d", len(fs))
	}
	have := map[string]string{}
	for _, f := range fs {
		u, _ := f.Attributes["username"].(string)
		pw, _ := f.Attributes["password"].(string)
		have[u] = pw
	}
	if have["alice"] != "Summer2024!" {
		t.Fatalf("alice password lost: %v", have)
	}
	if have["bob"] != "hunter2" {
		t.Fatalf("bob password lost: %v", have)
	}
	for _, f := range fs {
		if f.Severity != finding.SeverityHigh {
			t.Fatalf("cracked credential should be High; got %s", f.Severity)
		}
	}
}

func TestJohnWritesHashesAndRunsTwice(t *testing.T) {
	stub := &stubRunner{}
	c := newWithRunner(stub.run)
	_, p, ru, runner := setup(t)
	_, _ = runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{
		"hashes": []any{"alice:$NT$abc"},
		"format": "nt",
	})
	if len(stub.gotArgs) != 2 {
		t.Fatalf("expected 2 john invocations (crack + show); got %d", len(stub.gotArgs))
	}
	// First call should NOT contain --show; second call SHOULD.
	if hasArg(stub.gotArgs[0], "--show") {
		t.Fatalf("first call should be crack, not --show: %v", stub.gotArgs[0])
	}
	if !hasArg(stub.gotArgs[1], "--show") {
		t.Fatalf("second call should be --show: %v", stub.gotArgs[1])
	}
	// Both calls should pass the format flag through.
	for i, args := range stub.gotArgs {
		if !hasArg(args, "--format=nt") {
			t.Fatalf("call %d missing --format=nt: %v", i, args)
		}
	}
}

func TestJohnMissingHashesFails(t *testing.T) {
	c := newWithRunner((&stubRunner{}).run)
	_, p, ru, runner := setup(t)
	tx, _ := runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{})
	if tx.Status != run.ToolStatusFailed {
		t.Fatalf("status=%s", tx.Status)
	}
}

func TestParseShowOutput(t *testing.T) {
	out := parseShowOutput(`alice:Summer2024!:1001:1001:::
bob:hunter2
:no-user-pwd::1003:::

1 password hash cracked, 0 left
`)
	if len(out) != 3 {
		t.Fatalf("expected 3 pairs; got %v", out)
	}
}

func hasArg(args []string, want string) bool {
	for _, a := range args {
		if a == want || strings.HasPrefix(a, want+"=") {
			return true
		}
	}
	return false
}
