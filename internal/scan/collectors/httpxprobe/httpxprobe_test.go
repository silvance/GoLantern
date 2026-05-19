package httpxprobe

// Tests live in `package httpxprobe` (not _test) so they can swap in
// the unexported runner.

import (
	"context"
	"strings"
	"testing"

	"github.com/silvance/golantern/internal/entity"
	"github.com/silvance/golantern/internal/finding"
	"github.com/silvance/golantern/internal/project"
	"github.com/silvance/golantern/internal/run"
	"github.com/silvance/golantern/internal/scan"
	"github.com/silvance/golantern/internal/scope"
	"github.com/silvance/golantern/internal/store/memory"
	"github.com/silvance/golantern/internal/subprocess"
	"github.com/silvance/golantern/internal/workflow"
)

const sampleJSONL = `{"input":"api.example.com","url":"https://api.example.com","scheme":"https","host":"api.example.com","port":443,"status_code":200,"title":"API","webserver":"nginx","tech":["Nginx","Cloudflare"],"content_length":1024,"chain":[],"tls":{"subject_dn":"CN=*.example.com"}}
{"input":"admin.example.com","url":"https://admin.example.com/login","scheme":"https","host":"admin.example.com","port":443,"status_code":401,"title":"Admin Login","webserver":"nginx","tech":["Nginx"],"content_length":512}
{"input":"down.example.com","url":"https://down.example.com","host":"down.example.com"}
invalid-json-line-should-be-skipped
`

func setup(t *testing.T, rules []scope.Rule, defaultScope scope.RuleKind) (*memory.Store, *project.Project, *run.Run, *scan.Runner) {
	t.Helper()
	st := memory.New()
	ctx := context.Background()
	p := &project.Project{Name: "P", DefaultScope: defaultScope, Mode: project.ModeAssessment}
	if err := st.Projects.Save(ctx, p); err != nil {
		t.Fatal(err)
	}
	for _, r := range rules {
		_ = st.Scopes.Add(ctx, &scope.StoredRule{ProjectID: p.ID, Rule: r})
	}
	pol, _ := scope.Compile(p.ID, p.DefaultScope, rules)
	ru := &run.Run{ProjectID: p.ID, Phase: workflow.PhaseValidation, Status: run.StatusRunning}
	_ = st.Runs.Save(ctx, ru)
	runner, err := scan.NewRunner(scan.Deps{
		Runs: st.Runs, Entities: st.Entities, Findings: st.Findings, Scope: pol,
	}, nil, st.Audit)
	if err != nil {
		t.Fatal(err)
	}
	return st, p, ru, runner
}

type stubRunner struct {
	stdout  []byte
	err     error
	gotArgs []string
	gotIn   []byte
	called  int
}

func (s *stubRunner) run(_ context.Context, spec subprocess.Spec) (subprocess.Result, error) {
	s.called++
	s.gotArgs = append([]string(nil), spec.Args...)
	s.gotIn = append([]byte(nil), spec.Stdin...)
	return subprocess.Result{Stdout: s.stdout}, s.err
}

func TestHttpxProbeHappyPath(t *testing.T) {
	stub := &stubRunner{stdout: []byte(sampleJSONL)}
	c := newWithRunner(stub.run)
	st, p, ru, runner := setup(t,
		[]scope.Rule{
			{Pattern: "*.example.com", Kind: scope.KindLightActive},
		},
		scope.KindPassive,
	)
	tx, err := runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{
		"names": []any{"api.example.com", "admin.example.com", "down.example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if tx.Status != run.ToolStatusCompleted {
		t.Fatalf("status=%s err=%q", tx.Status, tx.ErrorSummary)
	}

	// URL entities: api + admin = 2 (down has no status_code so it's skipped).
	urls, _ := st.Entities.ListValuesByKind(context.Background(), p.ID, entity.KindURL)
	if len(urls) != 2 {
		t.Fatalf("URLs persisted=%d, want 2: %v", len(urls), urls)
	}
	// TECHNOLOGY entities: Nginx + Cloudflare deduped = 2.
	techs, _ := st.Entities.ListValuesByKind(context.Background(), p.ID, entity.KindTechnology)
	if len(techs) != 2 {
		t.Fatalf("technologies=%d, want 2: %v", len(techs), techs)
	}
	// Relations: 2 SERVES + 3 USES_TECH (api: Nginx+Cloudflare; admin: Nginx).
	rels, _ := st.Entities.ListRelationsByProject(context.Background(), p.ID)
	servesCount, usesCount := 0, 0
	for _, r := range rels {
		switch r.Kind {
		case entity.RelServes:
			servesCount++
		case entity.RelUsesTech:
			usesCount++
		}
	}
	if servesCount != 2 || usesCount != 3 {
		t.Fatalf("relations: serves=%d uses_tech=%d, want 2/3", servesCount, usesCount)
	}
	// Admin URL flagged the portal heuristic ("Admin Login" matches "admin" + "login").
	findings, _ := st.Findings.ListFindings(context.Background(), p.ID)
	if len(findings) != 1 || findings[0].Severity != finding.SeverityLow {
		t.Fatalf("expected 1 LOW exposed-portal finding; got %+v", findings)
	}
	if !strings.Contains(findings[0].Title, "admin.example.com") {
		t.Fatalf("finding title missing admin URL: %q", findings[0].Title)
	}
}

func TestHttpxProbeArgsAndStdin(t *testing.T) {
	stub := &stubRunner{stdout: []byte{}}
	c := newWithRunner(stub.run)
	_, p, ru, runner := setup(t,
		[]scope.Rule{{Pattern: "*.example.com", Kind: scope.KindLightActive}},
		scope.KindPassive,
	)
	_, _ = runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{
		"names":      []any{"api.example.com"},
		"extra_args": []any{"-screenshot"},
	})
	for _, want := range []string{"-silent", "-json", "-status-code", "-title", "-tech-detect", "-server", "-content-length", "-follow-redirects", "-no-color", "-screenshot"} {
		if !containsArg(stub.gotArgs, want) {
			t.Errorf("args missing %q; got %v", want, stub.gotArgs)
		}
	}
	if !strings.Contains(string(stub.gotIn), "api.example.com") {
		t.Fatalf("stdin missing target; got %q", stub.gotIn)
	}
}

func TestHttpxProbeNamesFallBackToSubdomainEntities(t *testing.T) {
	stub := &stubRunner{stdout: []byte{}}
	c := newWithRunner(stub.run)
	st, p, ru, runner := setup(t,
		[]scope.Rule{{Pattern: "*.example.com", Kind: scope.KindLightActive}},
		scope.KindPassive,
	)
	_, _ = st.Entities.Upsert(context.Background(), p.ID, entity.KindSubdomain, "api.example.com", nil)
	_, _ = st.Entities.Upsert(context.Background(), p.ID, entity.KindSubdomain, "admin.example.com", nil)
	tx, _ := runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{})
	if tx.Status != run.ToolStatusCompleted {
		t.Fatalf("status=%s err=%q", tx.Status, tx.ErrorSummary)
	}
	if !strings.Contains(string(stub.gotIn), "api.example.com") ||
		!strings.Contains(string(stub.gotIn), "admin.example.com") {
		t.Fatalf("stdin missing fallback names; got %q", stub.gotIn)
	}
}

func TestHttpxProbeNoNamesFails(t *testing.T) {
	stub := &stubRunner{}
	c := newWithRunner(stub.run)
	_, p, ru, runner := setup(t,
		[]scope.Rule{{Pattern: "*.example.com", Kind: scope.KindLightActive}},
		scope.KindPassive,
	)
	tx, _ := runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{})
	if tx.Status != run.ToolStatusFailed {
		t.Fatalf("status=%s, want failed", tx.Status)
	}
	if !strings.Contains(tx.ErrorSummary, "no targets") {
		t.Fatalf("error_summary missing hint: %q", tx.ErrorSummary)
	}
}

func TestHttpxProbeOutOfScopeSkipsSubprocess(t *testing.T) {
	stub := &stubRunner{}
	c := newWithRunner(stub.run)
	_, p, ru, runner := setup(t,
		[]scope.Rule{{Pattern: "*.good.test", Kind: scope.KindLightActive}},
		scope.KindPassive,
	)
	tx, _ := runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{
		"names": []any{"out.of.scope.example"},
	})
	if tx.Status != run.ToolStatusCompleted {
		t.Fatalf("status=%s", tx.Status)
	}
	if stub.called != 0 {
		t.Fatalf("subprocess called %d times; expected 0", stub.called)
	}
}

func TestHttpxProbeBinaryNotFound(t *testing.T) {
	c := newWithRunner(func(_ context.Context, spec subprocess.Spec) (subprocess.Result, error) {
		return subprocess.Result{}, &subprocess.BinaryNotFoundError{Binary: spec.Binary}
	})
	_, p, ru, runner := setup(t,
		[]scope.Rule{{Pattern: "*.example.com", Kind: scope.KindLightActive}},
		scope.KindPassive,
	)
	tx, _ := runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{
		"names": []any{"api.example.com"},
	})
	if tx.Status != run.ToolStatusFailed {
		t.Fatalf("status=%s", tx.Status)
	}
	if !strings.Contains(tx.ErrorSummary, "httpx") {
		t.Fatalf("error_summary missing binary name: %q", tx.ErrorSummary)
	}
}

func TestHttpxProbeRecordWithoutStatusSkipped(t *testing.T) {
	// down.example.com in the sample has no status_code; the parser
	// drops it. Confirm via emission counts when it's the only input.
	stub := &stubRunner{stdout: []byte(`{"url":"https://down.example.com","host":"down.example.com"}` + "\n")}
	c := newWithRunner(stub.run)
	_, p, ru, runner := setup(t,
		[]scope.Rule{{Pattern: "*.example.com", Kind: scope.KindLightActive}},
		scope.KindPassive,
	)
	tx, _ := runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{
		"names": []any{"down.example.com"},
	})
	if tx.Status != run.ToolStatusCompleted {
		t.Fatalf("status=%s err=%q", tx.Status, tx.ErrorSummary)
	}
	if tx.EntitiesEmitted != 0 {
		t.Fatalf("records without status_code should not produce entities; got %d", tx.EntitiesEmitted)
	}
}

func TestHttpxProbePortFieldAcceptsIntOrString(t *testing.T) {
	// Two records that differ only in the JSON shape of port — int vs
	// quoted string. Both should produce a URL entity.
	jsonl := `{"url":"https://a.example.com","host":"a.example.com","port":443,"status_code":200}
{"url":"https://b.example.com","host":"b.example.com","port":"8443","status_code":200}
`
	stub := &stubRunner{stdout: []byte(jsonl)}
	c := newWithRunner(stub.run)
	st, p, ru, runner := setup(t,
		[]scope.Rule{{Pattern: "*.example.com", Kind: scope.KindLightActive}},
		scope.KindPassive,
	)
	_, _ = runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{
		"names": []any{"a.example.com", "b.example.com"},
	})
	urls, _ := st.Entities.ListValuesByKind(context.Background(), p.ID, entity.KindURL)
	if len(urls) != 2 {
		t.Fatalf("expected 2 URL entities; got %v", urls)
	}
}

func TestMatchInterestingKeyword(t *testing.T) {
	cases := []struct {
		title, url, want string
	}{
		{"Admin Login", "https://x", "login"}, // earlier match wins (login)
		{"Welcome", "https://admin.example.com", "admin"},
		{"GitLab", "https://repo.example.com", "gitlab"},
		{"User Portal", "https://x", ""}, // no listed keyword
		{"", "", ""},
	}
	for _, c := range cases {
		if got := matchInterestingKeyword(c.title, c.url); got != c.want {
			t.Errorf("(%q, %q) = %q, want %q", c.title, c.url, got, c.want)
		}
	}
}

// containsArg is a tiny helper so the test stays readable.
func containsArg(args []string, want string) bool {
	for _, a := range args {
		if a == want {
			return true
		}
	}
	return false
}
