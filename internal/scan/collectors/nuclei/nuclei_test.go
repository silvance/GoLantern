package nuclei

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

const sampleJSONL = `{"template-id":"cve-2021-12345","host":"https://api.example.com","matched-at":"https://api.example.com/admin","matcher-name":"endpoint","info":{"name":"Some Critical CVE","severity":"critical","tags":"cve,exposure"}}
{"template-id":"misconfig-cors","host":"https://api.example.com","matched-at":"https://api.example.com/","info":{"name":"Permissive CORS","severity":"medium","tags":["misconfig","cors"]}}
{"template-id":"info-server-banner","host":"https://api.example.com","info":{"name":"Server banner","severity":"info","tags":"tech"}}
not-valid-json
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
	ru := &run.Run{ProjectID: p.ID, Phase: workflow.PhaseExposure, Status: run.StatusRunning}
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
	gotArgs []string
	gotIn   []byte
	called  int
}

func (s *stubRunner) run(_ context.Context, spec subprocess.Spec) (subprocess.Result, error) {
	s.called++
	s.gotArgs = append([]string(nil), spec.Args...)
	s.gotIn = append([]byte(nil), spec.Stdin...)
	return subprocess.Result{Stdout: s.stdout}, nil
}

func TestNucleiHappyPath(t *testing.T) {
	stub := &stubRunner{stdout: []byte(sampleJSONL)}
	c := newWithRunner(stub.run)
	st, p, ru, runner := setup(t,
		[]scope.Rule{{Pattern: "*.example.com", Kind: scope.KindFullActive}},
		scope.KindPassive,
	)
	tx, err := runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{
		"targets": []any{"https://api.example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if tx.Status != run.ToolStatusCompleted {
		t.Fatalf("status=%s err=%q", tx.Status, tx.ErrorSummary)
	}
	// 2 non-info hits become findings; the info hit becomes evidence only.
	findings, _ := st.Findings.ListFindings(context.Background(), p.ID)
	if len(findings) != 2 {
		t.Fatalf("findings=%d, want 2", len(findings))
	}
	bySev := map[finding.Severity]int{}
	for _, f := range findings {
		bySev[f.Severity]++
	}
	if bySev[finding.SeverityCritical] != 1 || bySev[finding.SeverityMedium] != 1 {
		t.Fatalf("severity counts wrong: %+v", bySev)
	}
}

func TestNucleiInfoStaysAsEvidence(t *testing.T) {
	stub := &stubRunner{stdout: []byte(sampleJSONL)}
	c := newWithRunner(stub.run)
	st, p, ru, runner := setup(t,
		[]scope.Rule{{Pattern: "*.example.com", Kind: scope.KindFullActive}},
		scope.KindPassive,
	)
	_, _ = runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{
		"targets": []any{"https://api.example.com"},
	})
	// 3 results: 2 findings + 1 info -> 1 info evidence row + 2 finding-create rows
	// (the runner doesn't auto-emit evidence for emit_finding here unless the
	// finding has supporting_entities, but our findings do, so each finding
	// adds 1 evidence row for the URL supporting entity). Plus the summary
	// evidence row at the end. So: 1 info-as-evidence + 2 supporting-entity
	// evidence + 1 summary = 4 evidence rows minimum.
	ev, _ := st.Findings.ListEvidence(context.Background(), p.ID)
	if len(ev) < 4 {
		t.Fatalf("expected >= 4 evidence rows; got %d", len(ev))
	}
	// One should carry the info template_id.
	var sawInfo bool
	for _, e := range ev {
		if tid, _ := e.Payload["template_id"].(string); tid == "info-server-banner" {
			sawInfo = true
		}
	}
	if !sawInfo {
		t.Fatal("info-tier evidence missing")
	}
}

func TestNucleiTagsAndSeverityArgsForwarded(t *testing.T) {
	stub := &stubRunner{}
	c := newWithRunner(stub.run)
	_, p, ru, runner := setup(t,
		[]scope.Rule{{Pattern: "*.example.com", Kind: scope.KindFullActive}},
		scope.KindPassive,
	)
	_, _ = runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{
		"targets":    []any{"https://api.example.com"},
		"severities": []any{"high", "critical"},
		"tags":       []any{"cve", "exposure"},
	})
	got := strings.Join(stub.gotArgs, " ")
	if !strings.Contains(got, "-severity high,critical") {
		t.Errorf("severity flag missing; got %v", stub.gotArgs)
	}
	if !strings.Contains(got, "-tags cve,exposure") {
		t.Errorf("tags flag missing; got %v", stub.gotArgs)
	}
}

func TestNucleiEmptyTagsListDisablesFilter(t *testing.T) {
	stub := &stubRunner{}
	c := newWithRunner(stub.run)
	_, p, ru, runner := setup(t,
		[]scope.Rule{{Pattern: "*.example.com", Kind: scope.KindFullActive}},
		scope.KindPassive,
	)
	_, _ = runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{
		"targets": []any{"https://api.example.com"},
		"tags":    []any{}, // explicit empty
	})
	for _, a := range stub.gotArgs {
		if a == "-tags" {
			t.Errorf("empty tags should suppress the standalone -tags flag; got %v", stub.gotArgs)
		}
	}
}

func TestNucleiExtraArgsForbidden(t *testing.T) {
	c := newWithRunner(func(_ context.Context, _ subprocess.Spec) (subprocess.Result, error) {
		t.Fatal("should not be reached")
		return subprocess.Result{}, nil
	})
	_, p, ru, runner := setup(t,
		[]scope.Rule{{Pattern: "*.example.com", Kind: scope.KindFullActive}},
		scope.KindPassive,
	)
	tx, _ := runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{
		"targets":    []any{"https://api.example.com"},
		"extra_args": []any{"-o", "/tmp/leak"},
	})
	if tx.Status != run.ToolStatusFailed {
		t.Fatalf("status=%s, want failed", tx.Status)
	}
	if !strings.Contains(tx.ErrorSummary, "forbidden") {
		t.Fatalf("error_summary missing forbidden hint: %q", tx.ErrorSummary)
	}
}

func TestNucleiURLFallbackFilteredToHTTP(t *testing.T) {
	stub := &stubRunner{}
	c := newWithRunner(stub.run)
	st, p, ru, runner := setup(t,
		[]scope.Rule{{Pattern: "*.example.com", Kind: scope.KindFullActive}},
		scope.KindPassive,
	)
	_, _ = st.Entities.Upsert(context.Background(), p.ID, entity.KindURL, "https://api.example.com", nil)
	_, _ = st.Entities.Upsert(context.Background(), p.ID, entity.KindURL, "ftp://files.example.com", nil)
	_, _ = runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{})
	if !strings.Contains(string(stub.gotIn), "https://api.example.com") {
		t.Fatalf("expected https URL in stdin; got %q", stub.gotIn)
	}
	if strings.Contains(string(stub.gotIn), "ftp://") {
		t.Fatalf("ftp URL leaked into nuclei input: %q", stub.gotIn)
	}
}

func TestNucleiMaxTargetsCaps(t *testing.T) {
	stub := &stubRunner{}
	c := newWithRunner(stub.run)
	_, p, ru, runner := setup(t,
		[]scope.Rule{{Pattern: "*.example.com", Kind: scope.KindFullActive}},
		scope.KindPassive,
	)
	targets := make([]any, 5)
	for i := range targets {
		targets[i] = "https://t" + string(rune('a'+i)) + ".example.com"
	}
	_, _ = runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{
		"targets":     targets,
		"max_targets": 2,
	})
	stdinLines := strings.Count(strings.TrimRight(string(stub.gotIn), "\n"), "\n") + 1
	if stdinLines != 2 {
		t.Fatalf("stdin lines=%d, want 2 (max_targets cap)", stdinLines)
	}
}

func TestNucleiTagsParsedFromStringOrArray(t *testing.T) {
	stub := &stubRunner{stdout: []byte(sampleJSONL)}
	c := newWithRunner(stub.run)
	st, p, ru, runner := setup(t,
		[]scope.Rule{{Pattern: "*.example.com", Kind: scope.KindFullActive}},
		scope.KindPassive,
	)
	_, _ = runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{
		"targets": []any{"https://api.example.com"},
	})
	findings, _ := st.Findings.ListFindings(context.Background(), p.ID)
	for _, f := range findings {
		tags, _ := f.Attributes["tags"].([]any)
		if len(tags) == 0 {
			// fallback: not stored as []any in memory; check []string too
			ts, _ := f.Attributes["tags"].([]string)
			if len(ts) > 0 {
				return
			}
			t.Fatalf("finding %q has no tags: %+v", f.Title, f.Attributes)
		}
	}
}

func TestNucleiNoTargetsFails(t *testing.T) {
	stub := &stubRunner{}
	c := newWithRunner(stub.run)
	_, p, ru, runner := setup(t,
		[]scope.Rule{{Pattern: "*.example.com", Kind: scope.KindFullActive}},
		scope.KindPassive,
	)
	tx, _ := runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{})
	if tx.Status != run.ToolStatusFailed {
		t.Fatalf("status=%s", tx.Status)
	}
	if !strings.Contains(tx.ErrorSummary, "no targets") {
		t.Fatalf("error_summary missing hint: %q", tx.ErrorSummary)
	}
}
