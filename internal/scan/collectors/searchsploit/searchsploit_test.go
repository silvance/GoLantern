package searchsploit

import (
	"context"
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
	byQuery map[string]string
	gotArgs [][]string
}

func (s *stubRunner) run(_ context.Context, spec subprocess.Spec) (subprocess.Result, error) {
	s.gotArgs = append(s.gotArgs, append([]string(nil), spec.Args...))
	q := spec.Args[len(spec.Args)-1]
	return subprocess.Result{Stdout: []byte(s.byQuery[q])}, nil
}

func TestSearchsploitEmitsFindings(t *testing.T) {
	stub := &stubRunner{byQuery: map[string]string{
		"wordpress 5.7.1": `{
			"RESULTS_EXPLOIT": [
				{"Title": "WordPress 5.7.1 - Remote Code Execution", "EDB-ID": "50000", "Path": "/exp/50000.py", "Date_Published": "2021-01-01", "Codes": "CVE-2021-9999"},
				{"Title": "WordPress 5.7.1 - Stored XSS", "EDB-ID": "50001", "Path": "/exp/50001.txt", "Date_Published": "2021-02-01"}
			]
		}`,
	}}
	c := newWithRunner(stub.run)
	st, p, ru, runner := setup(t)
	tx, err := runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{
		"queries": []any{"wordpress 5.7.1"},
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
	var rceSev finding.Severity
	for _, f := range fs {
		if f.Attributes["edb_id"] == "50000" {
			rceSev = f.Severity
		}
	}
	if rceSev != finding.SeverityHigh {
		t.Fatalf("RCE should be High; got %s", rceSev)
	}
}

func TestSearchsploitTechToQuery(t *testing.T) {
	cases := map[string]string{
		"wordpress/5.7.1":                "wordpress 5.7.1",
		"wp-plugin/contact-form-7/5.3.1": "contact-form-7 5.3.1",
		"wp-theme/twentyone/1.0":         "twentyone 1.0",
		"nginx":                          "nginx",
		"   ":                            "",
	}
	for in, want := range cases {
		if got := normalizeTechQuery(in); got != want {
			t.Errorf("normalizeTechQuery(%q) = %q; want %q", in, got, want)
		}
	}
}

func TestSearchsploitSeedsFromTechEntities(t *testing.T) {
	stub := &stubRunner{byQuery: map[string]string{
		"nginx 1.18.0": `{"RESULTS_EXPLOIT": []}`,
	}}
	c := newWithRunner(stub.run)
	st, p, ru, runner := setup(t)
	_, _ = st.Entities.Upsert(context.Background(), p.ID, entity.KindTechnology, "nginx/1.18.0", nil)
	_, _ = runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{})
	if len(stub.gotArgs) != 1 {
		t.Fatalf("expected 1 invocation; got %d", len(stub.gotArgs))
	}
	gotQuery := stub.gotArgs[0][len(stub.gotArgs[0])-1]
	if gotQuery != "nginx 1.18.0" {
		t.Fatalf("derived query wrong: %q", gotQuery)
	}
}

func TestSearchsploitMaxPerQuery(t *testing.T) {
	stub := &stubRunner{byQuery: map[string]string{
		"nginx 1.0": `{"RESULTS_EXPLOIT":[
			{"Title":"a","EDB-ID":"1"},
			{"Title":"b","EDB-ID":"2"},
			{"Title":"c","EDB-ID":"3"}
		]}`,
	}}
	c := newWithRunner(stub.run)
	st, p, ru, runner := setup(t)
	_, _ = runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{
		"queries":       []any{"nginx 1.0"},
		"max_per_query": 2,
	})
	fs, _ := st.Findings.ListFindings(context.Background(), p.ID)
	if len(fs) != 2 {
		t.Fatalf("expected 2 findings (capped); got %d", len(fs))
	}
}

func TestSearchsploitNoQueriesFails(t *testing.T) {
	c := newWithRunner((&stubRunner{}).run)
	_, p, ru, runner := setup(t)
	tx, _ := runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{})
	if tx.Status != run.ToolStatusFailed {
		t.Fatalf("status=%s", tx.Status)
	}
}
