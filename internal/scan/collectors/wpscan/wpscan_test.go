package wpscan

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
	p := &project.Project{Name: "P", DefaultScope: scope.KindDeny, Mode: project.ModeBugBounty}
	_ = st.Projects.Save(ctx, p)
	rules := []scope.Rule{{Pattern: "*.example.com", Kind: scope.KindFullActive}}
	for _, r := range rules {
		_ = st.Scopes.Add(ctx, &scope.StoredRule{ProjectID: p.ID, Rule: r})
	}
	pol, _ := scope.Compile(p.ID, p.DefaultScope, rules)
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

func TestWpscanHappyPath(t *testing.T) {
	stub := &stubRunner{stdout: `{
		"target_url": "https://blog.example.com/",
		"version": {
			"number": "5.7.1",
			"status": "insecure",
			"confidence": 100,
			"vulnerabilities": [
				{"title": "WP 5.7.1 SQL Injection", "fixed_in": "5.7.2", "references": {"cve": ["CVE-2021-9999"]}}
			]
		},
		"plugins": {
			"contact-form-7": {
				"version": {"number": "5.3.1"},
				"latest_version": "5.5.0",
				"outdated": true,
				"vulnerabilities": [
					{"title": "Unrestricted file upload", "fixed_in": "5.3.2", "references": {"cve": ["CVE-2020-35489"]}}
				]
			}
		},
		"themes": {},
		"interesting_findings": [
			{"type": "debug_log", "url": "https://blog.example.com/wp-content/debug.log", "to_s": "WordPress debug log accessible"}
		]
	}`}
	c := newWithRunner(stub.run)
	st, p, ru, runner := setup(t)
	tx, err := runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{
		"targets": []any{"https://blog.example.com/"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if tx.Status != run.ToolStatusCompleted {
		t.Fatalf("status=%s err=%q", tx.Status, tx.ErrorSummary)
	}
	// Technology entities: wp core, plugin.
	techs, _ := st.Entities.ListValuesByKind(context.Background(), p.ID, entity.KindTechnology)
	have := map[string]bool{}
	for _, v := range techs {
		have[v] = true
	}
	if !have["wordpress/5.7.1"] {
		t.Fatalf("missing wp core tech: %v", techs)
	}
	if !have["wp-plugin/contact-form-7/5.3.1"] {
		t.Fatalf("missing plugin tech: %v", techs)
	}
	// Findings: core vuln, plugin vuln, debug log.
	fs, _ := st.Findings.ListFindings(context.Background(), p.ID)
	if len(fs) != 3 {
		t.Fatalf("expected 3 findings; got %d (%+v)", len(fs), fs)
	}
}

func TestWpscanNonWordPressSiteRecorded(t *testing.T) {
	// Empty/non-JSON output (wpscan reports "not WordPress"); collector
	// should not blow up and should not emit a finding.
	stub := &stubRunner{stdout: "Site doesn't appear to run WordPress."}
	c := newWithRunner(stub.run)
	st, p, ru, runner := setup(t)
	tx, _ := runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{
		"targets": []any{"https://blog.example.com/"},
	})
	if tx.Status != run.ToolStatusCompleted {
		t.Fatalf("status=%s err=%q", tx.Status, tx.ErrorSummary)
	}
	fs, _ := st.Findings.ListFindings(context.Background(), p.ID)
	if len(fs) != 0 {
		t.Fatalf("non-WP site should produce no findings; got %d", len(fs))
	}
}

func TestWpscanUnfixedVulnIsCritical(t *testing.T) {
	stub := &stubRunner{stdout: `{
		"target_url": "https://blog.example.com/",
		"version": {"number": "4.0", "vulnerabilities": [
			{"title": "Zero-day RCE", "fixed_in": ""}
		]},
		"plugins": {},
		"themes": {},
		"interesting_findings": []
	}`}
	c := newWithRunner(stub.run)
	st, p, ru, runner := setup(t)
	_, _ = runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{
		"targets": []any{"https://blog.example.com/"},
	})
	fs, _ := st.Findings.ListFindings(context.Background(), p.ID)
	if len(fs) != 1 {
		t.Fatalf("expected 1 finding; got %d", len(fs))
	}
	if fs[0].Severity != finding.SeverityCritical {
		t.Fatalf("unfixed vuln should be Critical; got %s", fs[0].Severity)
	}
}

func TestWpscanNoTargetsFails(t *testing.T) {
	c := newWithRunner((&stubRunner{}).run)
	_, p, ru, runner := setup(t)
	tx, _ := runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{})
	if tx.Status != run.ToolStatusFailed {
		t.Fatalf("status=%s", tx.Status)
	}
}
