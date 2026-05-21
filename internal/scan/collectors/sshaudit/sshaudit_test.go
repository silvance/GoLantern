package sshaudit

import (
	"context"
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

func TestSshauditEmitsCVEAndAlgoFindings(t *testing.T) {
	// Trimmed ssh-audit JSON exemplar with a CVE, a "fail" cipher, and a "warn" kex.
	stub := &stubRunner{stdout: `{
		"banner": {"raw": "SSH-2.0-OpenSSH_7.4", "software": "OpenSSH_7.4", "protocol": [2,0]},
		"cves": [
			{"name": "CVE-2018-15473", "cvssv2": 5.0, "description": "Username enumeration via timing."}
		],
		"kex": [
			{"algorithm": "diffie-hellman-group1-sha1", "notes": {"fail": ["broken DH group"], "warn": [], "info": []}}
		],
		"key": [],
		"enc": [
			{"algorithm": "3des-cbc", "notes": {"fail": [], "warn": ["deprecated cipher"], "info": []}}
		],
		"mac": [],
		"compression": []
	}`}
	c := newWithRunner(stub.run)
	st, p, ru, runner := setup(t)
	tx, err := runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{
		"targets": []any{"10.0.0.1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if tx.Status != run.ToolStatusCompleted {
		t.Fatalf("status=%s err=%q", tx.Status, tx.ErrorSummary)
	}
	fs, _ := st.Findings.ListFindings(context.Background(), p.ID)
	if len(fs) != 3 {
		t.Fatalf("expected 3 findings (1 CVE + 1 fail + 1 warn); got %d", len(fs))
	}
	// CVE severity from CVSS 5.0 should be Medium; fail kex Medium; warn cipher Low.
	gotSev := map[string]finding.Severity{}
	for _, f := range fs {
		switch f.Category {
		case "ssh.cve":
			gotSev["cve"] = f.Severity
		case "ssh.weak_algorithm":
			if f.Attributes["severity"] == "fail" {
				gotSev["fail"] = f.Severity
			} else {
				gotSev["warn"] = f.Severity
			}
		}
	}
	if gotSev["cve"] != finding.SeverityMedium {
		t.Errorf("CVE 5.0 expected Medium; got %s", gotSev["cve"])
	}
	if gotSev["fail"] != finding.SeverityMedium {
		t.Errorf("fail expected Medium; got %s", gotSev["fail"])
	}
	if gotSev["warn"] != finding.SeverityLow {
		t.Errorf("warn expected Low; got %s", gotSev["warn"])
	}
}

func TestSshauditNoTargetsFails(t *testing.T) {
	c := newWithRunner((&stubRunner{}).run)
	_, p, ru, runner := setup(t)
	tx, _ := runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{})
	if tx.Status != run.ToolStatusFailed {
		t.Fatalf("status=%s", tx.Status)
	}
}

func TestSeverityFromCVSS(t *testing.T) {
	cases := []struct {
		cvss float64
		want finding.Severity
	}{
		{9.5, finding.SeverityCritical},
		{7.5, finding.SeverityHigh},
		{5.0, finding.SeverityMedium},
		{2.0, finding.SeverityLow},
	}
	for _, c := range cases {
		if got := severityFromCVSS(c.cvss); got != c.want {
			t.Errorf("severityFromCVSS(%.1f) = %s; want %s", c.cvss, got, c.want)
		}
	}
}
