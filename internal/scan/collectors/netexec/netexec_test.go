package netexec

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
	p := &project.Project{Name: "P", DefaultScope: scope.KindLightActive, Mode: project.ModeCTF}
	_ = st.Projects.Save(ctx, p)
	pol, _ := scope.Compile(p.ID, p.DefaultScope, nil)
	ru := &run.Run{ProjectID: p.ID, Phase: workflow.PhaseValidation, Status: run.StatusRunning}
	_ = st.Runs.Save(ctx, ru)
	runner, _ := scan.NewRunner(scan.Deps{
		Runs: st.Runs, Entities: st.Entities, Findings: st.Findings, Scope: pol,
	}, nil, st.Audit)
	return st, p, ru, runner
}

type stubRunner struct {
	stdout  string
	gotArgs []string
}

func (s *stubRunner) run(_ context.Context, spec subprocess.Spec) (subprocess.Result, error) {
	s.gotArgs = append([]string(nil), spec.Args...)
	return subprocess.Result{Stdout: []byte(s.stdout)}, nil
}

func TestNetexecParsesBannerAndShares(t *testing.T) {
	stub := &stubRunner{stdout: `
SMB    10.0.0.5    445   DC01    [*] Windows Server 2019 Build 17763 x64 (name:DC01) (domain:CORP) (signing:False) (SMBv1:True)
SMB    10.0.0.5    445   DC01    [+] CORP\:
SMB    10.0.0.5    445   DC01    [+] IPC$        READ        Remote IPC
SMB    10.0.0.5    445   DC01    [+] NETLOGON    READ        Logon server share
SMB    10.0.0.5    445   DC01    [+] SYSVOL      READ,WRITE  Logon server share
`}
	c := newWithRunner(stub.run)
	st, p, ru, runner := setup(t)
	tx, err := runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{
		"targets": []any{"10.0.0.5"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if tx.Status != run.ToolStatusCompleted {
		t.Fatalf("status=%s err=%q", tx.Status, tx.ErrorSummary)
	}
	fs, _ := st.Findings.ListFindings(context.Background(), p.ID)
	// Expect: signing disabled (Medium), SMBv1 (High), null session (Medium).
	if len(fs) < 3 {
		t.Fatalf("expected >=3 findings; got %d", len(fs))
	}
	var smbv1Sev finding.Severity
	for _, f := range fs {
		if f.Category == "smb.legacy_protocol" {
			smbv1Sev = f.Severity
		}
	}
	if smbv1Sev != finding.SeverityHigh {
		t.Fatalf("SMBv1 should be High; got %s", smbv1Sev)
	}
}

func TestNetexecPwn3dCriticalFinding(t *testing.T) {
	stub := &stubRunner{stdout: `
SMB    10.0.0.5    445   WS01    [*] Windows 10.0 (name:WS01) (domain:CORP) (signing:True) (SMBv1:False)
SMB    10.0.0.5    445   WS01    [+] CORP\admin:Hunter2 (Pwn3d!)
SMB    10.0.0.5    445   WS01    [+] C$         READ,WRITE
SMB    10.0.0.5    445   WS01    [+] ADMIN$     READ,WRITE
`}
	c := newWithRunner(stub.run)
	st, p, ru, runner := setup(t)
	_, _ = runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{
		"targets":  []any{"10.0.0.5"},
		"username": "admin",
		"password": "Hunter2",
		"domain":   "CORP",
	})
	fs, _ := st.Findings.ListFindings(context.Background(), p.ID)
	if len(fs) != 1 {
		t.Fatalf("expected 1 finding (Pwn3d!); got %d", len(fs))
	}
	if fs[0].Severity != finding.SeverityCritical {
		t.Fatalf("Pwn3d should be Critical; got %s", fs[0].Severity)
	}
}

func TestNetexecHardenedHostNoFindings(t *testing.T) {
	stub := &stubRunner{stdout: `
SMB    10.0.0.5    445   WS01    [*] Windows 10.0 (name:WS01) (domain:CORP) (signing:True) (SMBv1:False)
SMB    10.0.0.5    445   WS01    [-] CORP\:  STATUS_LOGON_FAILURE
`}
	c := newWithRunner(stub.run)
	st, p, ru, runner := setup(t)
	tx, err := runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{
		"targets": []any{"10.0.0.5"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if tx.Status != run.ToolStatusCompleted {
		t.Fatalf("status=%s", tx.Status)
	}
	fs, _ := st.Findings.ListFindings(context.Background(), p.ID)
	if len(fs) != 0 {
		t.Fatalf("hardened host should produce no findings; got %d", len(fs))
	}
}

func TestNetexecNoTargetsFails(t *testing.T) {
	c := newWithRunner((&stubRunner{}).run)
	_, p, ru, runner := setup(t)
	tx, _ := runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{})
	if tx.Status != run.ToolStatusFailed {
		t.Fatalf("status=%s", tx.Status)
	}
}

func TestStripANSI(t *testing.T) {
	in := "\x1b[1;32mSMB\x1b[0m   1.2.3.4   445   X    \x1b[0;31m[-]\x1b[0m fail"
	got := stripANSI(in)
	want := "SMB   1.2.3.4   445   X    [-] fail"
	if got != want {
		t.Fatalf("stripANSI = %q; want %q", got, want)
	}
}
