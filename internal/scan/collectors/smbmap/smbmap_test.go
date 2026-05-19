package smbmap

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
	rules := []scope.Rule{{Pattern: "10.0.0.0/8", Kind: scope.KindLightActive}}
	_ = st.Scopes.Add(ctx, &scope.StoredRule{ProjectID: p.ID, Rule: rules[0]})
	pol, _ := scope.Compile(p.ID, p.DefaultScope, rules)
	ru := &run.Run{ProjectID: p.ID, Phase: workflow.PhaseValidation, Status: run.StatusRunning}
	_ = st.Runs.Save(ctx, ru)
	runner, _ := scan.NewRunner(scan.Deps{
		Runs: st.Runs, Entities: st.Entities, Findings: st.Findings, Scope: pol,
	}, nil, st.Audit)
	return st, p, ru, runner
}

const sampleOutput = `
[+] IP: 10.0.0.5:445	Name: DC01
	Backups        READ, WRITE   the nightly backup dir
	Public         READ ONLY
	Confidential   READ            internal stuff
	IPC$           NO ACCESS
	C$             NO ACCESS
`

func TestSmbmapAnonymousWriteHighReadMedium(t *testing.T) {
	stub := func(_ context.Context, _ subprocess.Spec) (subprocess.Result, error) {
		return subprocess.Result{Stdout: []byte(sampleOutput)}, nil
	}
	c := newWithRunner(stub)
	st, p, ru, runner := setup(t)
	_, _ = runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{
		"targets": []any{"10.0.0.5"},
	})
	findings, _ := st.Findings.ListFindings(context.Background(), p.ID)
	// Backups WRITE -> HIGH; Public READ -> MEDIUM; Confidential READ -> MEDIUM.
	// IPC$ + C$ are system shares and skipped under anonymous.
	if len(findings) != 3 {
		t.Fatalf("findings=%d; want 3", len(findings))
	}
	bySev := map[finding.Severity]int{}
	for _, f := range findings {
		bySev[f.Severity]++
	}
	if bySev[finding.SeverityHigh] != 1 || bySev[finding.SeverityMedium] != 2 {
		t.Fatalf("severity counts wrong: %+v", bySev)
	}
	// SERVICE entity emitted.
	services, _ := st.Entities.ListValuesByKind(context.Background(), p.ID, entity.KindService)
	if len(services) != 1 || services[0] != "10.0.0.5:445/smb" {
		t.Fatalf("services=%v", services)
	}
}

func TestSmbmapNoTargets(t *testing.T) {
	stub := func(_ context.Context, _ subprocess.Spec) (subprocess.Result, error) { return subprocess.Result{}, nil }
	c := newWithRunner(stub)
	_, p, ru, runner := setup(t)
	tx, _ := runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{})
	if tx.Status != run.ToolStatusFailed {
		t.Fatalf("status=%s", tx.Status)
	}
}
