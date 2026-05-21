package snmpwalk

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
	p := &project.Project{Name: "P", DefaultScope: scope.KindLightActive, Mode: project.ModeAssessment}
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
	// byTargetCommunity maps "target|community" -> stdout. Missing
	// key means an empty/error response.
	byTargetCommunity map[string]string
	gotArgs           [][]string
}

func (s *stubRunner) run(_ context.Context, spec subprocess.Spec) (subprocess.Result, error) {
	s.gotArgs = append(s.gotArgs, append([]string(nil), spec.Args...))
	var target, community string
	for i, a := range spec.Args {
		if a == "-c" && i+1 < len(spec.Args) {
			community = spec.Args[i+1]
		}
	}
	target = spec.Args[len(spec.Args)-2] // target is second-to-last before OID
	out, ok := s.byTargetCommunity[target+"|"+community]
	if !ok {
		return subprocess.Result{Stdout: []byte("Timeout: No Response from " + target + "\n")}, nil
	}
	return subprocess.Result{Stdout: []byte(out)}, nil
}

const publicWalk = `SNMPv2-MIB::sysDescr.0 = STRING: Linux gateway 5.10.0
SNMPv2-MIB::sysObjectID.0 = OID: NET-SNMP-MIB::netSnmpAgentOIDs.10
SNMPv2-MIB::sysUpTime.0 = Timeticks: (12345) 0:02:03.45
SNMPv2-MIB::sysContact.0 = STRING: admin@example.com
SNMPv2-MIB::sysName.0 = STRING: gateway
SNMPv2-MIB::sysLocation.0 = STRING: Server room
`

func TestSnmpwalkPublicHit(t *testing.T) {
	stub := &stubRunner{byTargetCommunity: map[string]string{
		"10.0.0.1|public": publicWalk,
	}}
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
	if len(fs) != 1 {
		t.Fatalf("expected 1 finding; got %d", len(fs))
	}
	if fs[0].Severity != finding.SeverityMedium {
		t.Fatalf("public default community should be Medium; got %s", fs[0].Severity)
	}
	if !strings.Contains(fs[0].Attributes["sys_name"].(string), "gateway") {
		t.Fatalf("sys_name not parsed: %v", fs[0].Attributes)
	}
}

func TestSnmpwalkPrivateIsHigh(t *testing.T) {
	stub := &stubRunner{byTargetCommunity: map[string]string{
		"10.0.0.1|public":  "Timeout",
		"10.0.0.1|private": publicWalk,
	}}
	c := newWithRunner(stub.run)
	st, p, ru, runner := setup(t)
	_, _ = runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{
		"targets": []any{"10.0.0.1"},
	})
	fs, _ := st.Findings.ListFindings(context.Background(), p.ID)
	if len(fs) != 1 {
		t.Fatalf("expected 1 finding; got %d", len(fs))
	}
	if fs[0].Severity != finding.SeverityHigh {
		t.Fatalf("private community should be High; got %s", fs[0].Severity)
	}
}

func TestSnmpwalkNoResponseNoFinding(t *testing.T) {
	stub := &stubRunner{} // every probe returns Timeout
	c := newWithRunner(stub.run)
	st, p, ru, runner := setup(t)
	tx, _ := runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{
		"targets": []any{"10.0.0.1"},
	})
	if tx.Status != run.ToolStatusCompleted {
		t.Fatalf("status=%s; non-responding host should still complete", tx.Status)
	}
	fs, _ := st.Findings.ListFindings(context.Background(), p.ID)
	if len(fs) != 0 {
		t.Fatalf("expected no findings; got %d", len(fs))
	}
}

func TestSnmpwalkNoTargetsFails(t *testing.T) {
	c := newWithRunner((&stubRunner{}).run)
	_, p, ru, runner := setup(t)
	tx, _ := runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{})
	if tx.Status != run.ToolStatusFailed {
		t.Fatalf("status=%s", tx.Status)
	}
}

func TestParseSysOIDs(t *testing.T) {
	got := parseSysOIDs(publicWalk)
	if got["sys_descr"] == "" || got["sys_name"] != "gateway" {
		t.Fatalf("parse missed fields: %v", got)
	}
}
