package enum4linuxng

import (
	"context"
	"os"
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

// stubRunner emulates enum4linux-ng by writing the JSON output file
// the real binary would have produced at <prefix>.json.
type stubRunner struct {
	json string
}

func (s *stubRunner) run(_ context.Context, spec subprocess.Spec) (subprocess.Result, error) {
	var prefix string
	for i, a := range spec.Args {
		if a == "-oJ" && i+1 < len(spec.Args) {
			prefix = spec.Args[i+1]
		}
	}
	if prefix != "" {
		_ = os.WriteFile(prefix+".json", []byte(s.json), 0o600)
	}
	return subprocess.Result{}, nil
}

const sampleJSON = `{
	"target": "10.0.0.5",
	"nbtstat": {"workgroup": "CORP"},
	"users": {
		"1001": {"username": "alice", "RID": 1001},
		"1002": {"username": "bob", "RID": 1002},
		"500":  {"username": "Administrator", "RID": 500}
	},
	"groups": {"513": {"groupname": "Domain Users"}},
	"shares": {
		"public": {"mapping": "OK", "access": "READ,WRITE"},
		"netlogon": {"mapping": "OK", "access": "READ"}
	},
	"policy": {
		"min_password_length": 6,
		"password_complexity": false,
		"account_lockout_threshold": 0
	}
}`

func TestEnum4LinuxNGNullSessionFindings(t *testing.T) {
	stub := &stubRunner{json: sampleJSON}
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
	persons, _ := st.Entities.ListValuesByKind(context.Background(), p.ID, entity.KindPerson)
	if len(persons) != 3 {
		t.Fatalf("expected 3 person entities; got %v", persons)
	}
	fs, _ := st.Findings.ListFindings(context.Background(), p.ID)
	// Expect: anonymous user enum, writable share, weak password policy.
	if len(fs) != 3 {
		t.Fatalf("expected 3 findings; got %d (%+v)", len(fs), fs)
	}
	// Writable share should be High.
	var writableSev finding.Severity
	for _, f := range fs {
		if f.Category == "smb.writable_share" {
			writableSev = f.Severity
		}
	}
	if writableSev != finding.SeverityHigh {
		t.Fatalf("writable share should be High; got %s", writableSev)
	}
}

func TestEnum4LinuxNGAuthenticatedNoAnonFinding(t *testing.T) {
	// Same JSON but with credentials — anonymous-enum finding should NOT fire.
	stub := &stubRunner{json: sampleJSON}
	c := newWithRunner(stub.run)
	st, p, ru, runner := setup(t)
	_, _ = runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{
		"targets":  []any{"10.0.0.5"},
		"username": "guest",
		"password": "guest",
	})
	fs, _ := st.Findings.ListFindings(context.Background(), p.ID)
	for _, f := range fs {
		if f.Category == "smb.anonymous_user_enum" {
			t.Fatalf("anonymous-enum finding should not fire when credentials supplied: %+v", f)
		}
	}
}

func TestEnum4LinuxNGNoTargetsFails(t *testing.T) {
	c := newWithRunner((&stubRunner{}).run)
	_, p, ru, runner := setup(t)
	tx, _ := runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{})
	if tx.Status != run.ToolStatusFailed {
		t.Fatalf("status=%s", tx.Status)
	}
}
