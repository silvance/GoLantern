package trufflehog

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
	rules := []scope.Rule{{Pattern: "github.com", Kind: scope.KindPassive}}
	_ = st.Scopes.Add(ctx, &scope.StoredRule{ProjectID: p.ID, Rule: rules[0]})
	pol, _ := scope.Compile(p.ID, p.DefaultScope, rules)
	ru := &run.Run{ProjectID: p.ID, Phase: workflow.PhaseEnrichment, Status: run.StatusRunning}
	_ = st.Runs.Save(ctx, ru)
	runner, _ := scan.NewRunner(scan.Deps{
		Runs: st.Runs, Entities: st.Entities, Findings: st.Findings, Scope: pol,
	}, nil, st.Audit)
	return st, p, ru, runner
}

const sampleJSONL = `{"DetectorName":"AWS","Verified":true,"Redacted":"AKIA****","SourceMetadata":{"Data":{"Git":{"repository":"https://github.com/acme/api","commit":"abc123","file":"main.py","line":42,"email":"alice@acme.example"}}}}
{"DetectorName":"GitHub","Verified":false,"Redacted":"ghp_****","SourceMetadata":{"Data":{"Git":{"repository":"https://github.com/acme/api","file":"ci.yml","line":5}}}}
{"DetectorName":"AWS","Verified":true,"Redacted":"AKIA****","SourceMetadata":{"Data":{"Git":{"repository":"https://github.com/acme/api","file":"main.py","line":42}}}}
not-json
`

func TestTrufflehogVerifiedIsHighUnverifiedIsMedium(t *testing.T) {
	stub := func(_ context.Context, _ subprocess.Spec) (subprocess.Result, error) {
		return subprocess.Result{Stdout: []byte(sampleJSONL)}, nil
	}
	c := newWithRunner(stub)
	st, p, ru, runner := setup(t)
	tx, err := runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{
		"repos": []any{"https://github.com/acme/api"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if tx.Status != run.ToolStatusCompleted {
		t.Fatalf("status=%s err=%q", tx.Status, tx.ErrorSummary)
	}
	// Dedup: third record is a duplicate of the first. 2 findings.
	findings, _ := st.Findings.ListFindings(context.Background(), p.ID)
	if len(findings) != 2 {
		t.Fatalf("findings=%d, want 2", len(findings))
	}
	sevByDetector := map[string]finding.Severity{}
	for _, f := range findings {
		if d, _ := f.Attributes["detector"].(string); d != "" {
			sevByDetector[d] = f.Severity
		}
	}
	if sevByDetector["AWS"] != finding.SeverityHigh {
		t.Fatalf("verified AWS should be HIGH; got %s", sevByDetector["AWS"])
	}
	if sevByDetector["GitHub"] != finding.SeverityMedium {
		t.Fatalf("unverified GitHub should be MEDIUM; got %s", sevByDetector["GitHub"])
	}
}

func TestTrufflehogRedactedNeverContainsRawSecret(t *testing.T) {
	// The parser only reads Redacted; if upstream emits Raw, we drop it.
	body := `{"DetectorName":"AWS","Verified":true,"Redacted":"AKIA****","Raw":"AKIA_THE_REAL_SECRET","SourceMetadata":{"Data":{"Git":{"repository":"https://github.com/acme/api","file":"x"}}}}` + "\n"
	stub := func(_ context.Context, _ subprocess.Spec) (subprocess.Result, error) {
		return subprocess.Result{Stdout: []byte(body)}, nil
	}
	c := newWithRunner(stub)
	st, p, ru, runner := setup(t)
	_, _ = runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{
		"repos": []any{"https://github.com/acme/api"},
	})
	findings, _ := st.Findings.ListFindings(context.Background(), p.ID)
	if len(findings) != 1 {
		t.Fatalf("findings=%d", len(findings))
	}
	// Check every persisted field for the raw value.
	for _, v := range findings[0].Attributes {
		if s, ok := v.(string); ok && s == "AKIA_THE_REAL_SECRET" {
			t.Fatalf("raw secret leaked into finding attribute: %q", s)
		}
	}
	if findings[0].Attributes["redacted"] != "AKIA****" {
		t.Fatalf("redacted form missing: %+v", findings[0].Attributes)
	}
}

func TestTrufflehogNoReposFails(t *testing.T) {
	stub := func(_ context.Context, _ subprocess.Spec) (subprocess.Result, error) { return subprocess.Result{}, nil }
	c := newWithRunner(stub)
	_, p, ru, runner := setup(t)
	tx, _ := runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{})
	if tx.Status != run.ToolStatusFailed {
		t.Fatalf("status=%s", tx.Status)
	}
}

func TestTrufflehogReposFallbackToEntities(t *testing.T) {
	stub := func(_ context.Context, _ subprocess.Spec) (subprocess.Result, error) {
		return subprocess.Result{Stdout: []byte{}}, nil
	}
	c := newWithRunner(stub)
	st, p, ru, runner := setup(t)
	_, _ = st.Entities.Upsert(context.Background(), p.ID, entity.KindRepository, "https://github.com/acme/x", nil)
	tx, _ := runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{})
	if tx.Status != run.ToolStatusCompleted {
		t.Fatalf("status=%s err=%q", tx.Status, tx.ErrorSummary)
	}
}
