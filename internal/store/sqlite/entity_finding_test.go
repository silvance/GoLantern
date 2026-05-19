package sqlite

import (
	"database/sql"
	"testing"

	"github.com/silvance/golantern/internal/entity"
	"github.com/silvance/golantern/internal/finding"
	"github.com/silvance/golantern/internal/project"
	"github.com/silvance/golantern/internal/run"
	"github.com/silvance/golantern/internal/scope"
	"github.com/silvance/golantern/internal/workflow"
)

func seedProject(t *testing.T, st *Store) *project.Project {
	t.Helper()
	p := &project.Project{Name: "P", DefaultScope: scope.KindLightActive, Mode: project.ModeAssessment}
	if err := st.Projects.Save(ctx(), p); err != nil {
		t.Fatal(err)
	}
	return p
}

// ----- entities --------------------------------------------------------

func TestEntityUpsertCreatesAndDedupes(t *testing.T) {
	st := newTestStore(t)
	p := seedProject(t, st)
	canonical := entity.Canonicalize(entity.KindDomain, "EXAMPLE.com")
	id1, err := st.Entities.Upsert(ctx(), p.ID, entity.KindDomain, canonical, map[string]any{"src": "a"})
	if err != nil {
		t.Fatal(err)
	}
	id2, err := st.Entities.Upsert(ctx(), p.ID, entity.KindDomain, canonical, map[string]any{"src": "b"})
	if err != nil {
		t.Fatal(err)
	}
	if id1 != id2 {
		t.Fatalf("dedup failed: %q != %q", id1, id2)
	}

	rows, _ := st.Entities.ListByProject(ctx(), p.ID)
	if len(rows) != 1 {
		t.Fatalf("expected 1 entity row, got %d", len(rows))
	}
	// Older evidence wins on scalar conflicts: src should still be "a".
	if rows[0].Attributes["src"] != "a" {
		t.Fatalf("merge conflict-resolution wrong: %+v", rows[0].Attributes)
	}
}

func TestEntityUpsertListUnionsAttributes(t *testing.T) {
	st := newTestStore(t)
	p := seedProject(t, st)
	canonical := entity.Canonicalize(entity.KindIP, "192.0.2.5")
	if _, err := st.Entities.Upsert(ctx(), p.ID, entity.KindIP, canonical,
		map[string]any{"ports": []any{float64(80), float64(443)}},
	); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Entities.Upsert(ctx(), p.ID, entity.KindIP, canonical,
		map[string]any{"ports": []any{float64(443), float64(8080)}},
	); err != nil {
		t.Fatal(err)
	}
	rows, _ := st.Entities.ListByProject(ctx(), p.ID)
	ports, _ := rows[0].Attributes["ports"].([]any)
	if len(ports) != 3 {
		t.Fatalf("list union wrong: %+v", ports)
	}
}

func TestEntityListValuesByKind(t *testing.T) {
	st := newTestStore(t)
	p := seedProject(t, st)
	for _, v := range []string{"a.example.com", "b.example.com"} {
		_, err := st.Entities.Upsert(ctx(), p.ID, entity.KindDomain, v, nil)
		if err != nil {
			t.Fatal(err)
		}
	}
	if _, err := st.Entities.Upsert(ctx(), p.ID, entity.KindIP, "192.0.2.5", nil); err != nil {
		t.Fatal(err)
	}
	values, _ := st.Entities.ListValuesByKind(ctx(), p.ID, entity.KindDomain)
	if len(values) != 2 {
		t.Fatalf("expected 2 domain values, got %v", values)
	}
}

func TestEntityStoresUppercaseEnumName(t *testing.T) {
	// SQLAlchemy parity: the DB must hold 'DOMAIN', not 'domain'.
	st := newTestStore(t)
	p := seedProject(t, st)
	if _, err := st.Entities.Upsert(ctx(), p.ID, entity.KindDomain, "x.test", nil); err != nil {
		t.Fatal(err)
	}
	var raw string
	if err := st.DB.QueryRowContext(ctx(), `SELECT kind FROM entities WHERE project_id = ?`, p.ID).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if raw != "DOMAIN" {
		t.Fatalf("DB stored %q, want DOMAIN", raw)
	}
}

func TestEntityCascadeOnProjectDelete(t *testing.T) {
	st := newTestStore(t)
	p := seedProject(t, st)
	if _, err := st.Entities.Upsert(ctx(), p.ID, entity.KindDomain, "x.test", nil); err != nil {
		t.Fatal(err)
	}
	if err := st.Projects.Delete(ctx(), p.ID); err != nil {
		t.Fatal(err)
	}
	var n int
	_ = st.DB.QueryRowContext(ctx(), `SELECT count(*) FROM entities`).Scan(&n)
	if n != 0 {
		t.Fatalf("FK cascade failed: %d entity rows remain", n)
	}
}

// ----- findings + evidence --------------------------------------------

func TestFindingRoundTripAndOrdering(t *testing.T) {
	st := newTestStore(t)
	p := seedProject(t, st)
	for _, sev := range []finding.Severity{finding.SeverityLow, finding.SeverityCritical, finding.SeverityMedium} {
		if err := st.Findings.CreateFinding(ctx(), &finding.Finding{
			ProjectID:  p.ID,
			Title:      "T-" + string(sev),
			Severity:   sev,
			Confidence: finding.ConfidenceMedium,
			Attributes: map[string]any{"sev": string(sev)},
		}); err != nil {
			t.Fatal(err)
		}
	}
	got, err := st.Findings.ListFindings(ctx(), p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("findings=%d, want 3", len(got))
	}
	// Insertion order from the repo (report layer handles severity sort).
	if got[0].Severity != finding.SeverityLow || got[2].Severity != finding.SeverityMedium {
		t.Fatalf("insertion order broken: %+v", got)
	}
	// Attributes JSON round-tripped.
	if got[0].Attributes["sev"] != "low" {
		t.Fatalf("attributes lost: %+v", got[0].Attributes)
	}
}

func TestFindingStoresUppercaseEnums(t *testing.T) {
	st := newTestStore(t)
	p := seedProject(t, st)
	if err := st.Findings.CreateFinding(ctx(), &finding.Finding{
		ProjectID:  p.ID,
		Title:      "X",
		Severity:   finding.SeverityHigh,
		Confidence: finding.ConfidenceConfirmed,
	}); err != nil {
		t.Fatal(err)
	}
	var sev, conf string
	_ = st.DB.QueryRowContext(ctx(), `SELECT severity, confidence FROM findings WHERE project_id = ?`, p.ID).
		Scan(&sev, &conf)
	if sev != "HIGH" || conf != "CONFIRMED" {
		t.Fatalf("DB stored %q/%q, want HIGH/CONFIRMED", sev, conf)
	}
}

func TestEvidenceRoundTrip(t *testing.T) {
	st := newTestStore(t)
	p := seedProject(t, st)
	// Need both an entity and a finding to anchor evidence.
	eid, _ := st.Entities.Upsert(ctx(), p.ID, entity.KindDomain, "x.test", nil)
	f := &finding.Finding{
		ProjectID: p.ID, Title: "F", Severity: finding.SeverityLow, Confidence: finding.ConfidenceMedium,
	}
	_ = st.Findings.CreateFinding(ctx(), f)
	// And a run + tool execution to anchor tool_execution_id.
	ru := &run.Run{ProjectID: p.ID, Phase: workflow.PhaseOSINT, Status: run.StatusRunning}
	_ = st.Runs.Save(ctx(), ru)
	tx := &run.ToolExecution{RunID: ru.ID, Tool: "fixture", Status: run.ToolStatusCompleted}
	_ = st.Runs.SaveToolExecution(ctx(), tx)

	for i := 0; i < 2; i++ {
		if err := st.Findings.CreateEvidence(ctx(), &finding.Evidence{
			ProjectID:       p.ID,
			EntityID:        eid,
			FindingID:       f.ID,
			ToolExecutionID: tx.ID,
			SourceTool:      "fixture",
			SourceCategory:  finding.SourceActiveScan,
			Confidence:      finding.ConfidenceHigh,
			Payload:         map[string]any{"i": float64(i)},
			Notes:           "n",
		}); err != nil {
			t.Fatal(err)
		}
	}
	got, _ := st.Findings.ListEvidence(ctx(), p.ID)
	if len(got) != 2 {
		t.Fatalf("evidence=%d, want 2", len(got))
	}
	if got[0].SourceCategory != finding.SourceActiveScan {
		t.Fatalf("source_category lost: %+v", got[0])
	}
	if got[0].Payload["i"] != float64(0) {
		t.Fatalf("payload JSON lost: %+v", got[0].Payload)
	}
}

func TestEvidenceCascadeOnFindingDelete(t *testing.T) {
	st := newTestStore(t)
	p := seedProject(t, st)
	f := &finding.Finding{
		ProjectID: p.ID, Title: "F", Severity: finding.SeverityLow, Confidence: finding.ConfidenceMedium,
	}
	_ = st.Findings.CreateFinding(ctx(), f)
	_ = st.Findings.CreateEvidence(ctx(), &finding.Evidence{
		ProjectID: p.ID, FindingID: f.ID, SourceTool: "fixture",
		SourceCategory: finding.SourceActiveScan, Confidence: finding.ConfidenceHigh,
	})
	if _, err := st.DB.ExecContext(ctx(), `DELETE FROM findings WHERE id = ?`, f.ID); err != nil {
		t.Fatal(err)
	}
	var n int
	_ = st.DB.QueryRowContext(ctx(), `SELECT count(*) FROM evidence`).Scan(&n)
	if n != 0 {
		t.Fatalf("FK cascade failed: %d evidence rows survived finding delete", n)
	}
}

func TestEvidenceToolExecutionSetNull(t *testing.T) {
	// Deleting the parent ToolExecution must NOT wipe the evidence; the
	// FK is ON DELETE SET NULL so the audit trail of "what produced
	// this evidence" survives the tool-execution cleanup. (Python
	// invariant.)
	st := newTestStore(t)
	p := seedProject(t, st)
	ru := &run.Run{ProjectID: p.ID, Phase: workflow.PhaseOSINT, Status: run.StatusRunning}
	_ = st.Runs.Save(ctx(), ru)
	tx := &run.ToolExecution{RunID: ru.ID, Tool: "fixture", Status: run.ToolStatusCompleted}
	_ = st.Runs.SaveToolExecution(ctx(), tx)
	_ = st.Findings.CreateEvidence(ctx(), &finding.Evidence{
		ProjectID:       p.ID,
		ToolExecutionID: tx.ID,
		SourceTool:      "fixture",
		SourceCategory:  finding.SourceActiveScan,
		Confidence:      finding.ConfidenceHigh,
	})
	if _, err := st.DB.ExecContext(ctx(), `DELETE FROM tool_executions WHERE id = ?`, tx.ID); err != nil {
		t.Fatal(err)
	}
	var dbTxID sql.NullString
	_ = st.DB.QueryRowContext(ctx(), `SELECT tool_execution_id FROM evidence`).Scan(&dbTxID)
	if dbTxID.Valid {
		t.Fatalf("tool_execution_id should be NULL after parent deletion, got %q", dbTxID.String)
	}
	var n int
	_ = st.DB.QueryRowContext(ctx(), `SELECT count(*) FROM evidence`).Scan(&n)
	if n != 1 {
		t.Fatalf("evidence row should survive, got %d rows", n)
	}
}

// Compile-time check: both repositories satisfy the domain interfaces.
var (
	_ entity.Repository  = (*EntityRepo)(nil)
	_ finding.Repository = (*FindingRepo)(nil)
)
