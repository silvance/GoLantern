package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/silvance/golantern/internal/project"
	"github.com/silvance/golantern/internal/run"
	"github.com/silvance/golantern/internal/scope"
	"github.com/silvance/golantern/internal/workflow"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.db")
	db, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if err := Migrate(context.Background(), db); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	return NewStore(db)
}

func ctx() context.Context { return context.Background() }

// Compile-time interface assertions live here so test breakage is
// the first signal when an interface drifts.
var (
	_ project.Repository = (*ProjectRepo)(nil)
	_ scope.Repository   = (*ScopeRepo)(nil)
	_ run.Repository     = (*RunRepo)(nil)
)

func TestMigrateIsIdempotent(t *testing.T) {
	st := newTestStore(t)
	if err := Migrate(ctx(), st.DB); err != nil {
		t.Fatalf("second Migrate: %v", err)
	}
}

func TestProjectRoundTrip(t *testing.T) {
	st := newTestStore(t)
	p := &project.Project{
		Name:         "Acme",
		Description:  "test",
		Organization: "Co",
		DefaultScope: scope.KindLightActive,
		Mode:         project.ModeAssessment,
	}
	if err := st.Projects.Save(ctx(), p); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if p.ID == "" {
		t.Fatal("Save must assign ID")
	}
	got, err := st.Projects.Get(ctx(), p.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Name != "Acme" || got.DefaultScope != scope.KindLightActive || got.Mode != project.ModeAssessment {
		t.Fatalf("round trip mismatch: %+v", got)
	}
}

func TestProjectUpsert(t *testing.T) {
	st := newTestStore(t)
	p := &project.Project{Name: "A", DefaultScope: scope.KindPassive, Mode: project.ModeCTF}
	if err := st.Projects.Save(ctx(), p); err != nil {
		t.Fatal(err)
	}
	p.Description = "updated"
	if err := st.Projects.Save(ctx(), p); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	got, _ := st.Projects.Get(ctx(), p.ID)
	if got.Description != "updated" {
		t.Fatalf("upsert didn't take effect: %+v", got)
	}
}

func TestProjectDuplicateName(t *testing.T) {
	st := newTestStore(t)
	a := &project.Project{Name: "X", DefaultScope: scope.KindPassive, Mode: project.ModeCTF}
	b := &project.Project{Name: "X", DefaultScope: scope.KindPassive, Mode: project.ModeCTF}
	if err := st.Projects.Save(ctx(), a); err != nil {
		t.Fatal(err)
	}
	if err := st.Projects.Save(ctx(), b); !errors.Is(err, project.ErrDuplicate) {
		t.Fatalf("got %v, want ErrDuplicate", err)
	}
}

func TestProjectGetMissingIsErrNotFound(t *testing.T) {
	st := newTestStore(t)
	_, err := st.Projects.Get(ctx(), "ghost")
	if !errors.Is(err, project.ErrNotFound) {
		t.Fatalf("got %v, want ErrNotFound", err)
	}
}

func TestProjectListOrdersByCreatedAsc(t *testing.T) {
	st := newTestStore(t)
	names := []string{"a", "b", "c"}
	for _, n := range names {
		if err := st.Projects.Save(ctx(), &project.Project{
			Name: n, DefaultScope: scope.KindPassive, Mode: project.ModeCTF,
		}); err != nil {
			t.Fatal(err)
		}
		time.Sleep(2 * time.Millisecond) // ensure distinct created_at
	}
	got, err := st.Projects.List(ctx())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got[0].Name != "a" || got[2].Name != "c" {
		t.Fatalf("List order wrong: %+v", got)
	}
}

func TestProjectDelete(t *testing.T) {
	st := newTestStore(t)
	p := &project.Project{Name: "x", DefaultScope: scope.KindPassive, Mode: project.ModeCTF}
	_ = st.Projects.Save(ctx(), p)
	if err := st.Projects.Delete(ctx(), p.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if err := st.Projects.Delete(ctx(), p.ID); !errors.Is(err, project.ErrNotFound) {
		t.Fatalf("second Delete = %v, want ErrNotFound", err)
	}
}

func TestEnumValuesStoredAsSQLAlchemyNames(t *testing.T) {
	// Cross-check Python parity: the DB must hold the enum NAME, not
	// the value. A Python service reading this row must see 'PASSIVE',
	// not 'passive'.
	st := newTestStore(t)
	p := &project.Project{Name: "n", DefaultScope: scope.KindFullActive, Mode: project.ModeBugBounty}
	if err := st.Projects.Save(ctx(), p); err != nil {
		t.Fatal(err)
	}
	var dbScope, dbMode string
	row := st.DB.QueryRowContext(ctx(), `SELECT default_scope, mode FROM projects WHERE id = ?`, p.ID)
	if err := row.Scan(&dbScope, &dbMode); err != nil {
		t.Fatal(err)
	}
	if dbScope != "FULL_ACTIVE" || dbMode != "BUG_BOUNTY" {
		t.Fatalf("DB stored %q/%q, want FULL_ACTIVE/BUG_BOUNTY", dbScope, dbMode)
	}
}

func TestScopeRulesRoundTrip(t *testing.T) {
	st := newTestStore(t)
	p := &project.Project{Name: "x", DefaultScope: scope.KindPassive, Mode: project.ModeCTF}
	_ = st.Projects.Save(ctx(), p)
	for _, pat := range []string{"*.example.com", "api.example.com"} {
		if err := st.Scopes.Add(ctx(), &scope.StoredRule{
			ProjectID: p.ID, Rule: scope.Rule{Pattern: pat, Kind: scope.KindLightActive},
		}); err != nil {
			t.Fatal(err)
		}
	}
	rules, err := st.Scopes.ListByProject(ctx(), p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 2 {
		t.Fatalf("ListByProject = %d, want 2", len(rules))
	}
}

func TestScopeDuplicatePattern(t *testing.T) {
	st := newTestStore(t)
	p := &project.Project{Name: "x", DefaultScope: scope.KindPassive, Mode: project.ModeCTF}
	_ = st.Projects.Save(ctx(), p)
	a := &scope.StoredRule{ProjectID: p.ID, Rule: scope.Rule{Pattern: "host.example.com", Kind: scope.KindLightActive}}
	b := &scope.StoredRule{ProjectID: p.ID, Rule: scope.Rule{Pattern: "host.example.com", Kind: scope.KindFullActive}}
	if err := st.Scopes.Add(ctx(), a); err != nil {
		t.Fatal(err)
	}
	if err := st.Scopes.Add(ctx(), b); !errors.Is(err, scope.ErrDuplicate) {
		t.Fatalf("got %v, want ErrDuplicate", err)
	}
}

func TestScopeCascadeOnProjectDelete(t *testing.T) {
	st := newTestStore(t)
	p := &project.Project{Name: "x", DefaultScope: scope.KindPassive, Mode: project.ModeCTF}
	_ = st.Projects.Save(ctx(), p)
	_ = st.Scopes.Add(ctx(), &scope.StoredRule{
		ProjectID: p.ID, Rule: scope.Rule{Pattern: "*.example.com", Kind: scope.KindLightActive},
	})
	if err := st.Projects.Delete(ctx(), p.ID); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := st.DB.QueryRowContext(ctx(), `SELECT count(*) FROM scope_rules`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("FK cascade failed: %d rows remain", n)
	}
}

func TestRunRoundTripWithParameters(t *testing.T) {
	st := newTestStore(t)
	p := &project.Project{Name: "x", DefaultScope: scope.KindPassive, Mode: project.ModeAssessment}
	_ = st.Projects.Save(ctx(), p)

	ru := &run.Run{
		ProjectID:  p.ID,
		Phase:      workflow.PhaseOSINT,
		Status:     run.StatusRunning,
		Label:      "first sweep",
		Parameters: map[string]any{"depth": float64(2), "tools": []any{"crtsh", "dnsx"}},
	}
	if err := st.Runs.Save(ctx(), ru); err != nil {
		t.Fatal(err)
	}
	got, err := st.Runs.Get(ctx(), ru.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Phase != workflow.PhaseOSINT || got.Status != run.StatusRunning {
		t.Fatalf("phase/status round-trip: %+v", got)
	}
	if got.Parameters["depth"] != float64(2) {
		t.Fatalf("parameters JSON did not round-trip: %+v", got.Parameters)
	}
}

func TestRunListByProjectNewestFirst(t *testing.T) {
	st := newTestStore(t)
	p := &project.Project{Name: "x", DefaultScope: scope.KindPassive, Mode: project.ModeAssessment}
	_ = st.Projects.Save(ctx(), p)
	var ids []string
	for _, phase := range []workflow.Phase{workflow.PhaseOSINT, workflow.PhaseAssetDiscovery, workflow.PhaseValidation} {
		ru := &run.Run{ProjectID: p.ID, Phase: phase, Status: run.StatusCompleted}
		if err := st.Runs.Save(ctx(), ru); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, ru.ID)
		time.Sleep(2 * time.Millisecond)
	}
	list, err := st.Runs.ListByProject(ctx(), p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 3 || list[0].ID != ids[2] {
		t.Fatalf("newest-first wrong: got %s, want %s (full=%+v)", list[0].ID, ids[2], list)
	}
}

func TestToolExecutionRoundTrip(t *testing.T) {
	st := newTestStore(t)
	p := &project.Project{Name: "x", DefaultScope: scope.KindPassive, Mode: project.ModeAssessment}
	_ = st.Projects.Save(ctx(), p)
	ru := &run.Run{ProjectID: p.ID, Phase: workflow.PhaseOSINT, Status: run.StatusRunning}
	_ = st.Runs.Save(ctx(), ru)
	tx := &run.ToolExecution{
		RunID: ru.ID, Tool: "crtsh", Status: run.ToolStatusCompleted,
		EntitiesEmitted: 7, EvidenceEmitted: 3, FindingsEmitted: 1,
		Result: map[string]any{"raw_count": float64(42)},
	}
	if err := st.Runs.SaveToolExecution(ctx(), tx); err != nil {
		t.Fatal(err)
	}
	list, err := st.Runs.ListToolExecutions(ctx(), ru.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].Tool != "crtsh" || list[0].EntitiesEmitted != 7 {
		t.Fatalf("round trip: %+v", list)
	}
	if list[0].Result["raw_count"] != float64(42) {
		t.Fatalf("result JSON didn't round-trip: %+v", list[0].Result)
	}
}

func TestToolExecutionRejectsUnknownRun(t *testing.T) {
	st := newTestStore(t)
	tx := &run.ToolExecution{RunID: "ghost", Tool: "crtsh", Status: run.ToolStatusPending}
	if err := st.Runs.SaveToolExecution(ctx(), tx); !errors.Is(err, run.ErrNotFound) {
		t.Fatalf("got %v, want ErrNotFound", err)
	}
}

func TestForeignKeyCascade(t *testing.T) {
	// Deleting a run should drop tool_executions too (FK ON DELETE
	// CASCADE), which requires PRAGMA foreign_keys = ON from Open.
	st := newTestStore(t)
	p := &project.Project{Name: "x", DefaultScope: scope.KindPassive, Mode: project.ModeAssessment}
	_ = st.Projects.Save(ctx(), p)
	ru := &run.Run{ProjectID: p.ID, Phase: workflow.PhaseOSINT, Status: run.StatusRunning}
	_ = st.Runs.Save(ctx(), ru)
	_ = st.Runs.SaveToolExecution(ctx(), &run.ToolExecution{
		RunID: ru.ID, Tool: "crtsh", Status: run.ToolStatusCompleted,
	})
	if err := st.Runs.Delete(ctx(), ru.ID); err != nil {
		t.Fatal(err)
	}
	var n int
	_ = st.DB.QueryRowContext(ctx(), `SELECT count(*) FROM tool_executions`).Scan(&n)
	if n != 0 {
		t.Fatalf("tool_executions cascade failed: %d rows remain", n)
	}
}

func TestNullableColumnsRoundTripAsEmpty(t *testing.T) {
	// Empty description / organization / label must be stored as NULL
	// (matching Python) and surfaced as "" on read.
	st := newTestStore(t)
	p := &project.Project{Name: "x", DefaultScope: scope.KindPassive, Mode: project.ModeAssessment}
	_ = st.Projects.Save(ctx(), p)
	var desc sql.NullString
	_ = st.DB.QueryRowContext(ctx(), `SELECT description FROM projects WHERE id = ?`, p.ID).Scan(&desc)
	if desc.Valid {
		t.Fatalf("empty description should store NULL, got %q", desc.String)
	}
}
