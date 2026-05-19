package memory

import (
	"context"
	"errors"
	"testing"

	"github.com/silvance/golantern/internal/project"
	"github.com/silvance/golantern/internal/run"
	"github.com/silvance/golantern/internal/scope"
	"github.com/silvance/golantern/internal/workflow"
)

func newCtx() context.Context { return context.Background() }

// ----- ProjectRepo -----------------------------------------------------

func TestProjectSaveAssignsIDAndIsListable(t *testing.T) {
	r := NewProjectRepo()
	p := &project.Project{Name: "Acme", DefaultScope: scope.KindPassive, Mode: project.ModeAssessment}
	if err := r.Save(newCtx(), p); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if p.ID == "" {
		t.Fatal("Save must assign an ID")
	}
	got, err := r.Get(newCtx(), p.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Name != "Acme" {
		t.Fatalf("Get returned wrong project: %+v", got)
	}
	list, err := r.List(newCtx())
	if err != nil || len(list) != 1 {
		t.Fatalf("List returned %d items, err=%v", len(list), err)
	}
}

func TestProjectGetMissingReturnsErrNotFound(t *testing.T) {
	r := NewProjectRepo()
	_, err := r.Get(newCtx(), "missing")
	if !errors.Is(err, project.ErrNotFound) {
		t.Fatalf("got %v, want ErrNotFound", err)
	}
}

func TestProjectSaveDuplicateNameRejected(t *testing.T) {
	r := NewProjectRepo()
	a := &project.Project{Name: "X", DefaultScope: scope.KindPassive, Mode: project.ModeCTF}
	b := &project.Project{Name: "X", DefaultScope: scope.KindPassive, Mode: project.ModeCTF}
	if err := r.Save(newCtx(), a); err != nil {
		t.Fatal(err)
	}
	if err := r.Save(newCtx(), b); !errors.Is(err, project.ErrDuplicate) {
		t.Fatalf("got %v, want ErrDuplicate", err)
	}
}

func TestProjectRenameUpdatesUniqueIndex(t *testing.T) {
	r := NewProjectRepo()
	p := &project.Project{Name: "old", DefaultScope: scope.KindPassive, Mode: project.ModeCTF}
	if err := r.Save(newCtx(), p); err != nil {
		t.Fatal(err)
	}
	p.Name = "new"
	if err := r.Save(newCtx(), p); err != nil {
		t.Fatalf("rename: %v", err)
	}
	// Adding a project with the old name now must succeed.
	q := &project.Project{Name: "old", DefaultScope: scope.KindPassive, Mode: project.ModeCTF}
	if err := r.Save(newCtx(), q); err != nil {
		t.Fatalf("reuse old name: %v", err)
	}
}

func TestProjectGetReturnsClone(t *testing.T) {
	// Mutating the returned struct must not affect the store.
	r := NewProjectRepo()
	p := &project.Project{Name: "X", DefaultScope: scope.KindPassive, Mode: project.ModeAssessment}
	_ = r.Save(newCtx(), p)
	got, _ := r.Get(newCtx(), p.ID)
	got.Name = "MUTATED"
	again, _ := r.Get(newCtx(), p.ID)
	if again.Name == "MUTATED" {
		t.Fatal("store returned a shared pointer; mutation leaked")
	}
}

func TestProjectDelete(t *testing.T) {
	r := NewProjectRepo()
	p := &project.Project{Name: "X", DefaultScope: scope.KindPassive, Mode: project.ModeCTF}
	_ = r.Save(newCtx(), p)
	if err := r.Delete(newCtx(), p.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if err := r.Delete(newCtx(), p.ID); !errors.Is(err, project.ErrNotFound) {
		t.Fatalf("second Delete should be ErrNotFound, got %v", err)
	}
}

// ----- ScopeRepo -------------------------------------------------------

func TestScopeAddListDelete(t *testing.T) {
	r := NewScopeRepo()
	sr := &scope.StoredRule{
		ProjectID: "proj1",
		Rule:      scope.Rule{Pattern: "*.example.com", Kind: scope.KindLightActive},
	}
	if err := r.Add(newCtx(), sr); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if sr.ID == "" {
		t.Fatal("Add must assign an ID")
	}
	list, _ := r.ListByProject(newCtx(), "proj1")
	if len(list) != 1 || list[0].Rule.Pattern != "*.example.com" {
		t.Fatalf("List = %+v", list)
	}
	if err := r.Delete(newCtx(), sr.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if list, _ := r.ListByProject(newCtx(), "proj1"); len(list) != 0 {
		t.Fatal("post-delete list should be empty")
	}
}

func TestScopeDuplicatePatternRejected(t *testing.T) {
	r := NewScopeRepo()
	first := &scope.StoredRule{ProjectID: "p1", Rule: scope.Rule{Pattern: "host.example.com", Kind: scope.KindLightActive}}
	dup := &scope.StoredRule{ProjectID: "p1", Rule: scope.Rule{Pattern: "host.example.com", Kind: scope.KindFullActive}}
	if err := r.Add(newCtx(), first); err != nil {
		t.Fatal(err)
	}
	if err := r.Add(newCtx(), dup); !errors.Is(err, scope.ErrDuplicate) {
		t.Fatalf("got %v, want ErrDuplicate", err)
	}
	// Same pattern under a different project must be allowed.
	otherProj := &scope.StoredRule{ProjectID: "p2", Rule: scope.Rule{Pattern: "host.example.com", Kind: scope.KindLightActive}}
	if err := r.Add(newCtx(), otherProj); err != nil {
		t.Fatalf("cross-project duplicate must be allowed: %v", err)
	}
}

// ----- RunRepo ---------------------------------------------------------

func TestRunSaveAndList(t *testing.T) {
	r := NewRunRepo()
	r1 := &run.Run{ProjectID: "p", Phase: workflow.PhaseOSINT, Status: run.StatusPending}
	r2 := &run.Run{ProjectID: "p", Phase: workflow.PhaseAssetDiscovery, Status: run.StatusPending}
	_ = r.Save(newCtx(), r1)
	_ = r.Save(newCtx(), r2)
	if r1.ID == "" || r2.ID == "" || r1.ID == r2.ID {
		t.Fatalf("ids: %q %q", r1.ID, r2.ID)
	}
	list, _ := r.ListByProject(newCtx(), "p")
	if len(list) != 2 {
		t.Fatalf("List = %d, want 2", len(list))
	}
	// Newest-first.
	if list[0].ID != r2.ID {
		t.Fatalf("newest-first ordering broken: got %s, want %s", list[0].ID, r2.ID)
	}
}

func TestRunGetReturnsClone(t *testing.T) {
	r := NewRunRepo()
	ru := &run.Run{ProjectID: "p", Phase: workflow.PhaseOSINT, Status: run.StatusPending}
	_ = r.Save(newCtx(), ru)
	got, _ := r.Get(newCtx(), ru.ID)
	got.Label = "MUTATED"
	again, _ := r.Get(newCtx(), ru.ID)
	if again.Label == "MUTATED" {
		t.Fatal("RunRepo returned a shared pointer; mutation leaked")
	}
}

func TestToolExecutionAttachedToRunAndCascades(t *testing.T) {
	r := NewRunRepo()
	ru := &run.Run{ProjectID: "p", Phase: workflow.PhaseOSINT, Status: run.StatusRunning}
	_ = r.Save(newCtx(), ru)
	tx := &run.ToolExecution{RunID: ru.ID, Tool: "crtsh", Status: run.ToolStatusPending}
	if err := r.SaveToolExecution(newCtx(), tx); err != nil {
		t.Fatal(err)
	}
	if tx.ID == "" {
		t.Fatal("SaveToolExecution must assign ID")
	}
	list, _ := r.ListToolExecutions(newCtx(), ru.ID)
	if len(list) != 1 || list[0].Tool != "crtsh" {
		t.Fatalf("ListToolExecutions = %+v", list)
	}
	// Delete the run cascades the tool execution.
	_ = r.Delete(newCtx(), ru.ID)
	list, _ = r.ListToolExecutions(newCtx(), ru.ID)
	if len(list) != 0 {
		t.Fatalf("post-delete tool executions = %d, want 0", len(list))
	}
}

func TestToolExecutionRejectsUnknownRun(t *testing.T) {
	r := NewRunRepo()
	tx := &run.ToolExecution{RunID: "ghost", Tool: "crtsh", Status: run.ToolStatusPending}
	if err := r.SaveToolExecution(newCtx(), tx); !errors.Is(err, run.ErrNotFound) {
		t.Fatalf("got %v, want ErrNotFound", err)
	}
}

// ----- workflow.LoadPolicy end-to-end ----------------------------------

func TestLoadPolicyJoinsProjectAndScopeRepos(t *testing.T) {
	st := New()
	p := &project.Project{Name: "x", DefaultScope: scope.KindPassive, Mode: project.ModeAssessment}
	if err := st.Projects.Save(newCtx(), p); err != nil {
		t.Fatal(err)
	}
	for _, pattern := range []string{"*.example.com", "api.example.com"} {
		if err := st.Scopes.Add(newCtx(), &scope.StoredRule{
			ProjectID: p.ID, Rule: scope.Rule{Pattern: pattern, Kind: scope.KindFullActive},
		}); err != nil {
			t.Fatal(err)
		}
	}
	pol, err := workflow.LoadPolicy(newCtx(), st.Projects, st.Scopes, p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got := pol.MatchedScope("api.example.com"); got != scope.KindFullActive {
		t.Fatalf("MatchedScope(api.example.com) = %v, want full_active", got)
	}
	// Default falls through to the project's default_scope.
	if got := pol.MatchedScope("unrelated.test"); got != scope.KindPassive {
		t.Fatalf("default fallthrough = %v, want passive", got)
	}
}

func TestLoadPolicyPropagatesProjectNotFound(t *testing.T) {
	st := New()
	_, err := workflow.LoadPolicy(newCtx(), st.Projects, st.Scopes, "missing")
	if !errors.Is(err, project.ErrNotFound) {
		t.Fatalf("got %v, want chain ending in project.ErrNotFound", err)
	}
}
