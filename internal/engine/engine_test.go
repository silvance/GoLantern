package engine_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/silvance/golantern/internal/engine"
	"github.com/silvance/golantern/internal/project"
	"github.com/silvance/golantern/internal/run"
	"github.com/silvance/golantern/internal/scope"
	"github.com/silvance/golantern/internal/store/memory"
	"github.com/silvance/golantern/internal/workflow"
)

func newStore(t *testing.T, mode project.Mode) (*memory.Store, *project.Project) {
	t.Helper()
	st := memory.New()
	p := &project.Project{Name: "X", DefaultScope: scope.KindPassive, Mode: mode}
	if err := st.Projects.Save(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	return st, p
}

func TestLoadPolicyJoinsRepos(t *testing.T) {
	st, p := newStore(t, project.ModeAssessment)
	for _, pat := range []string{"*.example.com", "api.example.com"} {
		if err := st.Scopes.Add(context.Background(), &scope.StoredRule{
			ProjectID: p.ID, Rule: scope.Rule{Pattern: pat, Kind: scope.KindFullActive},
		}); err != nil {
			t.Fatal(err)
		}
	}
	pol, err := engine.LoadPolicy(context.Background(), st.Projects, st.Scopes, p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got := pol.MatchedScope("api.example.com"); got != scope.KindFullActive {
		t.Fatalf("MatchedScope = %v, want full_active", got)
	}
	if got := pol.MatchedScope("unrelated.test"); got != scope.KindPassive {
		t.Fatalf("default fallthrough = %v", got)
	}
}

func TestLoadPolicyMissingProjectPropagates(t *testing.T) {
	st := memory.New()
	_, err := engine.LoadPolicy(context.Background(), st.Projects, st.Scopes, "ghost")
	if !errors.Is(err, project.ErrNotFound) {
		t.Fatalf("got %v, want chain ending in project.ErrNotFound", err)
	}
}

func TestCanStartPhaseCTFShortCircuits(t *testing.T) {
	st, p := newStore(t, project.ModeCTF)
	for _, ph := range workflow.AllPhases {
		ok, reason, err := engine.CanStartPhase(
			context.Background(), st.Projects, st.Scopes, st.Runs, p.ID, ph,
		)
		if err != nil {
			t.Fatalf("phase %s: %v", ph, err)
		}
		if !ok {
			t.Fatalf("CTF should short-circuit, but phase %s blocked: %s", ph, reason)
		}
	}
}

func TestCanStartPhaseScopeSatisfiedByRule(t *testing.T) {
	st, p := newStore(t, project.ModeAssessment)
	ok, reason, err := engine.CanStartPhase(
		context.Background(), st.Projects, st.Scopes, st.Runs, p.ID, workflow.PhaseOSINT,
	)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("OSINT should be blocked on a scope-less project")
	}
	if !strings.Contains(reason, "scope rule") {
		t.Fatalf("expected scope-rule hint in reason; got %q", reason)
	}

	if err := st.Scopes.Add(context.Background(), &scope.StoredRule{
		ProjectID: p.ID, Rule: scope.Rule{Pattern: "*.example.com", Kind: scope.KindLightActive},
	}); err != nil {
		t.Fatal(err)
	}
	ok, _, _ = engine.CanStartPhase(
		context.Background(), st.Projects, st.Scopes, st.Runs, p.ID, workflow.PhaseOSINT,
	)
	if !ok {
		t.Fatal("OSINT should unlock once a scope rule exists")
	}
}

func TestCanStartPhaseChainsThroughCompletedRuns(t *testing.T) {
	st, p := newStore(t, project.ModeAssessment)
	_ = st.Scopes.Add(context.Background(), &scope.StoredRule{
		ProjectID: p.ID, Rule: scope.Rule{Pattern: "*.example.com", Kind: scope.KindLightActive},
	})

	ok, reason, _ := engine.CanStartPhase(
		context.Background(), st.Projects, st.Scopes, st.Runs, p.ID, workflow.PhaseValidation,
	)
	if ok {
		t.Fatal("VALIDATION should be blocked without an AD completion")
	}
	if !strings.Contains(reason, "asset_discovery") {
		t.Fatalf("missing prereq should mention asset_discovery; got %q", reason)
	}

	_ = st.Runs.Save(context.Background(), &run.Run{
		ProjectID: p.ID, Phase: workflow.PhaseAssetDiscovery, Status: run.StatusCompleted,
	})
	ok, _, _ = engine.CanStartPhase(
		context.Background(), st.Projects, st.Scopes, st.Runs, p.ID, workflow.PhaseValidation,
	)
	if !ok {
		t.Fatal("VALIDATION should unlock with a completed AD run")
	}
}

func TestCanStartPhaseReviewMergePoint(t *testing.T) {
	st, p := newStore(t, project.ModeAssessment)
	_ = st.Scopes.Add(context.Background(), &scope.StoredRule{
		ProjectID: p.ID, Rule: scope.Rule{Pattern: "*.example.com", Kind: scope.KindLightActive},
	})
	for _, ph := range []workflow.Phase{
		workflow.PhaseAssetDiscovery, workflow.PhaseValidation, workflow.PhaseExposure,
	} {
		_ = st.Runs.Save(context.Background(), &run.Run{
			ProjectID: p.ID, Phase: ph, Status: run.StatusCompleted,
		})
	}
	ok, reason, _ := engine.CanStartPhase(
		context.Background(), st.Projects, st.Scopes, st.Runs, p.ID, workflow.PhaseReview,
	)
	if ok {
		t.Fatal("REVIEW must wait for ENRICHMENT")
	}
	if !strings.Contains(reason, "enrichment") {
		t.Fatalf("reason should mention enrichment: %q", reason)
	}

	_ = st.Runs.Save(context.Background(), &run.Run{
		ProjectID: p.ID, Phase: workflow.PhaseEnrichment, Status: run.StatusCompleted,
	})
	ok, _, _ = engine.CanStartPhase(
		context.Background(), st.Projects, st.Scopes, st.Runs, p.ID, workflow.PhaseReview,
	)
	if !ok {
		t.Fatal("REVIEW should unlock once both branches complete")
	}
}
