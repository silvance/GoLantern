package workflow

import (
	"reflect"
	"slices"
	"testing"
)

func TestAllPhasesValid(t *testing.T) {
	for _, p := range AllPhases {
		if !p.Valid() {
			t.Fatalf("%q in AllPhases must be Valid()", p)
		}
	}
	if Phase("bogus").Valid() {
		t.Fatal("Phase(bogus) should not be valid")
	}
}

func TestPrerequisitesGraph(t *testing.T) {
	cases := []struct {
		phase Phase
		want  []Phase
	}{
		{PhaseScope, nil},
		{PhaseOSINT, []Phase{PhaseScope}},
		{PhaseAssetDiscovery, []Phase{PhaseScope}},
		{PhaseValidation, []Phase{PhaseAssetDiscovery}},
		{PhaseExposure, []Phase{PhaseValidation}},
		{PhaseEnrichment, []Phase{PhaseValidation}},
		{PhaseReview, []Phase{PhaseExposure, PhaseEnrichment}},
		{PhaseReporting, []Phase{PhaseReview}},
	}
	for _, c := range cases {
		got := Prerequisites(c.phase)
		if !reflect.DeepEqual(got, c.want) {
			t.Fatalf("Prerequisites(%s) = %v, want %v", c.phase, got, c.want)
		}
	}
}

func TestPrerequisitesReturnsCopy(t *testing.T) {
	// Mutating the returned slice must not corrupt the package's graph.
	got := Prerequisites(PhaseReview)
	if len(got) != 2 {
		t.Fatalf("setup: want 2 prereqs, got %d", len(got))
	}
	got[0] = PhaseScope
	again := Prerequisites(PhaseReview)
	if again[0] == PhaseScope {
		t.Fatal("internal prerequisite slice was mutated")
	}
}

func TestAllowedNextPhasesEmpty(t *testing.T) {
	// Nothing completed → only SCOPE is eligible (no prereqs).
	got := AllowedNextPhases(nil)
	want := []Phase{PhaseScope}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("AllowedNextPhases(empty) = %v, want %v", got, want)
	}
}

func TestAllowedNextPhasesProgress(t *testing.T) {
	completed := map[Phase]bool{
		PhaseScope:          true,
		PhaseOSINT:          true,
		PhaseAssetDiscovery: true,
		PhaseValidation:     true,
	}
	got := AllowedNextPhases(completed)
	// After VALIDATION: EXPOSURE and ENRICHMENT unlock (both require VALIDATION).
	// REVIEW needs both branches; REPORTING needs REVIEW.
	if !slices.Contains(got, PhaseExposure) || !slices.Contains(got, PhaseEnrichment) {
		t.Fatalf("post-validation should unlock exposure+enrichment; got %v", got)
	}
	if slices.Contains(got, PhaseReview) {
		t.Fatalf("REVIEW should not unlock until both branches complete; got %v", got)
	}
	if slices.Contains(got, PhaseScope) || slices.Contains(got, PhaseValidation) {
		t.Fatalf("already-completed phases should not be next; got %v", got)
	}
}

func TestAllowedNextPhasesMergePoint(t *testing.T) {
	// One branch completed isn't enough.
	c1 := map[Phase]bool{
		PhaseScope: true, PhaseAssetDiscovery: true,
		PhaseValidation: true, PhaseExposure: true,
	}
	if slices.Contains(AllowedNextPhases(c1), PhaseReview) {
		t.Fatal("REVIEW must wait for both EXPOSURE and ENRICHMENT")
	}

	// Both branches completed → REVIEW unlocks.
	c2 := map[Phase]bool{
		PhaseScope: true, PhaseAssetDiscovery: true,
		PhaseValidation: true, PhaseExposure: true, PhaseEnrichment: true,
	}
	if !slices.Contains(AllowedNextPhases(c2), PhaseReview) {
		t.Fatal("REVIEW must unlock after both branches")
	}
}
