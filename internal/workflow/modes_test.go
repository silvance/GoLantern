package workflow

import (
	"slices"
	"testing"

	"github.com/silvance/golantern/internal/project"
	"github.com/silvance/golantern/internal/scope"
)

func TestPresetForCoversEveryMode(t *testing.T) {
	for _, m := range []project.Mode{project.ModeAssessment, project.ModeBugBounty, project.ModeCTF} {
		p := PresetFor(m)
		if p.ReportTemplate == "" {
			t.Fatalf("mode %q: ReportTemplate must be set", m)
		}
		if !p.SuggestedScopeKind.Valid() {
			t.Fatalf("mode %q: SuggestedScopeKind %q is not valid", m, p.SuggestedScopeKind)
		}
	}
}

func TestPresetForUnknownPanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("PresetFor with unknown mode should panic")
		}
	}()
	_ = PresetFor(project.Mode("bogus"))
}

func TestRecommendedToolsAssessment(t *testing.T) {
	got := RecommendedToolsForPhase(project.ModeAssessment, PhaseOSINT)
	want := []string{"crtsh", "theharvester"}
	if !slices.Equal(got, want) {
		t.Fatalf("assessment OSINT tools = %v, want %v", got, want)
	}
}

func TestRecommendedToolsBugBountyFullActive(t *testing.T) {
	if PresetFor(project.ModeBugBounty).SuggestedScopeKind != scope.KindFullActive {
		t.Fatal("bug_bounty must suggest full_active")
	}
}

func TestRecommendedToolsCTFEmptyForNonRelevantPhases(t *testing.T) {
	// CTF intentionally has no OSINT / ASSET_DISCOVERY / ENRICHMENT
	// recommendations. An empty result is the documented contract.
	if got := RecommendedToolsForPhase(project.ModeCTF, PhaseOSINT); len(got) != 0 {
		t.Fatalf("CTF OSINT should be empty, got %v", got)
	}
	if got := RecommendedToolsForPhase(project.ModeCTF, PhaseValidation); len(got) == 0 {
		t.Fatal("CTF VALIDATION should be non-empty")
	}
}

// TestGowitnessRecommendedAcrossModes documents that every mode's
// Validation phase suggests gowitness now that the artifact subsystem
// supports it. Operators on environments without artifact storage
// configured will still see the collector skip cleanly at runtime,
// but the recommendation makes the screenshot workflow discoverable.
func TestGowitnessRecommendedAcrossModes(t *testing.T) {
	for _, m := range []project.Mode{project.ModeAssessment, project.ModeBugBounty, project.ModeCTF} {
		tools := RecommendedToolsForPhase(m, PhaseValidation)
		if !slices.Contains(tools, "gowitness") {
			t.Errorf("mode %q Validation tools missing gowitness: %v", m, tools)
		}
	}
}

func TestRecommendedToolsReturnsCopy(t *testing.T) {
	got := RecommendedToolsForPhase(project.ModeAssessment, PhaseOSINT)
	if len(got) == 0 {
		t.Fatal("setup: expected non-empty")
	}
	got[0] = "MUTATED"
	again := RecommendedToolsForPhase(project.ModeAssessment, PhaseOSINT)
	if again[0] == "MUTATED" {
		t.Fatal("internal preset slice was mutated")
	}
}
