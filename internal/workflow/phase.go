// Package workflow holds the phase graph and per-mode posture presets.
// Pure types and pure functions; no DB and no I/O. The phase-execution
// orchestrator (the equivalent of Python's WorkflowEngine) lives in
// internal/workflow/engine.go in a later phase.
package workflow

// Phase is one workflow stage. Mirrors lantern.models.runs.PhaseState.
// String values are wire format.
type Phase string

const (
	PhaseScope          Phase = "scope"
	PhaseOSINT          Phase = "osint"
	PhaseAssetDiscovery Phase = "asset_discovery"
	PhaseValidation     Phase = "validation"
	PhaseExposure       Phase = "exposure"
	PhaseEnrichment     Phase = "enrichment"
	PhaseReview         Phase = "review"
	PhaseReporting      Phase = "reporting"
)

// AllPhases is the canonical ordering, useful for UI listings.
var AllPhases = []Phase{
	PhaseScope,
	PhaseOSINT,
	PhaseAssetDiscovery,
	PhaseValidation,
	PhaseExposure,
	PhaseEnrichment,
	PhaseReview,
	PhaseReporting,
}

// Valid reports whether p is one of the defined phases.
func (p Phase) Valid() bool {
	for _, q := range AllPhases {
		if p == q {
			return true
		}
	}
	return false
}

// prerequisites maps each phase to the phases that must have at least
// one COMPLETED run before it may start. REVIEW is a merge point:
// both EXPOSURE and ENRICHMENT branches must have completed (a project
// that legitimately skipped one branch marks the corresponding phase
// COMPLETED with an empty Run, as in Python).
var prerequisites = map[Phase][]Phase{
	PhaseScope:          nil,
	PhaseOSINT:          {PhaseScope},
	PhaseAssetDiscovery: {PhaseScope},
	PhaseValidation:     {PhaseAssetDiscovery},
	PhaseExposure:       {PhaseValidation},
	PhaseEnrichment:     {PhaseValidation},
	PhaseReview:         {PhaseExposure, PhaseEnrichment},
	PhaseReporting:      {PhaseReview},
}

// Prerequisites returns the phases that must be completed before p can
// start. The returned slice is a copy; callers may mutate it.
//
// Returning a fresh slice (rather than the underlying value) is a
// defensive choice: the prerequisite graph is a package invariant and
// must not be mutated by callers.
func Prerequisites(p Phase) []Phase {
	src := prerequisites[p]
	if len(src) == 0 {
		return nil
	}
	out := make([]Phase, len(src))
	copy(out, src)
	return out
}

// AllowedNextPhases returns phases whose prerequisites are all in
// completed. Mirrors lantern.workflow.phases.allowed_next_phases.
//
// Phases already in completed are excluded from the result — re-running
// an already-completed phase is not "next" work, it's a separate Run.
func AllowedNextPhases(completed map[Phase]bool) []Phase {
	out := make([]Phase, 0, len(prerequisites))
	for _, p := range AllPhases {
		if completed[p] {
			continue
		}
		ok := true
		for _, pr := range prerequisites[p] {
			if !completed[pr] {
				ok = false
				break
			}
		}
		if ok {
			out = append(out, p)
		}
	}
	return out
}
