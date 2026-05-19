// Package engine holds orchestration glue that spans multiple domains
// — currently scope-policy assembly and phase-prerequisite checks. It
// imports every domain package and is imported only by the API layer.
//
// Why not put these on the workflow package? workflow declares Phase,
// which run imports for run.Run.Phase. If workflow also imported run
// (to consult completed-run state for CanStartPhase) we'd have a
// cycle. engine sits one level higher and observes both.
package engine

import (
	"context"
	"errors"
	"fmt"

	"github.com/silvance/golantern/internal/project"
	"github.com/silvance/golantern/internal/run"
	"github.com/silvance/golantern/internal/scope"
	"github.com/silvance/golantern/internal/workflow"
)

// ErrPrereqUnmet is returned by CanStartPhase when phase prerequisites
// are not yet satisfied. Callable from errors.Is at handler boundaries.
var ErrPrereqUnmet = errors.New("engine: phase prerequisites not yet completed")

// LoadPolicy resolves the scope policy for projectID by reading the
// project's default_scope and its rule list.
//
// Mirrors lantern.workflow.scope.load_scope_policy. Splitting it into
// a free function rather than putting it on either repository keeps
// the two repos decoupled and lets callers swap in fakes for tests
// independently.
func LoadPolicy(
	ctx context.Context,
	projects project.Repository,
	scopes scope.Repository,
	projectID string,
) (*scope.Policy, error) {
	p, err := projects.Get(ctx, projectID)
	if err != nil {
		return nil, fmt.Errorf("load scope policy: %w", err)
	}
	stored, err := scopes.ListByProject(ctx, projectID)
	if err != nil {
		return nil, fmt.Errorf("load scope policy: list rules: %w", err)
	}
	rules := make([]scope.Rule, len(stored))
	for i, s := range stored {
		rules[i] = s.Rule
	}
	pol, err := scope.Compile(p.ID, p.DefaultScope, rules)
	if err != nil {
		return nil, fmt.Errorf("load scope policy: compile: %w", err)
	}
	return pol, nil
}

// CanStartPhase reports whether projectID may start phase. Returns
// (true, "", nil) when allowed; (false, reason, nil) when blocked by a
// missing prerequisite; or (false, "", err) for infra errors.
//
// Mirrors WorkflowEngine.can_start_phase in lantern/workflow/engine.py
// including the two non-obvious special cases:
//
//   - CTF mode short-circuits the phase gate. Operators declared the
//     project is a lab/CTF target; mode is the affirmative signal.
//     Scope rules still gate at run time inside the runner.
//   - SCOPE is satisfied when the project has at least one ScopeRule
//     rather than a COMPLETED scope-phase run. SCOPE has no collectors;
//     without this special case every fresh project deadlocks on
//     "phase osint cannot start: prerequisites ['scope'] not yet
//     completed".
//
// The reason string is human-readable and suitable as an HTTP 409 body.
// It does not leak internal state beyond the names of unmet phases.
func CanStartPhase(
	ctx context.Context,
	projects project.Repository,
	scopes scope.Repository,
	runs run.Repository,
	projectID string,
	phase workflow.Phase,
) (ok bool, reason string, err error) {
	p, err := projects.Get(ctx, projectID)
	if err != nil {
		return false, "", err
	}
	// CTF short-circuit.
	if p.Mode == project.ModeCTF {
		return true, "", nil
	}

	prereqs := workflow.Prerequisites(phase)
	if len(prereqs) == 0 {
		return true, "", nil
	}

	completed, err := completedPhasesFor(ctx, runs, projectID)
	if err != nil {
		return false, "", err
	}

	// SCOPE prereq shortcut: any ScopeRule satisfies SCOPE.
	needsScope := false
	for _, pr := range prereqs {
		if pr == workflow.PhaseScope && !completed[workflow.PhaseScope] {
			needsScope = true
			break
		}
	}
	if needsScope {
		rules, err := scopes.ListByProject(ctx, projectID)
		if err != nil {
			return false, "", err
		}
		if len(rules) > 0 {
			completed[workflow.PhaseScope] = true
		}
	}

	var missing []string
	for _, pr := range prereqs {
		if !completed[pr] {
			missing = append(missing, string(pr))
		}
	}
	if len(missing) == 0 {
		return true, "", nil
	}
	if len(missing) == 1 && missing[0] == string(workflow.PhaseScope) {
		// Friendlier message when SCOPE is the only thing missing,
		// matching Python's "add at least one scope rule first" copy.
		return false, fmt.Sprintf(
			"phase %s cannot start: add at least one scope rule first, "+
				"or create the project with mode=ctf to skip the phase gate",
			phase,
		), nil
	}
	return false, fmt.Sprintf(
		"phase %s cannot start: prerequisites %v not yet completed",
		phase, missing,
	), nil
}

func completedPhasesFor(
	ctx context.Context,
	runs run.Repository,
	projectID string,
) (map[workflow.Phase]bool, error) {
	list, err := runs.ListByProject(ctx, projectID)
	if err != nil {
		return nil, err
	}
	out := make(map[workflow.Phase]bool, len(list))
	for _, ru := range list {
		if ru.Status == run.StatusCompleted {
			out[ru.Phase] = true
		}
	}
	return out, nil
}
