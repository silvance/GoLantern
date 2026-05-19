package workflow

import (
	"context"
	"fmt"

	"github.com/silvance/golantern/internal/project"
	"github.com/silvance/golantern/internal/scope"
)

// LoadPolicy resolves the scope policy for projectID by reading the
// project's default_scope and its rule list.
//
// Mirrors lantern.workflow.scope.load_scope_policy. Splitting it into a
// free function rather than putting it on either repository keeps the
// two repos decoupled and lets callers swap in fakes for tests
// independently. The function is in `workflow` because it spans both
// domains (project + scope); putting it in either domain would make
// that domain depend on the other.
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
