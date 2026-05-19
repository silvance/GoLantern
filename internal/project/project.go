// Package project holds the Project value type and posture-preset enum.
// It owns no I/O; the repository interface lives here but implementations
// live under internal/store.
//
// Ported from lantern.models.project. The Python module mixed the ORM
// row, the enums, and the relationship graph into one file. We split:
// scope rule kinds live in internal/scope (the matcher owns them), and
// the foreign-key graph is replaced with explicit repository methods.
package project

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/silvance/golantern/internal/scope"
)

// Mode is the project posture preset. Mirrors
// lantern.models.project.ProjectMode. The string values are wire format.
//
// Mode is a bias, not an enforcement layer: scope rules remain
// authoritative. See workflow.PresetFor for what changes per mode.
type Mode string

const (
	ModeAssessment Mode = "assessment"
	ModeBugBounty  Mode = "bug_bounty"
	ModeCTF        Mode = "ctf"
)

// Valid reports whether m is one of the defined modes. Unknown modes
// from the DB should be treated as data corruption, not silently
// coerced to a default.
func (m Mode) Valid() bool {
	switch m {
	case ModeAssessment, ModeBugBounty, ModeCTF:
		return true
	}
	return false
}

// Project is the in-memory representation of a project row. Timestamps
// belong to the storage layer; do not put created_at / updated_at here.
type Project struct {
	ID           string
	Name         string
	Description  string
	Organization string

	// DefaultScope is the authorization level applied when no specific
	// ScopeRule matches a target.
	DefaultScope scope.RuleKind

	// Mode biases the UI and report template; it does not relax scope.
	Mode Mode
}

// ErrInvalid is the sentinel for input-validation failures. Callers
// can use errors.Is to distinguish bad input from infra errors.
var ErrInvalid = errors.New("invalid project")

// ErrNotFound is returned by Repository.Get when no project matches the
// requested ID. Other repository methods may also return it (e.g.
// Delete of an absent id is a no-op-or-error decision left to the
// implementation; the in-memory store returns ErrNotFound).
var ErrNotFound = errors.New("project: not found")

// ErrDuplicate is returned by Repository.Save when a project name
// conflicts with an existing row (the Python schema declares Name
// UNIQUE; we preserve that invariant at the repository boundary).
var ErrDuplicate = errors.New("project: duplicate")

// Repository is the persistence contract for projects. Lives in this
// package (the consumer of the type) rather than in the storage layer
// so the domain owns the shape of its persistence calls.
//
// Save is upsert: it creates a row when ID is empty and updates when
// it isn't. Implementations are responsible for populating ID on
// create. This matches how the FastAPI handlers call WorkflowEngine /
// the session today and removes the "is this an insert or update?"
// branch from every caller.
type Repository interface {
	Get(ctx context.Context, id string) (*Project, error)
	List(ctx context.Context) ([]*Project, error)
	Save(ctx context.Context, p *Project) error
	Delete(ctx context.Context, id string) error
}

// Validate checks the invariants a Project must satisfy before being
// persisted. ID is populated by the store; an empty ID is fine at
// construction time.
//
// Constructor-side validation (rather than struct tags + a validator
// library) was a deliberate choice — the invariants are few enough
// that a function reads better than a tagged struct.
func (p *Project) Validate() error {
	if strings.TrimSpace(p.Name) == "" {
		return fmt.Errorf("%w: name is required", ErrInvalid)
	}
	if len(p.Name) > 256 {
		return fmt.Errorf("%w: name must be <= 256 chars", ErrInvalid)
	}
	if !p.DefaultScope.Valid() {
		return fmt.Errorf("%w: default_scope %q is not a known kind",
			ErrInvalid, p.DefaultScope)
	}
	if !p.Mode.Valid() {
		return fmt.Errorf("%w: mode %q is not a known mode",
			ErrInvalid, p.Mode)
	}
	return nil
}
