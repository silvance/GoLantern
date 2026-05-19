// Package run holds the Run and ToolExecution value types and their
// status enums. Pure types; no DB and no orchestration. The execution
// engine that drives runs through their states lives in
// internal/workflow/engine.go (later phase).
//
// Ported from lantern.models.runs. We deliberately keep the Run row
// independent of ORM mapping: timestamps and FKs are storage-layer
// concerns and live on the repository implementation, not on the
// in-memory struct.
package run

import (
	"context"
	"errors"
	"time"

	"github.com/silvance/golantern/internal/workflow"
)

// ErrNotFound is returned by Repository lookups that miss.
var ErrNotFound = errors.New("run: not found")

// Status is the lifecycle state of a Run.
type Status string

const (
	StatusPending   Status = "pending"
	StatusRunning   Status = "running"
	StatusCompleted Status = "completed"
	StatusFailed    Status = "failed"
	StatusCancelled Status = "cancelled"
)

// Valid reports whether s is one of the defined statuses.
func (s Status) Valid() bool {
	switch s {
	case StatusPending, StatusRunning, StatusCompleted, StatusFailed, StatusCancelled:
		return true
	}
	return false
}

// IsTerminal reports whether s is a final state (no further transitions
// allowed). The state machine permits any non-terminal status to move
// to any other non-terminal status; only the engine should ever set a
// terminal status.
func (s Status) IsTerminal() bool {
	switch s {
	case StatusCompleted, StatusFailed, StatusCancelled:
		return true
	}
	return false
}

// CanTransitionTo reports whether s -> next is a legal transition.
// Encodes the implicit state machine that's spread across Python's
// engine.py and runner.py:
//
//	PENDING   -> RUNNING | CANCELLED
//	RUNNING   -> COMPLETED | FAILED | CANCELLED
//	any terminal state -> nothing
//
// Same-state transitions (PENDING -> PENDING, etc.) are rejected on
// purpose: callers writing such code almost always mean something else.
func (s Status) CanTransitionTo(next Status) bool {
	if !next.Valid() || s.IsTerminal() || s == next {
		return false
	}
	switch s {
	case StatusPending:
		return next == StatusRunning || next == StatusCancelled
	case StatusRunning:
		return next == StatusCompleted || next == StatusFailed || next == StatusCancelled
	}
	return false
}

// ToolExecutionStatus is the lifecycle state of a single collector
// invocation inside a Run. Mirrors lantern's ToolExecutionStatus —
// it has one extra state (SkippedOutOfScope) that runs don't.
type ToolExecutionStatus string

const (
	ToolStatusPending           ToolExecutionStatus = "pending"
	ToolStatusRunning           ToolExecutionStatus = "running"
	ToolStatusCompleted         ToolExecutionStatus = "completed"
	ToolStatusFailed            ToolExecutionStatus = "failed"
	ToolStatusCancelled         ToolExecutionStatus = "cancelled"
	ToolStatusSkippedOutOfScope ToolExecutionStatus = "skipped_out_of_scope"
)

func (s ToolExecutionStatus) Valid() bool {
	switch s {
	case ToolStatusPending, ToolStatusRunning, ToolStatusCompleted,
		ToolStatusFailed, ToolStatusCancelled, ToolStatusSkippedOutOfScope:
		return true
	}
	return false
}

func (s ToolExecutionStatus) IsTerminal() bool {
	switch s {
	case ToolStatusCompleted, ToolStatusFailed, ToolStatusCancelled, ToolStatusSkippedOutOfScope:
		return true
	}
	return false
}

// Run is a logical batch of work within one Phase, possibly spanning
// many tool invocations.
//
// Parameters is the redacted invocation parameters as persisted (secrets
// already stripped — that's a security responsibility of the caller
// before it reaches this type, mirroring redact_parameters in Python).
// ErrorSummary is analyst-safe; ErrorDebug holds the full traceback and
// must never be exposed to non-debug callers.
type Run struct {
	ID         string
	ProjectID  string
	Phase      workflow.Phase
	Status     Status
	Label      string
	Parameters map[string]any
	StartedAt  *time.Time
	FinishedAt *time.Time

	ErrorSummary string
	ErrorDebug   string
}

// Repository persists Run and ToolExecution rows. The engine
// (later phase) uses this; HTTP handlers use it directly for reads.
//
// ListByProject orders newest-first to match the Python "Runs" UI; the
// in-memory store mirrors that and the SQLite store sorts by created_at
// DESC. Save is upsert: callers that need to distinguish create from
// update should check ID first.
type Repository interface {
	Get(ctx context.Context, id string) (*Run, error)
	ListByProject(ctx context.Context, projectID string) ([]*Run, error)
	Save(ctx context.Context, r *Run) error
	Delete(ctx context.Context, id string) error

	SaveToolExecution(ctx context.Context, tx *ToolExecution) error
	ListToolExecutions(ctx context.Context, runID string) ([]*ToolExecution, error)
}

// ToolExecution is one collector invocation inside a Run.
//
// The Python row carries entities_emitted / evidence_emitted /
// findings_emitted counters maintained by the runner. They live here as
// well so the runner has somewhere to put them; the repository
// implementation is responsible for updating them in the same
// transaction as the related entity / evidence / finding rows.
type ToolExecution struct {
	ID         string
	RunID      string
	Tool       string
	Status     ToolExecutionStatus
	Parameters map[string]any
	Result     map[string]any
	StartedAt  *time.Time
	FinishedAt *time.Time

	EntitiesEmitted int
	EvidenceEmitted int
	FindingsEmitted int

	ErrorSummary string
	ErrorDebug   string
}
