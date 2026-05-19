// Package audit records the append-only authorization trail.
//
// Mirrors lantern.audit and lantern.models.runs.AuditLog. Rows survive
// project deletion: project_id is set NULL by the FK so the trail of
// "who authorized what" remains reviewable after the project that the
// action targeted is gone. project_name_snapshot keeps a human-readable
// label on the row after the FK clears.
//
// The package is write-mostly from application code (handlers and the
// engine call Record); reads exist for the admin UI and reports.
package audit

import (
	"context"
	"errors"
	"time"
)

// Common action names. These are conventions, not enums — anything that
// records an authorization-relevant decision can pick a fresh string.
// We pre-declare the names this codebase emits so callers don't have to
// recall the exact spelling and so a typo in one place doesn't quietly
// emit a new "action" the audit dashboard never groups.
const (
	ActionScopeRuleCreated = "scope.rule_created"
	ActionScopeRuleDeleted = "scope.rule_deleted"
	ActionProjectCreated   = "project.created"
	ActionProjectUpdated   = "project.updated"
	ActionProjectDeleted   = "project.deleted"
	ActionRunCreated       = "run.created"
	ActionRunFinished      = "run.finished"
)

// LogEntry is one row of the audit trail. Detail is intentionally a
// map[string]any rather than a strongly-typed payload: every action has
// a different shape and we don't want a discriminated union per action
// just to keep the table writable.
type LogEntry struct {
	ID                  string
	ProjectID           string // empty when not project-scoped
	ProjectNameSnapshot string
	Actor               string // defaults to "system" at write time when empty
	Action              string
	Target              string
	Detail              map[string]any
	CreatedAt           time.Time
}

// ErrNotFound is returned by Repository lookups that miss. Audit log
// reads are rare but should still surface a sentinel rather than nil.
var ErrNotFound = errors.New("audit: not found")

// Repository persists audit-log rows. Implementations live in
// internal/store/*; handlers and the engine consume the interface.
//
// Record is the only write method. It mints an ID, stamps CreatedAt to
// time.Now if zero, and defaults Actor to "system" when empty. Reads
// are limited to per-project listing for now — global cross-project
// reporting can grow into a List(ctx) without breaking callers.
type Repository interface {
	Record(ctx context.Context, e *LogEntry) error
	ListByProject(ctx context.Context, projectID string) ([]*LogEntry, error)
}
