package memory

import (
	"context"
	"sync"
	"time"

	"github.com/silvance/golantern/internal/audit"
	"github.com/silvance/golantern/internal/id"
)

// AuditRepo is the in-memory audit.Repository. Rows are kept on a
// project bucket so List is O(N) over a project's history rather than
// the whole audit trail.
//
// Project deletion does NOT detach audit rows in the in-memory store —
// the SQL store handles that via ON DELETE SET NULL, and that's where
// the invariant is exercised. The in-memory variant exists for handler
// tests and the desktop dev loop, neither of which depends on the
// post-deletion linkage behaviour.
type AuditRepo struct {
	mu     sync.RWMutex
	byProj map[string][]*audit.LogEntry
}

func NewAuditRepo() *AuditRepo {
	return &AuditRepo{byProj: make(map[string][]*audit.LogEntry)}
}

func (r *AuditRepo) Record(_ context.Context, e *audit.LogEntry) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if e.ID == "" {
		e.ID = id.New()
	}
	if e.Actor == "" {
		e.Actor = "system"
	}
	if e.CreatedAt.IsZero() {
		e.CreatedAt = time.Now().UTC()
	}
	clone := *e
	r.byProj[e.ProjectID] = append(r.byProj[e.ProjectID], &clone)
	return nil
}

func (r *AuditRepo) ListByProject(_ context.Context, projectID string) ([]*audit.LogEntry, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	src := r.byProj[projectID]
	// Newest-first, matching the Python admin view default.
	out := make([]*audit.LogEntry, 0, len(src))
	for i := len(src) - 1; i >= 0; i-- {
		clone := *src[i]
		out = append(out, &clone)
	}
	return out, nil
}

var _ audit.Repository = (*AuditRepo)(nil)
