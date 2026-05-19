package memory

import (
	"context"
	"sync"

	"github.com/silvance/golantern/internal/finding"
	"github.com/silvance/golantern/internal/id"
)

// FindingRepo is the in-memory finding.Repository, also storing
// evidence rows. Both kinds share a repository so the runner can flush
// them together; tests can list each independently.
type FindingRepo struct {
	mu       sync.RWMutex
	findings map[string]*finding.Finding
	findOrd  map[string][]string // projectID -> finding IDs
	evidence map[string]*finding.Evidence
	evOrd    map[string][]string // projectID -> evidence IDs
}

func NewFindingRepo() *FindingRepo {
	return &FindingRepo{
		findings: make(map[string]*finding.Finding),
		findOrd:  make(map[string][]string),
		evidence: make(map[string]*finding.Evidence),
		evOrd:    make(map[string][]string),
	}
}

func (r *FindingRepo) CreateFinding(_ context.Context, f *finding.Finding) error {
	if f.ID == "" {
		f.ID = id.New()
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	clone := *f
	r.findings[f.ID] = &clone
	r.findOrd[f.ProjectID] = append(r.findOrd[f.ProjectID], f.ID)
	return nil
}

func (r *FindingRepo) CreateEvidence(_ context.Context, e *finding.Evidence) error {
	if e.ID == "" {
		e.ID = id.New()
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	clone := *e
	r.evidence[e.ID] = &clone
	r.evOrd[e.ProjectID] = append(r.evOrd[e.ProjectID], e.ID)
	return nil
}

func (r *FindingRepo) ListFindings(_ context.Context, projectID string) ([]*finding.Finding, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	ids := r.findOrd[projectID]
	out := make([]*finding.Finding, 0, len(ids))
	for _, fid := range ids {
		clone := *r.findings[fid]
		out = append(out, &clone)
	}
	return out, nil
}

func (r *FindingRepo) ListEvidence(_ context.Context, projectID string) ([]*finding.Evidence, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	ids := r.evOrd[projectID]
	out := make([]*finding.Evidence, 0, len(ids))
	for _, eid := range ids {
		clone := *r.evidence[eid]
		out = append(out, &clone)
	}
	return out, nil
}

var _ finding.Repository = (*FindingRepo)(nil)
