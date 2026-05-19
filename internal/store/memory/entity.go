package memory

import (
	"context"
	"sync"

	"github.com/silvance/golantern/internal/entity"
	"github.com/silvance/golantern/internal/fact"
	"github.com/silvance/golantern/internal/id"
)

// EntityRepo is the in-memory entity.Repository.
//
// Dedup keys on (projectID, kind, canonicalValue) and merges attributes
// per fact.MergeAttributes semantics on Upsert. Implementations of the
// repository must agree on the merge contract; using the fact.* helper
// in both stores keeps that pinned.
type EntityRepo struct {
	mu     sync.RWMutex
	byID   map[string]*entity.Entity
	byKey  map[string]string // "projectID|kind|value" -> id
	byProj map[string][]string
}

func NewEntityRepo() *EntityRepo {
	return &EntityRepo{
		byID:   make(map[string]*entity.Entity),
		byKey:  make(map[string]string),
		byProj: make(map[string][]string),
	}
}

func (r *EntityRepo) Upsert(
	_ context.Context, projectID string, kind entity.Kind,
	canonicalValue string, attributes map[string]any,
) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	key := projectID + "|" + string(kind) + "|" + canonicalValue
	if existingID, ok := r.byKey[key]; ok {
		if len(attributes) > 0 {
			e := r.byID[existingID]
			e.Attributes = fact.MergeAttributes(e.Attributes, attributes)
		}
		return existingID, nil
	}
	e := &entity.Entity{
		ID:         id.New(),
		ProjectID:  projectID,
		Kind:       kind,
		Value:      canonicalValue,
		Attributes: copyMap(attributes),
	}
	r.byID[e.ID] = e
	r.byKey[key] = e.ID
	r.byProj[projectID] = append(r.byProj[projectID], e.ID)
	return e.ID, nil
}

func (r *EntityRepo) ListValuesByKind(_ context.Context, projectID string, kind entity.Kind) ([]string, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	ids := r.byProj[projectID]
	out := make([]string, 0, len(ids))
	for _, eid := range ids {
		e := r.byID[eid]
		if e.Kind == kind {
			out = append(out, e.Value)
		}
	}
	return out, nil
}

func (r *EntityRepo) ListByProject(_ context.Context, projectID string) ([]*entity.Entity, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	ids := r.byProj[projectID]
	out := make([]*entity.Entity, 0, len(ids))
	for _, eid := range ids {
		e := r.byID[eid]
		clone := *e
		// Attributes is a map; deep-copy so callers can't mutate the
		// store through the returned snapshot.
		clone.Attributes = copyMap(e.Attributes)
		out = append(out, &clone)
	}
	return out, nil
}

// Get is not on the Repository interface; tests use it to verify state
// without round-tripping through the public surface.
func (r *EntityRepo) Get(_ context.Context, entityID string) (*entity.Entity, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	e, ok := r.byID[entityID]
	if !ok {
		return nil, entity.ErrNotFound
	}
	clone := *e
	return &clone, nil
}

func copyMap(in map[string]any) map[string]any {
	if in == nil {
		return map[string]any{}
	}
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

var _ entity.Repository = (*EntityRepo)(nil)
