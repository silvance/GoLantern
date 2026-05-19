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

	// relations indexed by (src_id, dst_id, kind) -- the same UNIQUE
	// triple SQLite's schema declares -- so duplicate-insert is an
	// O(1) check.
	relByID   map[string]*entity.Relation
	relByKey  map[string]string // "src|dst|kind" -> id
	relByProj map[string][]string
}

func NewEntityRepo() *EntityRepo {
	return &EntityRepo{
		byID:      make(map[string]*entity.Entity),
		byKey:     make(map[string]string),
		byProj:    make(map[string][]string),
		relByID:   make(map[string]*entity.Relation),
		relByKey:  make(map[string]string),
		relByProj: make(map[string][]string),
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

// CreateRelation persists a directed edge. Enforces same-project on
// both endpoints (matching the SQLite FK + the Python flush hook) and
// is idempotent on the (src, dst, kind) triple.
func (r *EntityRepo) CreateRelation(_ context.Context, rel *entity.Relation) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	src, hasSrc := r.byID[rel.SrcID]
	dst, hasDst := r.byID[rel.DstID]
	if !hasSrc || !hasDst {
		return entity.ErrNotFound
	}
	if src.ProjectID != rel.ProjectID || dst.ProjectID != rel.ProjectID {
		return entity.ErrCrossProject
	}

	key := rel.SrcID + "|" + rel.DstID + "|" + string(rel.Kind)
	if existing, ok := r.relByKey[key]; ok {
		// Idempotent: merge attributes into the existing row rather
		// than failing. Mirrors the Python optimistic-insert pattern
		// which catches IntegrityError and treats it as already-present.
		if len(rel.Attributes) > 0 {
			r.relByID[existing].Attributes = fact.MergeAttributes(
				r.relByID[existing].Attributes, rel.Attributes,
			)
		}
		return nil
	}
	if rel.ID == "" {
		rel.ID = id.New()
	}
	clone := *rel
	clone.Attributes = copyMap(rel.Attributes)
	r.relByID[rel.ID] = &clone
	r.relByKey[key] = rel.ID
	r.relByProj[rel.ProjectID] = append(r.relByProj[rel.ProjectID], rel.ID)
	return nil
}

func (r *EntityRepo) ListRelationsByProject(_ context.Context, projectID string) ([]*entity.Relation, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	ids := r.relByProj[projectID]
	out := make([]*entity.Relation, 0, len(ids))
	for _, rid := range ids {
		clone := *r.relByID[rid]
		clone.Attributes = copyMap(clone.Attributes)
		out = append(out, &clone)
	}
	return out, nil
}

var _ entity.Repository = (*EntityRepo)(nil)
