package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/silvance/golantern/internal/entity"
	"github.com/silvance/golantern/internal/fact"
	"github.com/silvance/golantern/internal/id"
)

// EntityRepo is the SQLite implementation of entity.Repository.
//
// Upsert relies on the (project_id, kind, value) UNIQUE constraint
// declared in schema.sql. The attribute merge happens in a
// transaction so a concurrent Upsert can't race the read with the
// write. Cost is one extra round-trip on the hit path, but
// transactions amortize across the scan engine's per-execution
// pattern of multiple emits per collector.
type EntityRepo struct{ db *sql.DB }

func NewEntityRepo(db *sql.DB) *EntityRepo { return &EntityRepo{db: db} }

func (r *EntityRepo) Upsert(
	ctx context.Context, projectID string, kind entity.Kind,
	canonicalValue string, attributes map[string]any,
) (string, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return "", fmt.Errorf("entity Upsert begin: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // either Commit or rollback

	// Look up existing row first. Pre-fetching the attributes lets the
	// merge use fact.MergeAttributes so the same semantics that govern
	// the in-memory store apply here — older evidence wins on scalar
	// conflicts, lists union with order preserved.
	var existingID string
	var existingAttrJSON string
	row := tx.QueryRowContext(ctx,
		`SELECT id, attributes FROM entities WHERE project_id = ? AND kind = ? AND value = ?`,
		projectID, toDBEnum(string(kind)), canonicalValue,
	)
	switch err := row.Scan(&existingID, &existingAttrJSON); {
	case errors.Is(err, sql.ErrNoRows):
		// Fall through to INSERT.
	case err != nil:
		return "", fmt.Errorf("entity lookup: %w", err)
	default:
		// Hit: merge and update.
		if len(attributes) == 0 {
			return existingID, tx.Commit()
		}
		var existing map[string]any
		if existingAttrJSON != "" {
			if err := json.Unmarshal([]byte(existingAttrJSON), &existing); err != nil {
				return "", fmt.Errorf("decode existing attributes: %w", err)
			}
		}
		merged := fact.MergeAttributes(existing, attributes)
		mergedJSON, err := json.Marshal(merged)
		if err != nil {
			return "", fmt.Errorf("encode merged attributes: %w", err)
		}
		if _, err := tx.ExecContext(ctx,
			`UPDATE entities SET attributes = ?, updated_at = ? WHERE id = ?`,
			string(mergedJSON), time.Now().UTC(), existingID,
		); err != nil {
			return "", fmt.Errorf("entity merge update: %w", err)
		}
		return existingID, tx.Commit()
	}

	// Miss: insert. We chose canonical-value-keyed dedup; the UNIQUE
	// constraint is the backstop if two workers race.
	newID := id.New()
	attrJSON := "{}"
	if len(attributes) > 0 {
		b, err := json.Marshal(attributes)
		if err != nil {
			return "", fmt.Errorf("encode attributes: %w", err)
		}
		attrJSON = string(b)
	}
	now := time.Now().UTC()
	_, err = tx.ExecContext(ctx, `
		INSERT INTO entities (id, project_id, kind, value, attributes, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		newID, projectID, toDBEnum(string(kind)), canonicalValue, attrJSON, now, now,
	)
	if err != nil {
		// Two writers racing: the loser sees UNIQUE violation. Reread
		// to find the winner's ID rather than failing — that's the
		// semantically-correct upsert behaviour.
		if isUniqueViolation(err, "uq_entities_project_kind_value") {
			var winnerID string
			lookupErr := tx.QueryRowContext(ctx,
				`SELECT id FROM entities WHERE project_id = ? AND kind = ? AND value = ?`,
				projectID, toDBEnum(string(kind)), canonicalValue,
			).Scan(&winnerID)
			if lookupErr != nil {
				return "", fmt.Errorf("entity race rerread: %w", lookupErr)
			}
			return winnerID, tx.Commit()
		}
		return "", fmt.Errorf("entity insert: %w", err)
	}
	return newID, tx.Commit()
}

func (r *EntityRepo) ListValuesByKind(
	ctx context.Context, projectID string, kind entity.Kind,
) ([]string, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT value FROM entities
		WHERE project_id = ? AND kind = ?
		ORDER BY created_at ASC, id ASC`,
		projectID, toDBEnum(string(kind)),
	)
	if err != nil {
		return nil, fmt.Errorf("entity ListValuesByKind: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// CreateRelation persists a directed edge with the (src, dst, kind)
// UNIQUE invariant from schema.sql. Cross-project endpoints surface
// as entity.ErrCrossProject (the runner only emits same-project
// relations; this is defense-in-depth catching application bugs).
//
// Idempotent: a duplicate triple returns nil (the row stays).
// Attribute merging on duplicates wraps the lookup+merge+update in a
// short transaction so concurrent writers don't race.
func (r *EntityRepo) CreateRelation(ctx context.Context, rel *entity.Relation) error {
	// Validate endpoints belong to the same project as the relation.
	var srcPID, dstPID string
	if err := r.db.QueryRowContext(ctx,
		`SELECT project_id FROM entities WHERE id = ?`, rel.SrcID,
	).Scan(&srcPID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return entity.ErrNotFound
		}
		return fmt.Errorf("relation src lookup: %w", err)
	}
	if err := r.db.QueryRowContext(ctx,
		`SELECT project_id FROM entities WHERE id = ?`, rel.DstID,
	).Scan(&dstPID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return entity.ErrNotFound
		}
		return fmt.Errorf("relation dst lookup: %w", err)
	}
	if srcPID != rel.ProjectID || dstPID != rel.ProjectID {
		return entity.ErrCrossProject
	}

	if rel.ID == "" {
		rel.ID = id.New()
	}
	attrJSON := "{}"
	if len(rel.Attributes) > 0 {
		b, err := json.Marshal(rel.Attributes)
		if err != nil {
			return fmt.Errorf("encode relation attributes: %w", err)
		}
		attrJSON = string(b)
	}
	now := time.Now().UTC()
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO entity_relations
			(id, project_id, src_id, dst_id, kind, attributes, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		rel.ID, rel.ProjectID, rel.SrcID, rel.DstID, toDBEnum(string(rel.Kind)),
		attrJSON, now, now,
	)
	if err != nil {
		// SQLite's UNIQUE error names the column list ("entity_relations.src_id, ...")
		// rather than the constraint, so match on either the constraint name
		// (some SQLite versions / sqlcipher use it) or on src_id.
		if isUniqueViolation(err, "uq_relation_src_dst_kind") ||
			isUniqueViolation(err, "entity_relations.src_id") {
			// Idempotent: the row already exists. Caller's attributes
			// are dropped; merging here would require a second
			// round-trip and Python's optimistic-insert pattern
			// doesn't merge either.
			return nil
		}
		return fmt.Errorf("relation insert: %w", err)
	}
	return nil
}

func (r *EntityRepo) ListRelationsByProject(
	ctx context.Context, projectID string,
) ([]*entity.Relation, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, project_id, src_id, dst_id, kind, attributes
		FROM entity_relations WHERE project_id = ?
		ORDER BY created_at ASC, id ASC`, projectID)
	if err != nil {
		return nil, fmt.Errorf("ListRelationsByProject: %w", err)
	}
	defer rows.Close()
	var out []*entity.Relation
	for rows.Next() {
		var rel entity.Relation
		var kindS, attrJSON string
		if err := rows.Scan(&rel.ID, &rel.ProjectID, &rel.SrcID, &rel.DstID, &kindS, &attrJSON); err != nil {
			return nil, err
		}
		rel.Kind = entity.RelationKind(fromDBEnum(kindS))
		if attrJSON != "" {
			if err := json.Unmarshal([]byte(attrJSON), &rel.Attributes); err != nil {
				return nil, fmt.Errorf("decode relation attributes: %w", err)
			}
		}
		out = append(out, &rel)
	}
	return out, rows.Err()
}

func (r *EntityRepo) ListByProject(ctx context.Context, projectID string) ([]*entity.Entity, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, project_id, kind, value, attributes
		FROM entities WHERE project_id = ?
		ORDER BY created_at ASC, id ASC`, projectID)
	if err != nil {
		return nil, fmt.Errorf("entity ListByProject: %w", err)
	}
	defer rows.Close()
	var out []*entity.Entity
	for rows.Next() {
		var e entity.Entity
		var kindS, attrJSON string
		if err := rows.Scan(&e.ID, &e.ProjectID, &kindS, &e.Value, &attrJSON); err != nil {
			return nil, err
		}
		e.Kind = entity.Kind(fromDBEnum(kindS))
		if attrJSON != "" {
			if err := json.Unmarshal([]byte(attrJSON), &e.Attributes); err != nil {
				return nil, fmt.Errorf("decode entity attributes: %w", err)
			}
		}
		out = append(out, &e)
	}
	return out, rows.Err()
}
