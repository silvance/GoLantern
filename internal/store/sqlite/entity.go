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
