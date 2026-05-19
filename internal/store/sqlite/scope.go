package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/silvance/golantern/internal/id"
	"github.com/silvance/golantern/internal/scope"
)

// ScopeRepo implements scope.Repository over SQLite.
type ScopeRepo struct{ db *sql.DB }

func NewScopeRepo(db *sql.DB) *ScopeRepo { return &ScopeRepo{db: db} }

func (r *ScopeRepo) ListByProject(ctx context.Context, projectID string) ([]scope.StoredRule, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, project_id, pattern, kind, COALESCE(note,'')
		FROM scope_rules
		WHERE project_id = ?
		ORDER BY created_at ASC, id ASC`,
		projectID,
	)
	if err != nil {
		return nil, fmt.Errorf("scope ListByProject: %w", err)
	}
	defer rows.Close()

	var out []scope.StoredRule
	for rows.Next() {
		var sr scope.StoredRule
		var kind string
		if err := rows.Scan(&sr.ID, &sr.ProjectID, &sr.Rule.Pattern, &kind, &sr.Note); err != nil {
			return nil, err
		}
		sr.Rule.Kind = scope.RuleKind(fromDBEnum(kind))
		out = append(out, sr)
	}
	return out, rows.Err()
}

func (r *ScopeRepo) Add(ctx context.Context, sr *scope.StoredRule) error {
	if sr.ID == "" {
		sr.ID = id.New()
	}
	now := time.Now().UTC()
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO scope_rules (id, project_id, pattern, kind, note, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		sr.ID, sr.ProjectID, sr.Rule.Pattern, toDBEnum(string(sr.Rule.Kind)),
		nullable(sr.Note), now, now,
	)
	if err != nil {
		if isUniqueViolation(err, "uq_scope_rules_project_pattern") ||
			isUniqueViolation(err, "scope_rules.pattern") {
			return scope.ErrDuplicate
		}
		return fmt.Errorf("scope Add: %w", err)
	}
	return nil
}

func (r *ScopeRepo) Delete(ctx context.Context, ruleID string) error {
	res, err := r.db.ExecContext(ctx, `DELETE FROM scope_rules WHERE id = ?`, ruleID)
	if err != nil {
		return fmt.Errorf("scope Delete: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return scope.ErrNotFound
	}
	return nil
}
