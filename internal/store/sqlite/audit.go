package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/silvance/golantern/internal/audit"
	"github.com/silvance/golantern/internal/id"
)

// AuditRepo implements audit.Repository over SQLite.
type AuditRepo struct{ db *sql.DB }

func NewAuditRepo(db *sql.DB) *AuditRepo { return &AuditRepo{db: db} }

func (r *AuditRepo) Record(ctx context.Context, e *audit.LogEntry) error {
	if e.ID == "" {
		e.ID = id.New()
	}
	if e.Actor == "" {
		e.Actor = "system"
	}
	if e.CreatedAt.IsZero() {
		e.CreatedAt = time.Now().UTC()
	}
	detail := e.Detail
	if detail == nil {
		detail = map[string]any{}
	}
	detailJSON, err := json.Marshal(detail)
	if err != nil {
		return fmt.Errorf("audit detail encode: %w", err)
	}
	_, err = r.db.ExecContext(ctx, `
		INSERT INTO audit_logs
			(id, project_id, project_name_snapshot, actor, action, target, detail,
			 created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		e.ID, nullable(e.ProjectID), nullable(e.ProjectNameSnapshot),
		e.Actor, e.Action, nullable(e.Target), string(detailJSON),
		e.CreatedAt, e.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("audit Record: %w", err)
	}
	return nil
}

func (r *AuditRepo) ListByProject(ctx context.Context, projectID string) ([]*audit.LogEntry, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, COALESCE(project_id,''), COALESCE(project_name_snapshot,''),
		       actor, action, COALESCE(target,''), detail, created_at
		FROM audit_logs
		WHERE project_id = ?
		ORDER BY created_at DESC, id DESC`, projectID)
	if err != nil {
		return nil, fmt.Errorf("audit ListByProject: %w", err)
	}
	defer rows.Close()
	var out []*audit.LogEntry
	for rows.Next() {
		var e audit.LogEntry
		var detailJSON string
		if err := rows.Scan(
			&e.ID, &e.ProjectID, &e.ProjectNameSnapshot,
			&e.Actor, &e.Action, &e.Target, &detailJSON, &e.CreatedAt,
		); err != nil {
			return nil, err
		}
		if detailJSON != "" {
			if err := json.Unmarshal([]byte(detailJSON), &e.Detail); err != nil {
				return nil, fmt.Errorf("audit detail decode for %s: %w", e.ID, err)
			}
		}
		out = append(out, &e)
	}
	return out, rows.Err()
}
