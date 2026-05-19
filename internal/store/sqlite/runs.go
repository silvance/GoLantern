package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/silvance/golantern/internal/id"
	"github.com/silvance/golantern/internal/run"
	"github.com/silvance/golantern/internal/workflow"
)

// RunRepo implements run.Repository over SQLite.
type RunRepo struct{ db *sql.DB }

func NewRunRepo(db *sql.DB) *RunRepo { return &RunRepo{db: db} }

func (r *RunRepo) Get(ctx context.Context, runID string) (*run.Run, error) {
	row := r.db.QueryRowContext(ctx, `
		SELECT id, project_id, phase, status, COALESCE(label,''), parameters,
		       started_at, finished_at,
		       COALESCE(error_summary,''), COALESCE(error_debug,'')
		FROM runs WHERE id = ?`, runID)
	ru, err := scanRun(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, run.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("run Get: %w", err)
	}
	return ru, nil
}

func (r *RunRepo) ListByProject(ctx context.Context, projectID string) ([]*run.Run, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, project_id, phase, status, COALESCE(label,''), parameters,
		       started_at, finished_at,
		       COALESCE(error_summary,''), COALESCE(error_debug,'')
		FROM runs WHERE project_id = ?
		ORDER BY created_at DESC, id DESC`, projectID)
	if err != nil {
		return nil, fmt.Errorf("run ListByProject: %w", err)
	}
	defer rows.Close()
	var out []*run.Run
	for rows.Next() {
		ru, err := scanRun(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, ru)
	}
	return out, rows.Err()
}

// rowScanner is the subset of sql.Row / sql.Rows we need.
type rowScanner interface {
	Scan(dest ...any) error
}

func scanRun(rs rowScanner) (*run.Run, error) {
	var ru run.Run
	var phase, status string
	var paramsJSON string
	var startedAt, finishedAt sql.NullTime
	if err := rs.Scan(
		&ru.ID, &ru.ProjectID, &phase, &status, &ru.Label, &paramsJSON,
		&startedAt, &finishedAt, &ru.ErrorSummary, &ru.ErrorDebug,
	); err != nil {
		return nil, err
	}
	ru.Phase = workflow.Phase(fromDBEnum(phase))
	ru.Status = run.Status(fromDBEnum(status))
	if startedAt.Valid {
		t := startedAt.Time
		ru.StartedAt = &t
	}
	if finishedAt.Valid {
		t := finishedAt.Time
		ru.FinishedAt = &t
	}
	if paramsJSON != "" {
		if err := json.Unmarshal([]byte(paramsJSON), &ru.Parameters); err != nil {
			return nil, fmt.Errorf("decode parameters JSON for run %s: %w", ru.ID, err)
		}
	}
	return &ru, nil
}

func (r *RunRepo) Save(ctx context.Context, ru *run.Run) error {
	if ru.ID == "" {
		ru.ID = id.New()
	}
	if ru.Parameters == nil {
		ru.Parameters = map[string]any{}
	}
	paramsJSON, err := json.Marshal(ru.Parameters)
	if err != nil {
		return fmt.Errorf("encode parameters JSON: %w", err)
	}
	now := time.Now().UTC()
	_, err = r.db.ExecContext(ctx, `
		INSERT INTO runs (id, project_id, phase, status, label, parameters,
		                  started_at, finished_at, error_summary, error_debug,
		                  created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			phase=excluded.phase,
			status=excluded.status,
			label=excluded.label,
			parameters=excluded.parameters,
			started_at=excluded.started_at,
			finished_at=excluded.finished_at,
			error_summary=excluded.error_summary,
			error_debug=excluded.error_debug,
			updated_at=excluded.updated_at`,
		ru.ID, ru.ProjectID, toDBEnum(string(ru.Phase)), toDBEnum(string(ru.Status)),
		nullable(ru.Label), string(paramsJSON),
		timeOrNil(ru.StartedAt), timeOrNil(ru.FinishedAt),
		nullable(ru.ErrorSummary), nullable(ru.ErrorDebug),
		now, now,
	)
	if err != nil {
		return fmt.Errorf("run Save: %w", err)
	}
	return nil
}

func (r *RunRepo) Delete(ctx context.Context, runID string) error {
	res, err := r.db.ExecContext(ctx, `DELETE FROM runs WHERE id = ?`, runID)
	if err != nil {
		return fmt.Errorf("run Delete: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return run.ErrNotFound
	}
	return nil
}

func (r *RunRepo) SaveToolExecution(ctx context.Context, tx *run.ToolExecution) error {
	// Foreign-key check happens at the SQL level (PRAGMA foreign_keys=ON
	// from Open). We pre-check so the caller gets run.ErrNotFound rather
	// than a generic constraint error.
	var exists int
	if err := r.db.QueryRowContext(ctx, `SELECT 1 FROM runs WHERE id = ?`, tx.RunID).Scan(&exists); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return run.ErrNotFound
		}
		return err
	}
	if tx.ID == "" {
		tx.ID = id.New()
	}
	if tx.Parameters == nil {
		tx.Parameters = map[string]any{}
	}
	if tx.Result == nil {
		tx.Result = map[string]any{}
	}
	paramsJSON, err := json.Marshal(tx.Parameters)
	if err != nil {
		return fmt.Errorf("encode parameters JSON: %w", err)
	}
	resultJSON, err := json.Marshal(tx.Result)
	if err != nil {
		return fmt.Errorf("encode result JSON: %w", err)
	}
	now := time.Now().UTC()
	_, err = r.db.ExecContext(ctx, `
		INSERT INTO tool_executions
			(id, run_id, tool, status, parameters, result_summary,
			 started_at, finished_at, error_summary, error_debug,
			 entities_emitted, evidence_emitted, findings_emitted,
			 created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			status=excluded.status,
			parameters=excluded.parameters,
			result_summary=excluded.result_summary,
			started_at=excluded.started_at,
			finished_at=excluded.finished_at,
			error_summary=excluded.error_summary,
			error_debug=excluded.error_debug,
			entities_emitted=excluded.entities_emitted,
			evidence_emitted=excluded.evidence_emitted,
			findings_emitted=excluded.findings_emitted,
			updated_at=excluded.updated_at`,
		tx.ID, tx.RunID, tx.Tool, toDBEnum(string(tx.Status)),
		string(paramsJSON), string(resultJSON),
		timeOrNil(tx.StartedAt), timeOrNil(tx.FinishedAt),
		nullable(tx.ErrorSummary), nullable(tx.ErrorDebug),
		tx.EntitiesEmitted, tx.EvidenceEmitted, tx.FindingsEmitted,
		now, now,
	)
	if err != nil {
		return fmt.Errorf("tool execution Save: %w", err)
	}
	return nil
}

func (r *RunRepo) ListToolExecutions(ctx context.Context, runID string) ([]*run.ToolExecution, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, run_id, tool, status, parameters, result_summary,
		       started_at, finished_at,
		       COALESCE(error_summary,''), COALESCE(error_debug,''),
		       entities_emitted, evidence_emitted, findings_emitted
		FROM tool_executions WHERE run_id = ?
		ORDER BY created_at ASC, id ASC`, runID)
	if err != nil {
		return nil, fmt.Errorf("tool exec list: %w", err)
	}
	defer rows.Close()
	var out []*run.ToolExecution
	for rows.Next() {
		var tx run.ToolExecution
		var status, paramsJSON, resultJSON string
		var startedAt, finishedAt sql.NullTime
		if err := rows.Scan(
			&tx.ID, &tx.RunID, &tx.Tool, &status, &paramsJSON, &resultJSON,
			&startedAt, &finishedAt, &tx.ErrorSummary, &tx.ErrorDebug,
			&tx.EntitiesEmitted, &tx.EvidenceEmitted, &tx.FindingsEmitted,
		); err != nil {
			return nil, err
		}
		tx.Status = run.ToolExecutionStatus(fromDBEnum(status))
		if startedAt.Valid {
			t := startedAt.Time
			tx.StartedAt = &t
		}
		if finishedAt.Valid {
			t := finishedAt.Time
			tx.FinishedAt = &t
		}
		if paramsJSON != "" {
			if err := json.Unmarshal([]byte(paramsJSON), &tx.Parameters); err != nil {
				return nil, fmt.Errorf("decode tx parameters: %w", err)
			}
		}
		if resultJSON != "" {
			if err := json.Unmarshal([]byte(resultJSON), &tx.Result); err != nil {
				return nil, fmt.Errorf("decode tx result: %w", err)
			}
		}
		out = append(out, &tx)
	}
	return out, rows.Err()
}

func timeOrNil(t *time.Time) any {
	if t == nil {
		return nil
	}
	return *t
}
