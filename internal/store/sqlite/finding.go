package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/silvance/golantern/internal/finding"
	"github.com/silvance/golantern/internal/id"
)

// FindingRepo implements finding.Repository over SQLite. Findings and
// Evidence share a repo because the runner emits them in lockstep.
type FindingRepo struct{ db *sql.DB }

func NewFindingRepo(db *sql.DB) *FindingRepo { return &FindingRepo{db: db} }

func (r *FindingRepo) CreateFinding(ctx context.Context, f *finding.Finding) error {
	if f.ID == "" {
		f.ID = id.New()
	}
	attrJSON := "{}"
	if len(f.Attributes) > 0 {
		b, err := json.Marshal(f.Attributes)
		if err != nil {
			return fmt.Errorf("encode finding attributes: %w", err)
		}
		attrJSON = string(b)
	}
	now := time.Now().UTC()
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO findings
			(id, project_id, title, description, recommendation, severity,
			 confidence, category, attributes, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		f.ID, f.ProjectID, f.Title, nullable(f.Description), nullable(f.Recommendation),
		toDBEnum(string(f.Severity)), toDBEnum(string(f.Confidence)),
		nullable(f.Category), attrJSON, now, now,
	)
	if err != nil {
		return fmt.Errorf("CreateFinding: %w", err)
	}
	return nil
}

func (r *FindingRepo) CreateEvidence(ctx context.Context, e *finding.Evidence) error {
	if e.ID == "" {
		e.ID = id.New()
	}
	payloadJSON := "{}"
	if len(e.Payload) > 0 {
		b, err := json.Marshal(e.Payload)
		if err != nil {
			return fmt.Errorf("encode evidence payload: %w", err)
		}
		payloadJSON = string(b)
	}
	now := time.Now().UTC()
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO evidence
			(id, project_id, entity_id, finding_id, tool_execution_id,
			 source_tool, source_category, confidence, payload,
			 artifact_uri, notes, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		e.ID, e.ProjectID,
		nullable(e.EntityID), nullable(e.FindingID), nullable(e.ToolExecutionID),
		e.SourceTool, toDBEnum(string(e.SourceCategory)), toDBEnum(string(e.Confidence)),
		payloadJSON, nullable(e.ArtifactURI), nullable(e.Notes),
		now, now,
	)
	if err != nil {
		return fmt.Errorf("CreateEvidence: %w", err)
	}
	return nil
}

func (r *FindingRepo) ListFindings(ctx context.Context, projectID string) ([]*finding.Finding, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, project_id, title,
		       COALESCE(description,''), COALESCE(recommendation,''),
		       severity, confidence, COALESCE(category,''), attributes
		FROM findings WHERE project_id = ?
		ORDER BY created_at ASC, id ASC`, projectID)
	if err != nil {
		return nil, fmt.Errorf("ListFindings: %w", err)
	}
	defer rows.Close()
	var out []*finding.Finding
	for rows.Next() {
		var f finding.Finding
		var sev, conf, attrJSON string
		if err := rows.Scan(
			&f.ID, &f.ProjectID, &f.Title, &f.Description, &f.Recommendation,
			&sev, &conf, &f.Category, &attrJSON,
		); err != nil {
			return nil, err
		}
		f.Severity = finding.Severity(fromDBEnum(sev))
		f.Confidence = finding.Confidence(fromDBEnum(conf))
		if attrJSON != "" {
			if err := json.Unmarshal([]byte(attrJSON), &f.Attributes); err != nil {
				return nil, fmt.Errorf("decode finding attributes: %w", err)
			}
		}
		out = append(out, &f)
	}
	return out, rows.Err()
}

func (r *FindingRepo) ListEvidence(ctx context.Context, projectID string) ([]*finding.Evidence, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, project_id, COALESCE(entity_id,''), COALESCE(finding_id,''),
		       COALESCE(tool_execution_id,''), source_tool, source_category,
		       confidence, payload, COALESCE(artifact_uri,''), COALESCE(notes,'')
		FROM evidence WHERE project_id = ?
		ORDER BY created_at ASC, id ASC`, projectID)
	if err != nil {
		return nil, fmt.Errorf("ListEvidence: %w", err)
	}
	defer rows.Close()
	var out []*finding.Evidence
	for rows.Next() {
		var e finding.Evidence
		var srcCat, conf, payloadJSON string
		if err := rows.Scan(
			&e.ID, &e.ProjectID, &e.EntityID, &e.FindingID, &e.ToolExecutionID,
			&e.SourceTool, &srcCat, &conf, &payloadJSON, &e.ArtifactURI, &e.Notes,
		); err != nil {
			return nil, err
		}
		e.SourceCategory = finding.SourceCategory(fromDBEnum(srcCat))
		e.Confidence = finding.Confidence(fromDBEnum(conf))
		if payloadJSON != "" {
			if err := json.Unmarshal([]byte(payloadJSON), &e.Payload); err != nil {
				return nil, fmt.Errorf("decode evidence payload: %w", err)
			}
		}
		out = append(out, &e)
	}
	return out, rows.Err()
}

