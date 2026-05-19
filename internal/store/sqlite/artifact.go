package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/silvance/golantern/internal/artifact"
	"github.com/silvance/golantern/internal/id"
)

// ArtifactRepo implements artifact.Repository over SQLite.
type ArtifactRepo struct{ db *sql.DB }

func NewArtifactRepo(db *sql.DB) *ArtifactRepo { return &ArtifactRepo{db: db} }

func (r *ArtifactRepo) Create(ctx context.Context, a *artifact.Artifact) error {
	if a.ID == "" {
		a.ID = id.New()
	}
	if a.CreatedAt.IsZero() {
		a.CreatedAt = time.Now().UTC()
	}
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO artifacts
			(id, project_id, filename, content_type, size_bytes, sha256,
			 storage_uri, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		a.ID, a.ProjectID, a.Filename, a.ContentType, a.SizeBytes,
		a.SHA256, a.StorageURI, a.CreatedAt, a.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("artifact Create: %w", err)
	}
	return nil
}

func (r *ArtifactRepo) Get(ctx context.Context, artifactID string) (*artifact.Artifact, error) {
	row := r.db.QueryRowContext(ctx, `
		SELECT id, project_id, filename, content_type, size_bytes, sha256,
		       storage_uri, created_at
		FROM artifacts WHERE id = ?`, artifactID)
	a := &artifact.Artifact{}
	if err := row.Scan(
		&a.ID, &a.ProjectID, &a.Filename, &a.ContentType, &a.SizeBytes,
		&a.SHA256, &a.StorageURI, &a.CreatedAt,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, artifact.ErrNotFound
		}
		return nil, fmt.Errorf("artifact Get: %w", err)
	}
	return a, nil
}

func (r *ArtifactRepo) ListByProject(ctx context.Context, projectID string) ([]*artifact.Artifact, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, project_id, filename, content_type, size_bytes, sha256,
		       storage_uri, created_at
		FROM artifacts
		WHERE project_id = ?
		ORDER BY created_at DESC, id DESC`, projectID)
	if err != nil {
		return nil, fmt.Errorf("artifact ListByProject: %w", err)
	}
	defer rows.Close()
	var out []*artifact.Artifact
	for rows.Next() {
		a := &artifact.Artifact{}
		if err := rows.Scan(
			&a.ID, &a.ProjectID, &a.Filename, &a.ContentType, &a.SizeBytes,
			&a.SHA256, &a.StorageURI, &a.CreatedAt,
		); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

var _ artifact.Repository = (*ArtifactRepo)(nil)
