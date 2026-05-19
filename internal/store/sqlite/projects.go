package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/silvance/golantern/internal/id"
	"github.com/silvance/golantern/internal/project"
	"github.com/silvance/golantern/internal/scope"
)

// ProjectRepo implements project.Repository over SQLite.
type ProjectRepo struct{ db *sql.DB }

func NewProjectRepo(db *sql.DB) *ProjectRepo { return &ProjectRepo{db: db} }

func (r *ProjectRepo) Get(ctx context.Context, projectID string) (*project.Project, error) {
	row := r.db.QueryRowContext(ctx, `
		SELECT id, name, COALESCE(description,''), COALESCE(organization,''),
		       default_scope, mode
		FROM projects WHERE id = ?`, projectID)
	var p project.Project
	var defScope, mode string
	if err := row.Scan(&p.ID, &p.Name, &p.Description, &p.Organization, &defScope, &mode); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, project.ErrNotFound
		}
		return nil, fmt.Errorf("project Get: %w", err)
	}
	p.DefaultScope = scope.RuleKind(fromDBEnum(defScope))
	p.Mode = project.Mode(fromDBEnum(mode))
	return &p, nil
}

func (r *ProjectRepo) List(ctx context.Context) ([]*project.Project, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, name, COALESCE(description,''), COALESCE(organization,''),
		       default_scope, mode
		FROM projects ORDER BY created_at ASC`)
	if err != nil {
		return nil, fmt.Errorf("project List: %w", err)
	}
	defer rows.Close()

	var out []*project.Project
	for rows.Next() {
		var p project.Project
		var defScope, mode string
		if err := rows.Scan(&p.ID, &p.Name, &p.Description, &p.Organization, &defScope, &mode); err != nil {
			return nil, err
		}
		p.DefaultScope = scope.RuleKind(fromDBEnum(defScope))
		p.Mode = project.Mode(fromDBEnum(mode))
		out = append(out, &p)
	}
	return out, rows.Err()
}

// Save upserts. ID is assigned on create and written back to the caller.
// The UNIQUE(name) collision surfaces as project.ErrDuplicate.
func (r *ProjectRepo) Save(ctx context.Context, p *project.Project) error {
	if err := p.Validate(); err != nil {
		return err
	}
	now := time.Now().UTC()
	if p.ID == "" {
		p.ID = id.New()
	}
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO projects (id, name, description, organization, default_scope, mode,
		                     created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			name=excluded.name,
			description=excluded.description,
			organization=excluded.organization,
			default_scope=excluded.default_scope,
			mode=excluded.mode,
			updated_at=excluded.updated_at`,
		p.ID, p.Name, nullable(p.Description), nullable(p.Organization),
		toDBEnum(string(p.DefaultScope)), toDBEnum(string(p.Mode)),
		now, now,
	)
	if err != nil {
		if isUniqueViolation(err, "projects.name") {
			return project.ErrDuplicate
		}
		return fmt.Errorf("project Save: %w", err)
	}
	return nil
}

func (r *ProjectRepo) Delete(ctx context.Context, projectID string) error {
	res, err := r.db.ExecContext(ctx, `DELETE FROM projects WHERE id = ?`, projectID)
	if err != nil {
		return fmt.Errorf("project Delete: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return project.ErrNotFound
	}
	return nil
}

// nullable maps "" -> sql.NullString{Valid: false} so the DB stores
// NULL instead of an empty string. This matters because Lantern's
// existing rows use NULL for absent description/organization and we
// don't want Go-inserted rows to look different from Python-inserted ones.
func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// isUniqueViolation returns true when err is a SQLite UNIQUE constraint
// failure mentioning column. modernc.org/sqlite returns errors whose
// message includes "UNIQUE constraint failed: <table>.<col>".
func isUniqueViolation(err error, column string) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "UNIQUE constraint failed") &&
		strings.Contains(msg, column)
}
