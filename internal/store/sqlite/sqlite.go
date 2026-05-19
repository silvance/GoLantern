// Package sqlite is the SQLite-backed implementation of the domain
// repository interfaces. Schema lives in schema.sql and mirrors
// Lantern's Alembic head, so Python and Go can share a database during
// the migration window.
//
// Driver: modernc.org/sqlite (pure Go, no CGO). Slightly slower than
// mattn/go-sqlite3 but trivial to cross-compile and bundle, which
// matters for the Tauri desktop shell that ships the binary.
//
// Enum mapping: Python stores the SQLAlchemy member NAME (uppercase)
// while our Go enum values are lowercase. The translation is a uniform
// strings.ToUpper / strings.ToLower at the SQL boundary; we centralize
// it in toDBEnum / fromDBEnum so collator drift between domains stays
// impossible.
package sqlite

import (
	"context"
	"database/sql"
	_ "embed"
	"fmt"
	"strings"

	_ "modernc.org/sqlite"
)

//go:embed schema.sql
var schemaSQL string

// Open opens (or creates) a SQLite database at path and applies the
// embedded schema idempotently. Pragmas enable foreign-key cascades
// (off by default in SQLite) and WAL journaling (so concurrent readers
// don't block on writers).
//
// The schema script is safe to run against a Python-managed Lantern DB
// because every CREATE uses IF NOT EXISTS; column types and constraints
// are kept identical to what Alembic emits.
func Open(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open %q: %w", path, err)
	}
	if _, err := db.ExecContext(context.Background(), `
		PRAGMA foreign_keys = ON;
		PRAGMA journal_mode = WAL;
	`); err != nil {
		db.Close()
		return nil, fmt.Errorf("pragmas: %w", err)
	}
	return db, nil
}

// Migrate applies the embedded schema. Idempotent; calling on an
// already-migrated DB is a no-op.
func Migrate(ctx context.Context, db *sql.DB) error {
	if _, err := db.ExecContext(ctx, schemaSQL); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	return nil
}

// toDBEnum converts a Go enum value ("light_active") to the SQLAlchemy
// member-name form ("LIGHT_ACTIVE") used in the database.
func toDBEnum(v string) string { return strings.ToUpper(v) }

// fromDBEnum is the inverse of toDBEnum. Empty input yields empty
// output (some columns are nullable).
func fromDBEnum(s string) string { return strings.ToLower(s) }

// Store bundles every repository sharing one *sql.DB. Useful when
// wiring a server or test from a single connection.
type Store struct {
	DB        *sql.DB
	Projects  *ProjectRepo
	Scopes    *ScopeRepo
	Runs      *RunRepo
	Audit     *AuditRepo
	Entities  *EntityRepo
	Findings  *FindingRepo
	Artifacts *ArtifactRepo
}

// NewStore constructs all repositories around db. The caller remains
// responsible for db.Close().
func NewStore(db *sql.DB) *Store {
	return &Store{
		DB:        db,
		Projects:  NewProjectRepo(db),
		Scopes:    NewScopeRepo(db),
		Runs:      NewRunRepo(db),
		Audit:     NewAuditRepo(db),
		Entities:  NewEntityRepo(db),
		Findings:  NewFindingRepo(db),
		Artifacts: NewArtifactRepo(db),
	}
}
