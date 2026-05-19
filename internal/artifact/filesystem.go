package artifact

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// FilesystemStore writes artifact bytes under a single root directory.
// Layout matches the Python store: <root>/<project_id>/<artifact_id>.
// The two-level layout keeps the per-project blob count tractable when
// listing on a developer's machine, and makes "rm -rf <root>/<id>"
// straightforward when a project is purged.
//
// Concurrency: os.WriteFile already handles atomic-per-call write; we
// don't try to overlap writes to the same artifact id (the runner only
// emits one at a time per execution).
type FilesystemStore struct {
	root string
}

// NewFilesystemStore returns a store rooted at root. The directory is
// created on first Put, not at construction time, so a test using a
// throwaway tempdir doesn't have to pre-create the subdirs.
func NewFilesystemStore(root string) *FilesystemStore {
	return &FilesystemStore{root: root}
}

// Root returns the configured root directory. Exposed so callers
// (mostly tests) can clean up.
func (s *FilesystemStore) Root() string { return s.root }

// Put writes content under <root>/<projectID>/<artifactID> and returns
// the canonical lantern://artifacts/<artifactID> URI. Both IDs are
// validated against the safe-id pattern before any filesystem operation
// so a hostile caller can't escape the root via "../".
func (s *FilesystemStore) Put(_ context.Context, projectID, artifactID string, content []byte) (string, error) {
	if !IsSafeID(projectID) {
		return "", fmt.Errorf("artifact: unsafe project id %q", projectID)
	}
	if !IsSafeID(artifactID) {
		return "", fmt.Errorf("artifact: unsafe artifact id %q", artifactID)
	}
	dir := filepath.Join(s.root, projectID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("artifact: mkdir %q: %w", dir, err)
	}
	path := filepath.Join(dir, artifactID)
	if err := os.WriteFile(path, content, 0o644); err != nil {
		return "", fmt.Errorf("artifact: write %q: %w", path, err)
	}
	return URI(artifactID), nil
}

// Get reads the bytes for the artifact named by uri. The URI alone
// doesn't carry the project id, so we walk the root's project
// subdirectories looking for the file. Acceptable cost: artifact reads
// happen at report time and per-project counts are small.
func (s *FilesystemStore) Get(_ context.Context, uri string) ([]byte, error) {
	id, err := ParseURI(uri)
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(s.root)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("artifact: read root %q: %w", s.root, err)
	}
	for _, ent := range entries {
		if !ent.IsDir() {
			continue
		}
		path := filepath.Join(s.root, ent.Name(), id)
		b, err := os.ReadFile(path)
		if err == nil {
			return b, nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("artifact: read %q: %w", path, err)
		}
	}
	return nil, ErrNotFound
}

// Delete removes the artifact's bytes. Missing is fine — the row
// already keeps the metadata, and Delete is best-effort cleanup.
func (s *FilesystemStore) Delete(_ context.Context, uri string) error {
	id, err := ParseURI(uri)
	if err != nil {
		return err
	}
	entries, err := os.ReadDir(s.root)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("artifact: read root %q: %w", s.root, err)
	}
	for _, ent := range entries {
		if !ent.IsDir() {
			continue
		}
		path := filepath.Join(s.root, ent.Name(), id)
		if err := os.Remove(path); err == nil {
			return nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("artifact: delete %q: %w", path, err)
		}
	}
	return nil
}

var _ Store = (*FilesystemStore)(nil)
