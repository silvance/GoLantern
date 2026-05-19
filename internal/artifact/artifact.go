// Package artifact persists binary blobs (screenshots, downloaded
// HTML bodies, nuclei output dumps, etc.) that don't fit in a JSON
// attribute payload. Two pieces: the relational metadata row
// (Repository) and the raw byte store (Store). They're split so a
// future S3 backend is a drop-in replacement for the filesystem
// implementation without touching the row layer.
//
// Ported from lantern/artifacts.
package artifact

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"time"
)

// URIScheme + prefix are the canonical Lantern artifact URI shape:
// "lantern://artifacts/<id>". Anything else is rejected by ParseURI.
const (
	URIScheme = "lantern"
	URIPrefix = "lantern://artifacts/"
)

// idPattern restricts artifact IDs (and the project IDs we accept on
// the storage side) to filesystem-safe characters. Same pattern as
// the Python store.
var idPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

var uriPattern = regexp.MustCompile(`^lantern://artifacts/([A-Za-z0-9_-]{1,128})$`)

// ErrNotFound is returned when an artifact's bytes or row are missing.
var ErrNotFound = errors.New("artifact: not found")

// URI builds the canonical URI for an artifact ID.
func URI(artifactID string) string { return URIPrefix + artifactID }

// ParseURI returns the ID encoded in a lantern://artifacts/<id> URI.
// Returns ErrNotFound on any other shape — that's a programming bug
// at the call site, not an analyst-facing error.
func ParseURI(uri string) (string, error) {
	m := uriPattern.FindStringSubmatch(uri)
	if m == nil {
		return "", fmt.Errorf("artifact: not a Lantern artifact URI: %q", uri)
	}
	return m[1], nil
}

// SHA256 returns the lowercase hex digest of content. Used for the
// stored row's sha256 column so analysts can dedupe / verify integrity.
func SHA256(content []byte) string {
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:])
}

// Artifact is the in-memory metadata row. ID + ProjectID are
// filesystem-safe; the actual bytes live in a Store referenced via
// StorageURI.
type Artifact struct {
	ID          string
	ProjectID   string
	Filename    string
	ContentType string
	SizeBytes   int
	SHA256      string
	StorageURI  string
	CreatedAt   time.Time
}

// Repository persists artifact metadata. Bytes go through Store.
type Repository interface {
	Create(ctx context.Context, a *Artifact) error
	Get(ctx context.Context, id string) (*Artifact, error)
	ListByProject(ctx context.Context, projectID string) ([]*Artifact, error)
}

// Store handles raw artifact bytes. The filesystem implementation
// lives in this package; an S3 / blob-storage backend would slot in
// as another implementation.
type Store interface {
	Put(ctx context.Context, projectID, artifactID string, content []byte) (uri string, err error)
	Get(ctx context.Context, uri string) ([]byte, error)
	Delete(ctx context.Context, uri string) error
}

// IsSafeID is exposed so the runner can reject suspicious caller-
// supplied IDs early. Returns true iff id matches the safe pattern.
func IsSafeID(id string) bool { return idPattern.MatchString(id) }
