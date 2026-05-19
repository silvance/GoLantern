package artifact_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/silvance/golantern/internal/artifact"
)

func TestURIRoundTrip(t *testing.T) {
	uri := artifact.URI("abc123")
	if uri != "lantern://artifacts/abc123" {
		t.Fatalf("URI shape wrong: %q", uri)
	}
	id, err := artifact.ParseURI(uri)
	if err != nil {
		t.Fatal(err)
	}
	if id != "abc123" {
		t.Fatalf("ParseURI got %q want abc123", id)
	}
}

func TestParseURIRejectsBadShapes(t *testing.T) {
	bad := []string{
		"",
		"http://example.com/abc",
		"lantern://artifacts/",                          // empty id
		"lantern://artifacts/has space",                 // disallowed char
		"lantern://other/abc",                           // wrong host
		"lantern://artifacts/" + strings.Repeat("a", 129), // too long
	}
	for _, b := range bad {
		if _, err := artifact.ParseURI(b); err == nil {
			t.Errorf("ParseURI(%q) should have errored", b)
		}
	}
}

func TestIsSafeID(t *testing.T) {
	if !artifact.IsSafeID("abc-DEF_123") {
		t.Fatal("safe id rejected")
	}
	if artifact.IsSafeID("../etc/passwd") {
		t.Fatal("traversal id accepted")
	}
	if artifact.IsSafeID("") {
		t.Fatal("empty id accepted")
	}
}

func TestSHA256Deterministic(t *testing.T) {
	a := artifact.SHA256([]byte("hello"))
	b := artifact.SHA256([]byte("hello"))
	c := artifact.SHA256([]byte("world"))
	if a != b {
		t.Fatal("hash not deterministic")
	}
	if a == c {
		t.Fatal("hash collision between distinct inputs")
	}
	if len(a) != 64 {
		t.Fatalf("hash length %d, want 64", len(a))
	}
}

func TestFilesystemStorePutGetDelete(t *testing.T) {
	root := t.TempDir()
	store := artifact.NewFilesystemStore(root)
	ctx := context.Background()

	uri, err := store.Put(ctx, "proj1", "art1", []byte("hello world"))
	if err != nil {
		t.Fatal(err)
	}
	if uri != artifact.URI("art1") {
		t.Fatalf("URI %q != expected %q", uri, artifact.URI("art1"))
	}
	// On-disk layout assertion.
	if _, err := os.Stat(filepath.Join(root, "proj1", "art1")); err != nil {
		t.Fatalf("file not at expected path: %v", err)
	}

	got, err := store.Get(ctx, uri)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "hello world" {
		t.Fatalf("Get bytes = %q", got)
	}

	if err := store.Delete(ctx, uri); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get(ctx, uri); !errors.Is(err, artifact.ErrNotFound) {
		t.Fatalf("post-delete Get err=%v, want ErrNotFound", err)
	}
	// Delete on an already-gone artifact is a no-op.
	if err := store.Delete(ctx, uri); err != nil {
		t.Fatalf("idempotent Delete returned err: %v", err)
	}
}

func TestFilesystemStoreRejectsUnsafeIDs(t *testing.T) {
	store := artifact.NewFilesystemStore(t.TempDir())
	ctx := context.Background()
	if _, err := store.Put(ctx, "../etc", "id", []byte("x")); err == nil {
		t.Fatal("Put should reject traversal project id")
	}
	if _, err := store.Put(ctx, "proj1", "../passwd", []byte("x")); err == nil {
		t.Fatal("Put should reject traversal artifact id")
	}
}

func TestFilesystemStoreGetMissing(t *testing.T) {
	store := artifact.NewFilesystemStore(t.TempDir())
	_, err := store.Get(context.Background(), artifact.URI("nope"))
	if !errors.Is(err, artifact.ErrNotFound) {
		t.Fatalf("err=%v, want ErrNotFound", err)
	}
}

func TestFilesystemStoreGetMissingRoot(t *testing.T) {
	// Constructing a store at a path that doesn't exist is fine; Get
	// reports ErrNotFound rather than a wrapped ENOENT so callers
	// don't have to special-case fresh installs.
	store := artifact.NewFilesystemStore(filepath.Join(t.TempDir(), "does-not-exist"))
	_, err := store.Get(context.Background(), artifact.URI("nope"))
	if !errors.Is(err, artifact.ErrNotFound) {
		t.Fatalf("err=%v, want ErrNotFound", err)
	}
}
