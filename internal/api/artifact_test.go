package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/silvance/golantern/internal/artifact"
	"github.com/silvance/golantern/internal/store/memory"
)

func newArtifactServer(t *testing.T) (*httptest.Server, *memory.Store, artifact.Store) {
	t.Helper()
	st := memory.New()
	store := artifact.NewFilesystemStore(t.TempDir())
	s := New(st.Projects, st.Scopes, st.Runs, st.Audit)
	s.Artifacts = st.Artifacts
	s.ArtifactStore = store
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)
	return srv, st, store
}

func TestListArtifactsEmpty(t *testing.T) {
	srv, st, _ := newArtifactServer(t)
	p := seedProject(t, st)

	resp, err := http.Get(srv.URL + "/api/v1/projects/" + p.ID + "/artifacts")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d", resp.StatusCode)
	}
	var out []artifactDTO
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if len(out) != 0 {
		t.Fatalf("expected empty list, got %d", len(out))
	}
}

func TestListAndGetArtifact(t *testing.T) {
	srv, st, store := newArtifactServer(t)
	p := seedProject(t, st)
	ctx := context.Background()

	uri, err := store.Put(ctx, p.ID, "img1", []byte("PNGDATA"))
	if err != nil {
		t.Fatal(err)
	}
	row := &artifact.Artifact{
		ID:          "img1",
		ProjectID:   p.ID,
		Filename:    "site.png",
		ContentType: "image/png",
		SizeBytes:   7,
		SHA256:      artifact.SHA256([]byte("PNGDATA")),
		StorageURI:  uri,
	}
	if err := st.Artifacts.Create(ctx, row); err != nil {
		t.Fatal(err)
	}

	// List should surface it.
	resp, err := http.Get(srv.URL + "/api/v1/projects/" + p.ID + "/artifacts")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var list []artifactDTO
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].ID != "img1" || list[0].SizeBytes != 7 {
		t.Fatalf("list wrong: %+v", list)
	}

	// Fetch the bytes.
	resp2, err := http.Get(srv.URL + "/api/v1/artifacts/img1")
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("byte fetch status=%d", resp2.StatusCode)
	}
	if got := resp2.Header.Get("Content-Type"); got != "image/png" {
		t.Errorf("Content-Type=%q, want image/png", got)
	}
	if got := resp2.Header.Get("Content-Disposition"); got == "" {
		t.Errorf("Content-Disposition missing")
	}
	body, _ := io.ReadAll(resp2.Body)
	if string(body) != "PNGDATA" {
		t.Fatalf("body=%q", body)
	}
}

func TestGetArtifactMissing(t *testing.T) {
	srv, _, _ := newArtifactServer(t)
	resp, err := http.Get(srv.URL + "/api/v1/artifacts/missing")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status=%d, want 404", resp.StatusCode)
	}
}

func TestGetArtifactBytesGoneIs410(t *testing.T) {
	srv, st, store := newArtifactServer(t)
	p := seedProject(t, st)
	ctx := context.Background()
	uri, _ := store.Put(ctx, p.ID, "img2", []byte("data"))
	_ = st.Artifacts.Create(ctx, &artifact.Artifact{
		ID: "img2", ProjectID: p.ID, Filename: "x.bin",
		ContentType: "application/octet-stream", SizeBytes: 4,
		SHA256: artifact.SHA256([]byte("data")), StorageURI: uri,
	})
	// Delete bytes but leave the row.
	if err := store.Delete(ctx, uri); err != nil {
		t.Fatal(err)
	}
	resp, err := http.Get(srv.URL + "/api/v1/artifacts/img2")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusGone {
		t.Fatalf("status=%d, want 410", resp.StatusCode)
	}
}

func TestArtifactEndpointsDisabledWhenNotConfigured(t *testing.T) {
	// Server WITHOUT artifact wiring should return 501 on both endpoints.
	st := memory.New()
	p := seedProject(t, st)
	s := New(st.Projects, st.Scopes, st.Runs, st.Audit)
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/api/v1/projects/" + p.ID + "/artifacts")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotImplemented {
		t.Fatalf("list status=%d, want 501", resp.StatusCode)
	}
	resp2, err := http.Get(srv.URL + "/api/v1/artifacts/anything")
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusNotImplemented {
		t.Fatalf("get status=%d, want 501", resp2.StatusCode)
	}
}
