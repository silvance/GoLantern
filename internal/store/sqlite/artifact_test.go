package sqlite

import (
	"errors"
	"testing"

	"github.com/silvance/golantern/internal/artifact"
	"github.com/silvance/golantern/internal/project"
	"github.com/silvance/golantern/internal/scope"
)

// Compile-time assertion the SQLite repo satisfies the domain
// interface — keeps method signature drift as a build error rather
// than a runtime surprise.
var _ artifact.Repository = (*ArtifactRepo)(nil)

func seedProjForArtifacts(t *testing.T, st *Store) *project.Project {
	t.Helper()
	p := &project.Project{Name: "P", DefaultScope: scope.KindPassive, Mode: project.ModeAssessment}
	if err := st.Projects.Save(ctx(), p); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestArtifactCreateGetList(t *testing.T) {
	st := newTestStore(t)
	p := seedProjForArtifacts(t, st)

	a := &artifact.Artifact{
		ProjectID:   p.ID,
		Filename:    "site.png",
		ContentType: "image/png",
		SizeBytes:   1234,
		SHA256:      "deadbeef",
		StorageURI:  "lantern://artifacts/abc",
	}
	if err := st.Artifacts.Create(ctx(), a); err != nil {
		t.Fatal(err)
	}
	if a.ID == "" {
		t.Fatal("Create did not assign an ID")
	}
	if a.CreatedAt.IsZero() {
		t.Fatal("Create did not stamp CreatedAt")
	}

	got, err := st.Artifacts.Get(ctx(), a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Filename != "site.png" || got.SizeBytes != 1234 || got.StorageURI != "lantern://artifacts/abc" {
		t.Fatalf("round-trip wrong: %+v", got)
	}

	rows, err := st.Artifacts.ListByProject(ctx(), p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].ID != a.ID {
		t.Fatalf("list wrong: %+v", rows)
	}
}

func TestArtifactGetMissing(t *testing.T) {
	st := newTestStore(t)
	_, err := st.Artifacts.Get(ctx(), "nope")
	if !errors.Is(err, artifact.ErrNotFound) {
		t.Fatalf("err=%v, want ErrNotFound", err)
	}
}

func TestArtifactDeleteCascadesWithProject(t *testing.T) {
	st := newTestStore(t)
	p := seedProjForArtifacts(t, st)
	a := &artifact.Artifact{
		ProjectID: p.ID, Filename: "x.bin", ContentType: "application/octet-stream",
		SizeBytes: 1, SHA256: "h", StorageURI: "lantern://artifacts/xyz",
	}
	if err := st.Artifacts.Create(ctx(), a); err != nil {
		t.Fatal(err)
	}
	if err := st.Projects.Delete(ctx(), p.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Artifacts.Get(ctx(), a.ID); !errors.Is(err, artifact.ErrNotFound) {
		t.Fatalf("expected cascade delete to drop artifact row, err=%v", err)
	}
}
