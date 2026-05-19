package sqlite

import (
	"errors"
	"testing"

	"github.com/silvance/golantern/internal/entity"
)

func TestSQLiteRelationRoundTrip(t *testing.T) {
	st := newTestStore(t)
	p := seedProject(t, st)
	srcID, _ := st.Entities.Upsert(ctx(), p.ID, entity.KindSubdomain, "a.example.com", nil)
	dstID, _ := st.Entities.Upsert(ctx(), p.ID, entity.KindDomain, "example.com", nil)
	if err := st.Entities.CreateRelation(ctx(), &entity.Relation{
		ProjectID: p.ID, SrcID: srcID, DstID: dstID, Kind: entity.RelChildOf,
	}); err != nil {
		t.Fatal(err)
	}
	got, _ := st.Entities.ListRelationsByProject(ctx(), p.ID)
	if len(got) != 1 || got[0].Kind != entity.RelChildOf {
		t.Fatalf("got %+v", got)
	}
	// DB holds the SQLAlchemy NAME (uppercase).
	var raw string
	_ = st.DB.QueryRowContext(ctx(), `SELECT kind FROM entity_relations`).Scan(&raw)
	if raw != "CHILD_OF" {
		t.Fatalf("DB stored %q, want CHILD_OF", raw)
	}
}

func TestSQLiteRelationUniqueTripleIdempotent(t *testing.T) {
	st := newTestStore(t)
	p := seedProject(t, st)
	srcID, _ := st.Entities.Upsert(ctx(), p.ID, entity.KindSubdomain, "a.test", nil)
	dstID, _ := st.Entities.Upsert(ctx(), p.ID, entity.KindDomain, "test", nil)
	for i := 0; i < 3; i++ {
		if err := st.Entities.CreateRelation(ctx(), &entity.Relation{
			ProjectID: p.ID, SrcID: srcID, DstID: dstID, Kind: entity.RelChildOf,
		}); err != nil {
			t.Fatalf("attempt %d: %v", i, err)
		}
	}
	got, _ := st.Entities.ListRelationsByProject(ctx(), p.ID)
	if len(got) != 1 {
		t.Fatalf("expected single row across 3 inserts, got %d", len(got))
	}
}

func TestSQLiteRelationCrossProjectRejected(t *testing.T) {
	st := newTestStore(t)
	pA := seedProject(t, st)
	pB := &struct{}{} // placeholder; need a second project
	_ = pB
	// Create a second project directly to get its ID.
	pB2 := seedProjectNamed(t, st, "OtherProj")
	srcID, _ := st.Entities.Upsert(ctx(), pA.ID, entity.KindSubdomain, "a.test", nil)
	dstID, _ := st.Entities.Upsert(ctx(), pB2.ID, entity.KindDomain, "test", nil)
	err := st.Entities.CreateRelation(ctx(), &entity.Relation{
		ProjectID: pA.ID, SrcID: srcID, DstID: dstID, Kind: entity.RelChildOf,
	})
	if !errors.Is(err, entity.ErrCrossProject) {
		t.Fatalf("got %v, want ErrCrossProject", err)
	}
}

func TestSQLiteRelationCascadeOnProjectDelete(t *testing.T) {
	st := newTestStore(t)
	p := seedProject(t, st)
	srcID, _ := st.Entities.Upsert(ctx(), p.ID, entity.KindSubdomain, "a.test", nil)
	dstID, _ := st.Entities.Upsert(ctx(), p.ID, entity.KindDomain, "test", nil)
	_ = st.Entities.CreateRelation(ctx(), &entity.Relation{
		ProjectID: p.ID, SrcID: srcID, DstID: dstID, Kind: entity.RelChildOf,
	})
	if err := st.Projects.Delete(ctx(), p.ID); err != nil {
		t.Fatal(err)
	}
	var n int
	_ = st.DB.QueryRowContext(ctx(), `SELECT count(*) FROM entity_relations`).Scan(&n)
	if n != 0 {
		t.Fatalf("FK cascade failed: %d relation rows survived project delete", n)
	}
}
