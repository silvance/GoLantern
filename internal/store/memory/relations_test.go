package memory

import (
	"context"
	"errors"
	"testing"

	"github.com/silvance/golantern/internal/entity"
)

func TestRelationCreateAndList(t *testing.T) {
	r := NewEntityRepo()
	ctx := context.Background()
	srcID, _ := r.Upsert(ctx, "p", entity.KindSubdomain, "a.example.com", nil)
	dstID, _ := r.Upsert(ctx, "p", entity.KindDomain, "example.com", nil)
	if err := r.CreateRelation(ctx, &entity.Relation{
		ProjectID: "p", SrcID: srcID, DstID: dstID, Kind: entity.RelChildOf,
	}); err != nil {
		t.Fatal(err)
	}
	got, _ := r.ListRelationsByProject(ctx, "p")
	if len(got) != 1 || got[0].Kind != entity.RelChildOf {
		t.Fatalf("ListRelations = %+v", got)
	}
}

func TestRelationIdempotent(t *testing.T) {
	r := NewEntityRepo()
	ctx := context.Background()
	srcID, _ := r.Upsert(ctx, "p", entity.KindSubdomain, "a.example.com", nil)
	dstID, _ := r.Upsert(ctx, "p", entity.KindDomain, "example.com", nil)
	rel := &entity.Relation{ProjectID: "p", SrcID: srcID, DstID: dstID, Kind: entity.RelChildOf}
	if err := r.CreateRelation(ctx, rel); err != nil {
		t.Fatal(err)
	}
	if err := r.CreateRelation(ctx, &entity.Relation{
		ProjectID: "p", SrcID: srcID, DstID: dstID, Kind: entity.RelChildOf,
		Attributes: map[string]any{"discovered_by": "crtsh"},
	}); err != nil {
		t.Fatalf("dup-insert should be silently accepted: %v", err)
	}
	got, _ := r.ListRelationsByProject(ctx, "p")
	if len(got) != 1 {
		t.Fatalf("relations=%d, want 1", len(got))
	}
	// Memory store merges attributes on duplicate. SQLite store does not
	// (Python parity); the merge-on-memory choice is documented in the
	// memory.CreateRelation comment.
	if got[0].Attributes["discovered_by"] != "crtsh" {
		t.Fatalf("expected attrs to merge in memory store, got %+v", got[0].Attributes)
	}
}

func TestRelationCrossProjectRejected(t *testing.T) {
	r := NewEntityRepo()
	ctx := context.Background()
	srcID, _ := r.Upsert(ctx, "projA", entity.KindSubdomain, "a.test", nil)
	dstID, _ := r.Upsert(ctx, "projB", entity.KindDomain, "test", nil)
	err := r.CreateRelation(ctx, &entity.Relation{
		ProjectID: "projA", SrcID: srcID, DstID: dstID, Kind: entity.RelChildOf,
	})
	if !errors.Is(err, entity.ErrCrossProject) {
		t.Fatalf("got %v, want ErrCrossProject", err)
	}
}

func TestRelationMissingEndpoint(t *testing.T) {
	r := NewEntityRepo()
	if err := r.CreateRelation(context.Background(), &entity.Relation{
		ProjectID: "p", SrcID: "ghost1", DstID: "ghost2", Kind: entity.RelChildOf,
	}); !errors.Is(err, entity.ErrNotFound) {
		t.Fatalf("got %v, want ErrNotFound", err)
	}
}
