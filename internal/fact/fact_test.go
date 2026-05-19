package fact

import (
	"reflect"
	"testing"
)

func TestMergeAttributesEmptyExisting(t *testing.T) {
	got := MergeAttributes(nil, map[string]any{"a": 1, "b": "x"})
	want := map[string]any{"a": 1, "b": "x"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestMergeAttributesAddsMissing(t *testing.T) {
	existing := map[string]any{"a": 1}
	got := MergeAttributes(existing, map[string]any{"b": 2})
	if got["a"] != 1 || got["b"] != 2 {
		t.Fatalf("missing key not added: %v", got)
	}
	// Existing must not be mutated.
	if _, has := existing["b"]; has {
		t.Fatal("existing map was mutated")
	}
}

func TestMergeAttributesScalarConflictKeepsExisting(t *testing.T) {
	got := MergeAttributes(
		map[string]any{"port": 80, "host": "old.example.com"},
		map[string]any{"port": 8080, "host": "new.example.com"},
	)
	if got["port"] != 80 {
		t.Fatalf("scalar conflict should keep existing; got %v", got["port"])
	}
	if got["host"] != "old.example.com" {
		t.Fatalf("scalar conflict should keep existing; got %v", got["host"])
	}
}

func TestMergeAttributesListUnion(t *testing.T) {
	got := MergeAttributes(
		map[string]any{"tags": []any{"alpha", "beta"}},
		map[string]any{"tags": []any{"beta", "gamma"}},
	)
	want := []any{"alpha", "beta", "gamma"}
	if !reflect.DeepEqual(got["tags"], want) {
		t.Fatalf("list union = %v, want %v", got["tags"], want)
	}
}

func TestMergeAttributesListUnionPreservesOrder(t *testing.T) {
	got := MergeAttributes(
		map[string]any{"ports": []any{443, 22, 80}},
		map[string]any{"ports": []any{8080, 22, 443}},
	)
	want := []any{443, 22, 80, 8080}
	if !reflect.DeepEqual(got["ports"], want) {
		t.Fatalf("ordering: got %v, want %v", got["ports"], want)
	}
}

func TestMergeAttributesStringSliceWidening(t *testing.T) {
	// Collectors emitting Go-native []string should merge against any
	// existing []any from JSON-decoded storage.
	got := MergeAttributes(
		map[string]any{"hosts": []any{"a"}},
		map[string]any{"hosts": []string{"a", "b"}},
	)
	want := []any{"a", "b"}
	if !reflect.DeepEqual(got["hosts"], want) {
		t.Fatalf("got %v, want %v", got["hosts"], want)
	}
}

func TestMergeAttributesListVsScalarNoMerge(t *testing.T) {
	// One side list, other side scalar: Python keeps existing (it's not
	// a list-vs-list match, so the elif branch doesn't fire).
	got := MergeAttributes(
		map[string]any{"v": []any{1, 2}},
		map[string]any{"v": 3},
	)
	want := []any{1, 2}
	if !reflect.DeepEqual(got["v"], want) {
		t.Fatalf("list vs scalar: got %v, want %v", got["v"], want)
	}
}

func TestMergeAttributesUnhashableElementsDeduplicate(t *testing.T) {
	// Python's fallback path uses `==` so dicts with identical contents
	// dedup. Two distinct map values with the same contents must not
	// produce duplicates.
	got := MergeAttributes(
		map[string]any{"refs": []any{map[string]any{"id": "a"}}},
		map[string]any{"refs": []any{map[string]any{"id": "a"}, map[string]any{"id": "b"}}},
	)
	want := []any{map[string]any{"id": "a"}, map[string]any{"id": "b"}}
	if !reflect.DeepEqual(got["refs"], want) {
		t.Fatalf("unhashable dedup: got %v, want %v", got["refs"], want)
	}
}

func TestMergeAttributesUnhashableMixedWithHashable(t *testing.T) {
	// Fast path collects hashable items, then trips on an unhashable
	// and must fall back without dropping items.
	got := MergeAttributes(
		map[string]any{"refs": []any{1, 2}},
		map[string]any{"refs": []any{2, 3, map[string]any{"k": 1}, 4}},
	)
	want := []any{1, 2, 3, map[string]any{"k": 1}, 4}
	if !reflect.DeepEqual(got["refs"], want) {
		t.Fatalf("mixed: got %v, want %v", got["refs"], want)
	}
}
