// Package fact holds the collector-emitted DTOs (EntityFact,
// RelationFact, EvidenceFact, FindingFact) and the merge helpers used
// when a fact's target entity already exists.
//
// Ported from lantern.tools.base and the merging helpers from
// lantern.tools.runner. Splitting the DTOs into their own package
// breaks the Python cycle where tools/base.py imported from models/*
// and models/* indirectly imported tools via runner.py. In Go, fact
// depends on entity + finding; the runner (later phase) consumes facts
// and writes through repository interfaces declared in those packages.
package fact

import (
	"reflect"

	"github.com/silvance/golantern/internal/entity"
	"github.com/silvance/golantern/internal/finding"
)

// EntityFact is a normalized entity emitted by a collector. The runner
// persists it, deduplicating by (project, kind, value) and merging
// attributes with MergeAttributes.
type EntityFact struct {
	Kind           entity.Kind
	Value          string
	Attributes     map[string]any
	Confidence     finding.Confidence
	SourceCategory finding.SourceCategory
	Notes          string
}

// RelationFact is an edge between two entities, expressed by their
// (Kind, Value) natural keys. Using natural keys rather than DB ids
// lets collectors produce relations without round-tripping through the
// database first.
type RelationFact struct {
	Src        EntityRef
	Dst        EntityRef
	Kind       entity.RelationKind
	Attributes map[string]any
}

// EntityRef is the natural-key tuple used by RelationFact.
type EntityRef struct {
	Kind  entity.Kind
	Value string
}

// EvidenceFact is a standalone piece of evidence, optionally attached
// to a specific entity by natural key or to a finding by title.
type EvidenceFact struct {
	SourceTool     string
	SourceCategory finding.SourceCategory
	Confidence     finding.Confidence
	Payload        map[string]any
	ArtifactURI    string
	Notes          string

	// Optional: attach the evidence to a specific entity (looked up by
	// natural key) or to a finding (looked up by title within the
	// project). Both are independent; either, both, or neither may be set.
	EntityKind   entity.Kind
	EntityValue  string
	FindingTitle string
}

// FindingFact is an analyst-facing finding emitted by a collector. The
// supporting entities are natural-key references; the runner resolves
// them at persistence time.
type FindingFact struct {
	Title              string
	Severity           finding.Severity
	Confidence         finding.Confidence
	Description        string
	Recommendation     string
	Category           string
	Attributes         map[string]any
	SupportingEntities []EntityRef
}

// MergeAttributes shallow-merges incoming into existing.
//
// Semantics (preserved from lantern.tools.runner._merge_attributes):
//   - Keys present only in incoming are added.
//   - Keys present only in existing are kept.
//   - When both sides hold a []any (or []string), the result is the
//     order-preserving union of the two.
//   - Any other conflict prefers the existing value: "older evidence
//     wins on conflicts so the analyst sees a stable canonical value;
//     new data still gets recorded as evidence."
//
// existing is not mutated; a new map is returned.
func MergeAttributes(existing, incoming map[string]any) map[string]any {
	if len(existing) == 0 {
		out := make(map[string]any, len(incoming))
		for k, v := range incoming {
			out[k] = v
		}
		return out
	}
	out := make(map[string]any, len(existing)+len(incoming))
	for k, v := range existing {
		out[k] = v
	}
	for k, v := range incoming {
		old, present := out[k]
		if !present {
			out[k] = v
			continue
		}
		// List union when both sides are []any / []string.
		if merged, ok := mergeLists(old, v); ok {
			out[k] = merged
			continue
		}
		// Scalar conflict — keep existing.
	}
	return out
}

// mergeLists returns the order-preserving union of a and b when both
// are list-shaped, plus true. Returns nil/false when either side isn't
// a list. Hashable scalar elements use a map for O(N+M); non-hashable
// elements (nested maps/slices) fall back to a linear-scan membership
// check, exactly like the Python version's TypeError fallback.
func mergeLists(a, b any) (any, bool) {
	la, lb := toAnySlice(a), toAnySlice(b)
	if la == nil || lb == nil {
		return nil, false
	}
	out := make([]any, 0, len(la)+len(lb))
	out = append(out, la...)
	// Try hashable fast path first; on the first unhashable element
	// fall through to linear search for the remainder.
	seen := make(map[any]struct{}, len(la))
	hashable := true
	for _, item := range la {
		if !isHashable(item) {
			hashable = false
			break
		}
		seen[item] = struct{}{}
	}
	if hashable {
		for _, item := range lb {
			if !isHashable(item) {
				hashable = false
				break
			}
			if _, dup := seen[item]; dup {
				continue
			}
			seen[item] = struct{}{}
			out = append(out, item)
		}
		if hashable {
			return out, true
		}
	}
	// Slow path: linear scan over out.
	contains := func(slice []any, x any) bool {
		for _, y := range slice {
			if anyEqual(x, y) {
				return true
			}
		}
		return false
	}
	for _, item := range lb {
		if !contains(out, item) {
			out = append(out, item)
		}
	}
	return out, true
}

// toAnySlice coerces a []any or []string into []any; returns nil for
// non-list inputs. JSON-decoded payloads typically yield []any
// already; the []string case shows up when collectors emit attribute
// payloads in Go-native form.
func toAnySlice(v any) []any {
	switch s := v.(type) {
	case []any:
		return s
	case []string:
		out := make([]any, len(s))
		for i, x := range s {
			out[i] = x
		}
		return out
	}
	return nil
}

// isHashable reports whether v is a map-key-safe value. Maps and slices
// are not — they panic when used as map keys. Everything else (strings,
// numbers, bools, nil, structs of those) is fine.
func isHashable(v any) bool {
	switch v.(type) {
	case map[string]any, []any, []string:
		return false
	}
	return true
}

func anyEqual(a, b any) bool {
	// Cheap path: comparable scalars.
	if isHashable(a) && isHashable(b) {
		return a == b
	}
	// Slow path: structural equality for nested maps/slices. Mirrors
	// Python's `==` semantics on the fallback in _union_preserving_order
	// so two distinct map values with identical contents dedup.
	return reflect.DeepEqual(a, b)
}
