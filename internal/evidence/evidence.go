// Package evidence implements the "paste evidence" workflow:
// post-foothold tool output (LinPEAS, WinPEAS, mimikatz, etc.) is
// posted to GoLantern from the operator's clipboard or a saved
// file, parsed into structured facts, and folded into the project
// graph alongside the scanner-driven collectors.
//
// Parsers are pure: they take raw text and a target hint and emit
// entity/finding/evidence facts. The HTTP handler in
// internal/api/evidence_handler.go uses the same persistence
// plumbing as the scan runner so the resulting facts are
// indistinguishable from collector output downstream.
package evidence

import (
	"fmt"

	"github.com/silvance/golantern/internal/fact"
)

// Result is what a parser returns to the caller.
type Result struct {
	Entities []fact.EntityFact
	Findings []fact.FindingFact
	Evidence []fact.EvidenceFact
}

// Parser converts raw tool output into structured facts. Target
// is an operator-supplied hint that identifies the host the
// evidence pertains to (usually an IP or hostname). Empty target
// is acceptable; parsers should still emit findings but skip the
// "attach to entity" wiring.
type Parser interface {
	// Name is the slug operators reference in API/UI.
	Name() string
	// Description is the one-liner shown in the UI tool picker.
	Description() string
	// Parse extracts facts from raw. The returned Result is fed
	// into the same persistence pipeline collectors use; parsers
	// should NOT touch storage themselves.
	Parse(raw, target string) (Result, error)
}

// Registry maps parser names to implementations. Mirrors the scan
// registry pattern; the API layer holds one instance.
type Registry struct {
	parsers map[string]Parser
}

func NewRegistry() *Registry {
	return &Registry{parsers: make(map[string]Parser)}
}

func (r *Registry) Register(p Parser) {
	if p == nil || p.Name() == "" {
		panic("evidence: cannot register nil or unnamed parser")
	}
	r.parsers[p.Name()] = p
}

func (r *Registry) Get(name string) (Parser, error) {
	p, ok := r.parsers[name]
	if !ok {
		return nil, fmt.Errorf("evidence: parser %q not registered", name)
	}
	return p, nil
}

// Names returns every registered parser slug in registration order.
func (r *Registry) Names() []string {
	out := make([]string, 0, len(r.parsers))
	for name := range r.parsers {
		out = append(out, name)
	}
	return out
}

// Describe returns the (name, description) pairs for every parser.
// Used by the API to populate the UI's parser dropdown.
type Descriptor struct {
	Name        string
	Description string
}

func (r *Registry) Describe() []Descriptor {
	out := make([]Descriptor, 0, len(r.parsers))
	for _, p := range r.parsers {
		out = append(out, Descriptor{Name: p.Name(), Description: p.Description()})
	}
	return out
}
