// Package scan is the collector framework: Collector interface,
// per-execution Context, Registry, and Runner. Ports the Python
// `tools/` machinery (base.py, registry.py, runner.py) into Go's
// idioms.
//
// Differences from Python:
//
//   - Collectors are values (or factories), not classes with a ClassVar
//     “meta“ attribute. The Metadata() method returns the meta;
//     concrete collectors typically store a *Meta on the struct.
//   - Registration is explicit. The Python registry uses subclass-import
//     side-effects (each tool module's import statement triggers a
//     decorator). Go has no class statement and we don't want package
//     init() side-effects: callers compose a Registry with the
//     collectors they want, usually in cmd/golantern/main.go.
//   - The Context is a sealed interface backed by the runner's
//     persisting impl. Tests can supply a recording impl without
//     depending on the runner.
//   - Concurrency: the runner takes a context.Context (Python cancels
//     via asyncio tasks; we cancel via ctx.Done()). Collectors must
//     observe ctx in any blocking call.
package scan

import (
	"context"
	"errors"
	"fmt"

	"github.com/silvance/golantern/internal/entity"
	"github.com/silvance/golantern/internal/fact"
	"github.com/silvance/golantern/internal/finding"
	"github.com/silvance/golantern/internal/run"
	"github.com/silvance/golantern/internal/scope"
	"github.com/silvance/golantern/internal/workflow"
)

// ParameterSpec describes a single collector parameter for the UI.
// Lifts to the SPA which renders a form per collector. The runner does
// not consult ParameterSpec at execution time — it's purely a UI
// contract and collectors continue to read from ctx.Parameters
// directly.
type ParameterSpec struct {
	Name        string
	Type        string // one of: string, int, float, bool, enum, string_list
	Description string
	Required    bool
	Default     any
	Choices     []string
	Placeholder string
}

// Meta is the static description of a collector for the registry and UI.
// Ported from CollectorMetadata; ParameterSpec is a sibling type rather
// than nested inside Meta to make field-by-field reuse easier.
type Meta struct {
	Name          string
	Phase         workflow.Phase
	RequiredScope scope.RuleKind
	Description   string

	Consumes       []entity.Kind
	Produces       []entity.Kind
	SourceCategory finding.SourceCategory
	Parameters     []ParameterSpec

	// TriggersOnServices: canonical service names this collector is
	// interesting for (smb, ssh, http, ...). Empty when not
	// service-scoped. Mirrors the Python field; used by the
	// "next-step" UI suggestions.
	TriggersOnServices []string

	// Binary names the external CLI this collector wraps as it
	// appears on PATH. "lantern doctor" probes via exec.LookPath to
	// tell operators which tools are missing. Empty when the
	// collector has no external dependency.
	Binary string

	// InstallHint is a free-form install command shown to the
	// operator when Binary is missing. Multi-line is fine; one line
	// per package manager.
	InstallHint string
}

// Collector is one tool. Concrete implementations live in
// internal/scan/collectors/<name> and are usually constructed by a
// New() factory their package exposes.
type Collector interface {
	Metadata() Meta
	Run(ctx context.Context, cctx Context) error
}

// Context is the runtime hand-off from the runner to the collector.
// Collectors call Emit* to produce facts; the runner persists them
// (with dedup, attribute merging, evidence linking).
//
// The Python ABC mixed instance attributes (project_id, parameters)
// with abstract methods. In Go those become accessor methods on the
// interface so the underlying impl can compute them lazily if needed.
type Context interface {
	// Identifiers — stable for the lifetime of the collector run.
	ProjectID() string
	ToolExecutionID() string
	Parameters() map[string]any

	// Fact emission. Returns the persisted entity/finding ID where
	// applicable so the collector can chain follow-ups (e.g. emit a
	// relation between two entities the collector just produced).
	EmitEntity(fact.EntityFact) (entityID string, err error)
	EmitRelation(fact.RelationFact) error
	EmitEvidence(fact.EvidenceFact) error
	EmitFinding(fact.FindingFact) (findingID string, err error)

	// Helpers.
	IsInScope(target string) bool
	ListEntityValues(kind entity.Kind) ([]string, error)
	StoreArtifact(content []byte, filename, contentType string) (uri string, err error)
}

// ErrStoreArtifactNotImplemented is returned by Context.StoreArtifact
// until the artifact subsystem lands. The runner stubs the method so
// collectors can be authored against the full interface today.
var ErrStoreArtifactNotImplemented = errors.New("scan: artifact storage not yet implemented")

// Registry maps collector names to factories.
//
// Each Register call replaces a prior factory for the same name. Callers
// (typically cmd/golantern/main.go) compose the registry once at
// process start and pass it to the runner; we deliberately avoid the
// Python pattern of import-time auto-registration via decorators.
//
// Factories produce a fresh Collector per Run so collectors holding
// per-execution state (entity caches, retry counters) don't carry it
// across invocations. The factory's collector is constructed via the
// factory; concrete factories that have no state can return the same
// instance every call.
type Registry struct {
	factories map[string]Factory
}

// Factory constructs a Collector. Returning Collector (not *Collector)
// lets each factory choose pointer vs value receivers.
type Factory func() Collector

func NewRegistry() *Registry {
	return &Registry{factories: make(map[string]Factory)}
}

// Register adds (or replaces) the factory under name. Panics on
// empty name — that's a configuration bug, not a runtime condition.
func (r *Registry) Register(name string, f Factory) {
	if name == "" {
		panic("scan: cannot register collector with empty name")
	}
	r.factories[name] = f
}

// Get returns the factory for name, or an error if not registered.
// Returning the factory rather than the constructed Collector lets the
// runner produce a fresh instance per execution without an additional
// method on Collector.
func (r *Registry) Get(name string) (Factory, error) {
	f, ok := r.factories[name]
	if !ok {
		return nil, fmt.Errorf("scan: collector %q not registered", name)
	}
	return f, nil
}

// Names lists registered collector names in unspecified order. Use
// for "lantern doctor" / "lantern collectors" listings.
func (r *Registry) Names() []string {
	out := make([]string, 0, len(r.factories))
	for name := range r.factories {
		out = append(out, name)
	}
	return out
}

// Wiring helpers used by the runner --------------------------------------

// Deps is the set of repositories the runner depends on. Bundling
// them keeps Runner construction terse and adds a single point to
// extend when a new domain joins the persistence path.
//
// Audit is optional in the sense that a nil here will simply skip
// audit emission; everything else is required. The runner asserts
// the non-optional fields once at construction.
type Deps struct {
	Runs     run.Repository
	Entities entity.Repository
	Findings finding.Repository
	Scope    *scope.Policy
}

// validate reports the first missing required dep. We call this at
// runner-construction time so handler code fails loudly when
// something is wired wrong, rather than at first emit.
func (d Deps) validate() error {
	switch {
	case d.Runs == nil:
		return errors.New("scan: Deps.Runs is required")
	case d.Entities == nil:
		return errors.New("scan: Deps.Entities is required")
	case d.Findings == nil:
		return errors.New("scan: Deps.Findings is required")
	case d.Scope == nil:
		return errors.New("scan: Deps.Scope is required")
	}
	return nil
}
