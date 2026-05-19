// Package entity holds the normalized OSINT entity value types and the
// canonicalization rules used for project-scoped dedup. Pure logic.
//
// Ported from lantern.models.entities. The SQLAlchemy single-table
// polymorphism and the cross-project-relation flush-time hook live in
// the storage layer; what's here is just the in-memory shape and the
// kind-aware string normalization.
package entity

import (
	"context"
	"errors"
	"net/netip"
	"net/url"
	"strings"
)

// ErrNotFound is returned by Repository lookups that miss.
var ErrNotFound = errors.New("entity: not found")

// Repository persists entities and their attributes with per-project,
// per-(kind, value) dedup. Upsert is the only write method the runner
// needs at the entity layer: the canonicalized value is the natural
// key, and conflicting attributes merge rather than overwriting (older
// evidence wins on scalar conflicts, list-valued attributes union).
//
// The merge happens inside the repository so the runner doesn't have
// to round-trip read-modify-write for every emission. Implementations
// must use the (project_id, kind, canonical_value) uniqueness rule.
type Repository interface {
	// Upsert finds or creates the row keyed by (projectID, kind,
	// canonicalValue). When found, attributes are merged in place via
	// fact.MergeAttributes semantics. Returns the entity ID either way.
	//
	// Callers are responsible for canonicalizing value via
	// Canonicalize(kind, raw) before calling — passing a raw value
	// would silently create duplicates. Putting the canonicalization
	// in the repo would tempt callers to skip it for relation
	// endpoints (where the cost of re-canonicalizing is wasted).
	Upsert(ctx context.Context, projectID string, kind Kind, canonicalValue string, attributes map[string]any) (id string, err error)

	// ListValuesByKind returns every entity value of kind for the
	// project. Used by ctx.list_entity_values so later-phase
	// collectors can consume earlier-phase output (e.g. dnsx
	// resolving subdomains found by crt.sh).
	ListValuesByKind(ctx context.Context, projectID string, kind Kind) ([]string, error)

	// ListByProject returns every entity row for the project in
	// insertion order. Used by report generation; renderers group
	// by kind client-side.
	ListByProject(ctx context.Context, projectID string) ([]*Entity, error)
}

// Kind enumerates entity kinds. Mirrors lantern's EntityKind. String
// values are wire format.
type Kind string

const (
	KindDomain       Kind = "domain"
	KindSubdomain    Kind = "subdomain"
	KindIP           Kind = "ip"
	KindURL          Kind = "url"
	KindEmail        Kind = "email"
	KindPerson       Kind = "person"
	KindDocument     Kind = "document"
	KindTechnology   Kind = "technology"
	KindPort         Kind = "port"
	KindService      Kind = "service"
	KindOrganization Kind = "organization"
	KindRepository   Kind = "repository"
)

// allKinds is used only by Valid; keep in sync with the const block.
var allKinds = []Kind{
	KindDomain, KindSubdomain, KindIP, KindURL, KindEmail, KindPerson,
	KindDocument, KindTechnology, KindPort, KindService, KindOrganization,
	KindRepository,
}

func (k Kind) Valid() bool {
	for _, q := range allKinds {
		if k == q {
			return true
		}
	}
	return false
}

// RelationKind enumerates the directed-edge kinds.
type RelationKind string

const (
	RelResolvesTo     RelationKind = "resolves_to"
	RelHosts          RelationKind = "hosts"
	RelServes         RelationKind = "serves"
	RelBelongsTo      RelationKind = "belongs_to"
	RelAuthored       RelationKind = "authored"
	RelUsesTech       RelationKind = "uses_tech"
	RelChildOf        RelationKind = "child_of"
	RelReferences     RelationKind = "references"
	RelDiscoveredFrom RelationKind = "discovered_from"
)

func (r RelationKind) Valid() bool {
	switch r {
	case RelResolvesTo, RelHosts, RelServes, RelBelongsTo, RelAuthored,
		RelUsesTech, RelChildOf, RelReferences, RelDiscoveredFrom:
		return true
	}
	return false
}

// Entity is the in-memory representation of one entity row. Same-project
// dedup is enforced by the storage layer via a UNIQUE (project_id, kind,
// value) constraint; callers should canonicalize values via Canonicalize
// before write, never after.
type Entity struct {
	ID         string
	ProjectID  string
	Kind       Kind
	Value      string
	Attributes map[string]any
}

// Relation is a directed edge between two entities within one project.
// The same-project invariant is a storage-layer check (see comments in
// the Python event hook); the value type doesn't enforce it because the
// FK shape is owned by the repository.
type Relation struct {
	ID         string
	ProjectID  string
	SrcID      string
	DstID      string
	Kind       RelationKind
	Attributes map[string]any
}

// Canonicalize normalizes value so dedup behaves consistently across
// collectors. Without this, "Example.com" and "example.com" (or
// "USER@example.com" and "user@example.com") would land as separate
// entities depending on which tool produced them. Mirrors
// lantern.models.entities.canonicalize_entity_value exactly — every
// branch carries a parity test.
func Canonicalize(kind Kind, value string) string {
	raw := strings.TrimSpace(value)
	if raw == "" {
		return raw
	}
	switch kind {
	case KindDomain, KindSubdomain:
		return strings.TrimRight(strings.ToLower(raw), ".")
	case KindEmail:
		return strings.ToLower(raw)
	case KindIP:
		// netip.ParseAddr returns the compressed form via String();
		// matches Python's ipaddress.ip_address() str().
		if addr, err := netip.ParseAddr(raw); err == nil {
			return strings.ToLower(addr.String())
		}
		return raw
	case KindURL:
		return canonicalizeURL(raw)
	case KindRepository:
		return canonicalizeRepo(raw)
	}
	return raw
}

func canonicalizeURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return raw
	}
	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	// Drop default ports.
	if (scheme == "http" && port == "80") || (scheme == "https" && port == "443") {
		port = ""
	}
	netloc := host
	if u.User != nil {
		netloc = u.User.String() + "@" + netloc
	}
	if port != "" {
		netloc = netloc + ":" + port
	}
	path := u.Path
	// Strip trailing slash on a root-only path so "https://x" and
	// "https://x/" dedup. Other paths keep their slashes verbatim.
	if path == "/" {
		path = ""
	}
	out := scheme + "://" + netloc + path
	if u.RawQuery != "" {
		out += "?" + u.RawQuery
	}
	if u.Fragment != "" {
		out += "#" + u.Fragment
	}
	return out
}

// canonicalizeRepo normalizes a git repository identifier to
// https://host/owner/repo. Accepts https URLs, git@host:owner/repo SSH
// shorthand, and bare host/owner/repo strings. Strips trailing ".git",
// query, fragment. Anything we can't parse comes back unchanged so an
// upstream tool can still surface it.
func canonicalizeRepo(raw string) string {
	text := raw
	if strings.HasPrefix(text, "git@") {
		// git@github.com:Owner/Repo.git -> https://github.com/Owner/Repo.git
		body := text[len("git@"):]
		if i := strings.Index(body, ":"); i > 0 {
			text = "https://" + body[:i] + "/" + body[i+1:]
		}
	}
	if !strings.Contains(text, "://") {
		text = "https://" + text
	}
	u, err := url.Parse(text)
	if err != nil {
		return raw
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return raw
	}
	path := strings.Trim(u.Path, "/")
	path = strings.ToLower(path)
	if strings.HasSuffix(path, ".git") {
		path = path[:len(path)-len(".git")]
	}
	if path == "" {
		return raw
	}
	return "https://" + host + "/" + path
}
