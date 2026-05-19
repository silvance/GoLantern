// Package finding holds severity / confidence / source-category enums
// and the Evidence and Finding value types. Pure types; the persistence
// layer maps these into rows.
//
// Ported from lantern.models.findings. Sort and rank tables are kept
// here so a future severity addition only needs to update one place.
package finding

import (
	"context"
	"errors"
)

// ErrNotFound is returned by Repository lookups that miss.
var ErrNotFound = errors.New("finding: not found")

// Repository persists findings and the evidence rows attached to them
// (or attached directly to entities). Findings and evidence share a
// repository because the runner emits them in lockstep — a finding
// with supporting entities produces both kinds of rows in the same
// flush.
type Repository interface {
	CreateFinding(ctx context.Context, f *Finding) error
	CreateEvidence(ctx context.Context, e *Evidence) error
	ListFindings(ctx context.Context, projectID string) ([]*Finding, error)
	ListEvidence(ctx context.Context, projectID string) ([]*Evidence, error)
}

// Severity is the analyst-facing finding severity.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// allSeverities is the ranking source of truth; everything else
// (Valid, AtLeast, SortKey) derives from this slice so adding a new
// severity is one edit. Ordered low-to-high so the index is the rank.
var allSeverities = []Severity{
	SeverityInfo,
	SeverityLow,
	SeverityMedium,
	SeverityHigh,
	SeverityCritical,
}

func (s Severity) Valid() bool {
	for _, q := range allSeverities {
		if s == q {
			return true
		}
	}
	return false
}

// rank returns the threshold-comparison rank (higher = more severe).
// Unknown values return -1; combined with AtLeast that means an
// unknown severity never satisfies any threshold.
func (s Severity) rank() int {
	for i, q := range allSeverities {
		if s == q {
			return i
		}
	}
	return -1
}

// AtLeast reports whether s is at least as severe as threshold.
// Equivalent to lantern.models.findings.severity_at_least.
func (s Severity) AtLeast(threshold Severity) bool {
	if !s.Valid() || !threshold.Valid() {
		return false
	}
	return s.rank() >= threshold.rank()
}

// SortKey returns the sort order used in finding tables and report
// sections: critical first (0), info last (4). Inverted from rank
// because the two uses go opposite directions.
func (s Severity) SortKey() int {
	r := s.rank()
	if r < 0 {
		return len(allSeverities) // unknown sorts last
	}
	return len(allSeverities) - 1 - r
}

// Confidence is the collector's self-reported confidence in the fact.
type Confidence string

const (
	ConfidenceLow       Confidence = "low"
	ConfidenceMedium    Confidence = "medium"
	ConfidenceHigh      Confidence = "high"
	ConfidenceConfirmed Confidence = "confirmed"
)

func (c Confidence) Valid() bool {
	switch c {
	case ConfidenceLow, ConfidenceMedium, ConfidenceHigh, ConfidenceConfirmed:
		return true
	}
	return false
}

// SourceCategory captures where evidence came from. Drives the
// OSINT-vs-active distinction in reports.
type SourceCategory string

const (
	SourcePublicOSINT      SourceCategory = "public_osint"
	SourcePassiveDNS       SourceCategory = "passive_dns"
	SourceCertTransparency SourceCategory = "cert_transparency"
	SourceBreachIntel      SourceCategory = "breach_intel"
	SourceDocMetadata      SourceCategory = "doc_metadata"
	SourceLiveProbe        SourceCategory = "live_probe"
	SourceActiveScan       SourceCategory = "active_scan"
	SourceManual           SourceCategory = "manual"
)

func (s SourceCategory) Valid() bool {
	switch s {
	case SourcePublicOSINT, SourcePassiveDNS, SourceCertTransparency,
		SourceBreachIntel, SourceDocMetadata, SourceLiveProbe,
		SourceActiveScan, SourceManual:
		return true
	}
	return false
}

// Evidence is one observation linking an entity (or finding) back to a
// tool run. Provenance is immutable in this model: callers should add
// new Evidence rather than mutate existing ones.
type Evidence struct {
	ID              string
	ProjectID       string
	ToolExecutionID string
	EntityID        string // optional
	FindingID       string // optional
	SourceTool      string
	SourceCategory  SourceCategory
	Confidence      Confidence
	Payload         map[string]any
	ArtifactURI     string
	Notes           string
}

// Finding is an analyst-facing finding within a project.
type Finding struct {
	ID             string
	ProjectID      string
	Title          string
	Severity       Severity
	Confidence     Confidence
	Description    string
	Recommendation string
	Category       string
	Attributes     map[string]any
}
