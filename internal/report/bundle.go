// Package report builds and renders project report bundles.
//
// Mirrors lantern.reports.base.ReportBundle and the html/csv
// renderers. PDF and DOCX renderers land later (PDF needs chromedp
// or an external Gotenberg; DOCX wants unidoc/templates). Schedule
// diffs are omitted until the scheduler ports.
//
// The bundle is plain data so renderers stay decoupled from the
// aggregation logic. Generate is a single repository round per
// domain (projects, entities, findings, evidence, runs); evidence is
// grouped client-side rather than per-finding to keep cost predictable
// on projects with hundreds of findings.
package report

import (
	"context"
	"fmt"
	"sort"

	"github.com/silvance/golantern/internal/audit"
	"github.com/silvance/golantern/internal/entity"
	"github.com/silvance/golantern/internal/finding"
	"github.com/silvance/golantern/internal/project"
	"github.com/silvance/golantern/internal/run"
	"github.com/silvance/golantern/internal/workflow"
)

// Bundle is the serializable aggregate every renderer consumes.
//
// EntitiesByKind is keyed by entity kind string ("domain", "ip", ...)
// so the UI / SPA can index by kind without checking for nil; every
// known kind is present with at least an empty slice when Generate
// runs.
type Bundle struct {
	Project        ProjectView             `json:"project"`
	Summary        Summary                 `json:"summary"`
	EntitiesByKind map[string][]EntityView `json:"entities_by_kind"`
	Findings       []FindingView           `json:"findings"`
	Runs           []RunView               `json:"runs"`
}

type ProjectView struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	Organization   string `json:"organization,omitempty"`
	Description    string `json:"description,omitempty"`
	DefaultScope   string `json:"default_scope"`
	Mode           string `json:"mode"`
	ReportTemplate string `json:"report_template"`
}

type Summary struct {
	EntitiesTotal int `json:"entities_total"`
	FindingsTotal int `json:"findings_total"`
	RunsTotal     int `json:"runs_total"`
}

type EntityView struct {
	ID         string         `json:"id"`
	Kind       string         `json:"kind"`
	Value      string         `json:"value"`
	Attributes map[string]any `json:"attributes,omitempty"`
}

type FindingView struct {
	ID             string         `json:"id"`
	Title          string         `json:"title"`
	Severity       string         `json:"severity"`
	Confidence     string         `json:"confidence"`
	Category       string         `json:"category,omitempty"`
	Description    string         `json:"description,omitempty"`
	Recommendation string         `json:"recommendation,omitempty"`
	Attributes     map[string]any `json:"attributes,omitempty"`
	Evidence       []EvidenceView `json:"evidence"`
}

type EvidenceView struct {
	ID             string         `json:"id"`
	SourceTool     string         `json:"source_tool"`
	SourceCategory string         `json:"source_category"`
	Confidence     string         `json:"confidence"`
	Payload        map[string]any `json:"payload,omitempty"`
	Notes          string         `json:"notes,omitempty"`
}

type RunView struct {
	ID     string `json:"id"`
	Phase  string `json:"phase"`
	Status string `json:"status"`
	Label  string `json:"label,omitempty"`
}

// Deps wires the repositories Generate needs. Audit is unused for
// bundle assembly today but kept in the struct for symmetry — the
// bundle will eventually include a per-project audit excerpt for
// compliance evidence.
type Deps struct {
	Projects project.Repository
	Entities entity.Repository
	Findings finding.Repository
	Runs     run.Repository
	Audit    audit.Repository
}

// Options tunes Generate. Zero values are sensible defaults.
type Options struct {
	// IncludeAllFindings: when true, include every finding regardless
	// of any "reportable" flag. The Go domain model doesn't carry
	// reportable yet (lands with the SQLite findings store), so the
	// option is a no-op today and every finding is included. The
	// field is here so callers can pass the future intent without
	// breaking API parity.
	IncludeAllFindings bool
}

// Generate assembles a Bundle for projectID. Errors surface only for
// missing-project or repository-infra failures.
func Generate(ctx context.Context, deps Deps, projectID string, _ Options) (*Bundle, error) {
	p, err := deps.Projects.Get(ctx, projectID)
	if err != nil {
		return nil, fmt.Errorf("report.Generate: %w", err)
	}
	entities, err := deps.Entities.ListByProject(ctx, projectID)
	if err != nil {
		return nil, fmt.Errorf("report.Generate: list entities: %w", err)
	}
	findings, err := deps.Findings.ListFindings(ctx, projectID)
	if err != nil {
		return nil, fmt.Errorf("report.Generate: list findings: %w", err)
	}
	allEvidence, err := deps.Findings.ListEvidence(ctx, projectID)
	if err != nil {
		return nil, fmt.Errorf("report.Generate: list evidence: %w", err)
	}
	runs, err := deps.Runs.ListByProject(ctx, projectID)
	if err != nil {
		return nil, fmt.Errorf("report.Generate: list runs: %w", err)
	}

	// Group entities by kind. Every defined kind gets an entry so
	// renderers can index without nil-checking.
	entitiesByKind := make(map[string][]EntityView, 12)
	for _, k := range allKindStrings() {
		entitiesByKind[k] = []EntityView{}
	}
	for _, e := range entities {
		entitiesByKind[string(e.Kind)] = append(entitiesByKind[string(e.Kind)], EntityView{
			ID: e.ID, Kind: string(e.Kind), Value: e.Value, Attributes: e.Attributes,
		})
	}

	// Group evidence by finding_id in one pass.
	evByFinding := make(map[string][]EvidenceView, len(allEvidence))
	for _, e := range allEvidence {
		if e.FindingID == "" {
			continue
		}
		evByFinding[e.FindingID] = append(evByFinding[e.FindingID], EvidenceView{
			ID:             e.ID,
			SourceTool:     e.SourceTool,
			SourceCategory: string(e.SourceCategory),
			Confidence:     string(e.Confidence),
			Payload:        e.Payload,
			Notes:          e.Notes,
		})
	}

	// Sort findings by severity (critical first) for stable rendering.
	sort.SliceStable(findings, func(i, j int) bool {
		return findings[i].Severity.SortKey() < findings[j].Severity.SortKey()
	})
	findingViews := make([]FindingView, 0, len(findings))
	for _, f := range findings {
		ev := evByFinding[f.ID]
		if ev == nil {
			ev = []EvidenceView{}
		}
		findingViews = append(findingViews, FindingView{
			ID:             f.ID,
			Title:          f.Title,
			Severity:       string(f.Severity),
			Confidence:     string(f.Confidence),
			Category:       f.Category,
			Description:    f.Description,
			Recommendation: f.Recommendation,
			Attributes:     f.Attributes,
			Evidence:       ev,
		})
	}

	// Python orders runs ascending by created_at for the report; the
	// repo's default ListByProject returns newest-first, so reverse.
	runViews := make([]RunView, 0, len(runs))
	for i := len(runs) - 1; i >= 0; i-- {
		r := runs[i]
		runViews = append(runViews, RunView{
			ID: r.ID, Phase: string(r.Phase), Status: string(r.Status), Label: r.Label,
		})
	}

	return &Bundle{
		Project: ProjectView{
			ID:             p.ID,
			Name:           p.Name,
			Organization:   p.Organization,
			Description:    p.Description,
			DefaultScope:   string(p.DefaultScope),
			Mode:           string(p.Mode),
			ReportTemplate: workflow.PresetFor(p.Mode).ReportTemplate,
		},
		Summary: Summary{
			EntitiesTotal: len(entities),
			FindingsTotal: len(findings),
			RunsTotal:     len(runs),
		},
		EntitiesByKind: entitiesByKind,
		Findings:       findingViews,
		Runs:           runViews,
	}, nil
}

// allKindStrings returns every defined entity kind as a string. Used
// so the bundle ships an entry for each kind even when it's empty.
func allKindStrings() []string {
	return []string{
		string(entity.KindDomain), string(entity.KindSubdomain), string(entity.KindIP),
		string(entity.KindURL), string(entity.KindEmail), string(entity.KindPerson),
		string(entity.KindDocument), string(entity.KindTechnology), string(entity.KindPort),
		string(entity.KindService), string(entity.KindOrganization), string(entity.KindRepository),
	}
}
