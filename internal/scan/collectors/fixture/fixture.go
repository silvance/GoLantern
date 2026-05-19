// Package fixture is a synthetic collector for tests and demos. It
// emits a small, deterministic set of entities/relations/findings
// based on its parameters so the scan engine and downstream pipelines
// can be exercised end-to-end without standing up real external tools.
//
// Parameters honored:
//
//	"targets":        []string -- hosts to probe (each goes through
//	                              IsInScope; out-of-scope ones are
//	                              skipped)
//	"finding_title":  string   -- when set, emit a Finding with that
//	                              title backed by every in-scope
//	                              target as a supporting entity
//	"finding_severity": string -- defaults to "low"
//
// The fixture intentionally does not return errors on missing/empty
// parameters: defaults produce a no-op collector that the runner
// still records as COMPLETED. Tests that want failure paths can wrap
// this with a custom collector instead.
package fixture

import (
	"context"
	"fmt"

	"github.com/silvance/golantern/internal/entity"
	"github.com/silvance/golantern/internal/fact"
	"github.com/silvance/golantern/internal/finding"
	"github.com/silvance/golantern/internal/scan"
	"github.com/silvance/golantern/internal/scope"
	"github.com/silvance/golantern/internal/workflow"
)

const Name = "fixture"

// New returns a fresh collector. Stateless, so the same instance could
// be reused, but we return a new one to keep the factory contract honest.
func New() scan.Collector { return &collector{} }

type collector struct{}

func (collector) Metadata() scan.Meta {
	return scan.Meta{
		Name:           Name,
		Phase:          workflow.PhaseOSINT,
		RequiredScope:  scope.KindPassive,
		Description:    "Synthetic collector for tests; emits per parameters.",
		Produces:       []entity.Kind{entity.KindDomain, entity.KindIP},
		SourceCategory: finding.SourcePublicOSINT,
		Parameters: []scan.ParameterSpec{
			{Name: "targets", Type: "string_list", Description: "Targets to probe (each is scope-gated)."},
			{Name: "finding_title", Type: "string", Description: "If set, emit a Finding with this title."},
			{Name: "finding_severity", Type: "enum", Description: "low|medium|high|critical|info", Default: "low",
				Choices: []string{"info", "low", "medium", "high", "critical"}},
		},
	}
}

func (c collector) Run(_ context.Context, cctx scan.Context) error {
	targets, _ := stringList(cctx.Parameters()["targets"])
	var inScope []string
	for _, t := range targets {
		if cctx.IsInScope(t) {
			inScope = append(inScope, t)
		}
	}

	// Emit a Domain entity per in-scope target. Out-of-scope targets
	// are deliberately silently dropped — the runner's zero-emission
	// diagnostic surfaces the case where everything was rejected.
	supporting := make([]fact.EntityRef, 0, len(inScope))
	for _, t := range inScope {
		_, err := cctx.EmitEntity(fact.EntityFact{
			Kind:       entity.KindDomain,
			Value:      t,
			Attributes: map[string]any{"discovered_via": Name},
			Confidence: finding.ConfidenceMedium,
		})
		if err != nil {
			return fmt.Errorf("emit %s: %w", t, err)
		}
		supporting = append(supporting, fact.EntityRef{Kind: entity.KindDomain, Value: t})
	}

	if title, _ := cctx.Parameters()["finding_title"].(string); title != "" && len(supporting) > 0 {
		severity := finding.Severity("low")
		if sev, ok := cctx.Parameters()["finding_severity"].(string); ok && sev != "" {
			severity = finding.Severity(sev)
		}
		if _, err := cctx.EmitFinding(fact.FindingFact{
			Title:              title,
			Severity:           severity,
			Confidence:         finding.ConfidenceMedium,
			SupportingEntities: supporting,
		}); err != nil {
			return fmt.Errorf("emit finding: %w", err)
		}
	}
	return nil
}

// stringList accepts []string, []any (with string elements), or a
// single string and returns []string. Callers tolerate empty/nil as
// "no targets".
func stringList(v any) ([]string, bool) {
	switch s := v.(type) {
	case nil:
		return nil, true
	case []string:
		return s, true
	case []any:
		out := make([]string, 0, len(s))
		for _, x := range s {
			str, ok := x.(string)
			if !ok {
				return nil, false
			}
			out = append(out, str)
		}
		return out, true
	case string:
		return []string{s}, true
	}
	return nil, false
}
