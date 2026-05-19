package assistant

import (
	"fmt"
	"sort"
	"strings"

	"github.com/silvance/golantern/internal/report"
)

// BuildPrompt assembles the user-side message: a structured context
// block (entities + findings + runs from the report Bundle, with
// untrusted content wrapped via WrapUntrusted) followed by the
// analyst's question.
//
// We compress the bundle to a fixed-size summary rather than shipping
// the whole thing — LLM context windows are finite and most of the
// bundle is repetitive payload bytes. The summary covers what
// matters for "what should I do next?":
//
//   - Project name + mode + scope rules count
//   - Entity counts by kind + a sample of values per kind
//   - Findings with severity / title / category (full text in body
//     since these are operator-typed)
//   - Run phases + statuses (no parameters; those can carry secrets
//     even after redaction)
//
// Long bundles are truncated at maxEntitiesPerKind / maxFindings
// to keep token usage bounded.
func BuildPrompt(b *report.Bundle, question string) string {
	const (
		maxEntitiesPerKind = 20
		maxFindings        = 50
		maxRuns            = 20
	)

	var sb strings.Builder
	sb.WriteString("Project context follows. Untrusted content is wrapped between\n")
	sb.WriteString(openMarker + " ... " + closeMarker + " markers.\n\n")

	fmt.Fprintf(&sb, "Project: %s\n", b.Project.Name)
	fmt.Fprintf(&sb, "Mode: %s\n", b.Project.Mode)
	fmt.Fprintf(&sb, "Default scope: %s\n", b.Project.DefaultScope)
	if b.Project.Organization != "" {
		fmt.Fprintf(&sb, "Organization: %s\n", b.Project.Organization)
	}
	fmt.Fprintf(&sb, "\nSummary: %d entities, %d findings, %d runs.\n",
		b.Summary.EntitiesTotal, b.Summary.FindingsTotal, b.Summary.RunsTotal)

	// Entities by kind, sample of values per kind. Sorted kind keys
	// so the rendered context is deterministic across calls.
	sb.WriteString("\n--- Entities (sample per kind) ---\n")
	kinds := make([]string, 0, len(b.EntitiesByKind))
	for k := range b.EntitiesByKind {
		kinds = append(kinds, k)
	}
	sort.Strings(kinds)
	for _, k := range kinds {
		rs := b.EntitiesByKind[k]
		if len(rs) == 0 {
			continue
		}
		fmt.Fprintf(&sb, "%s (%d):\n", k, len(rs))
		shown := rs
		if len(shown) > maxEntitiesPerKind {
			shown = shown[:maxEntitiesPerKind]
		}
		for _, e := range shown {
			sb.WriteString("  " + WrapUntrusted(e.Value, k+" value") + "\n")
		}
		if len(rs) > maxEntitiesPerKind {
			fmt.Fprintf(&sb, "  (+%d more truncated)\n", len(rs)-maxEntitiesPerKind)
		}
	}

	// Findings — operator-typed titles/descriptions are technically
	// trusted, but we still wrap them as untrusted because a previous
	// collector run could have stuffed adversarial banner text into a
	// finding description via emit_finding.
	sb.WriteString("\n--- Findings ---\n")
	if len(b.Findings) == 0 {
		sb.WriteString("(none)\n")
	} else {
		shown := b.Findings
		if len(shown) > maxFindings {
			shown = shown[:maxFindings]
		}
		for _, f := range shown {
			fmt.Fprintf(&sb, "- [%s] %s (category=%s, evidence=%d)\n",
				strings.ToUpper(f.Severity), f.Title, f.Category, len(f.Evidence))
			if f.Description != "" {
				sb.WriteString("  description: " + WrapUntrusted(f.Description, "finding description") + "\n")
			}
			if f.Recommendation != "" {
				sb.WriteString("  recommendation: " + WrapUntrusted(f.Recommendation, "finding recommendation") + "\n")
			}
		}
		if len(b.Findings) > maxFindings {
			fmt.Fprintf(&sb, "(+%d more findings truncated)\n", len(b.Findings)-maxFindings)
		}
	}

	// Runs — phase + status only. Parameters can carry secrets even
	// after the runner's secret-shaped-key redaction, so we don't
	// include them in the LLM context.
	sb.WriteString("\n--- Runs ---\n")
	if len(b.Runs) == 0 {
		sb.WriteString("(none)\n")
	} else {
		shown := b.Runs
		if len(shown) > maxRuns {
			shown = shown[:maxRuns]
		}
		for _, r := range shown {
			fmt.Fprintf(&sb, "- phase=%s status=%s label=%q\n", r.Phase, r.Status, r.Label)
		}
		if len(b.Runs) > maxRuns {
			fmt.Fprintf(&sb, "(+%d more runs truncated)\n", len(b.Runs)-maxRuns)
		}
	}

	sb.WriteString("\n--- Analyst question ---\n")
	// The operator's question is trusted (they're the operator); no
	// wrapping. But we still strip our own marker tokens out of it
	// defensively in case the operator pasted in raw banner text
	// while writing the prompt.
	sb.WriteString(stripMarkers(question))
	return sb.String()
}
