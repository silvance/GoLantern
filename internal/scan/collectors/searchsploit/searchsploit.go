// Package searchsploit wraps the searchsploit CLI from exploit-db
// for offline known-exploit lookup. Bridges GoLantern's "discovered
// tech version" outputs (from wpscan, whatweb, nuclei) to "here are
// known public exploits for that version."
//
// Pure offline lookup: searchsploit queries the local ExploitDB
// clone, no network calls. Required scope is passive because the
// collector itself never touches a target.
package searchsploit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/silvance/golantern/internal/entity"
	"github.com/silvance/golantern/internal/fact"
	"github.com/silvance/golantern/internal/finding"
	"github.com/silvance/golantern/internal/scan"
	"github.com/silvance/golantern/internal/scope"
	"github.com/silvance/golantern/internal/subprocess"
	"github.com/silvance/golantern/internal/workflow"
)

const (
	Name           = "searchsploit"
	defaultBinary  = "searchsploit"
	defaultTimeout = 120 * time.Second
)

func New() scan.Collector { return &collector{} }

type runnerFn func(ctx context.Context, spec subprocess.Spec) (subprocess.Result, error)

func newWithRunner(r runnerFn) scan.Collector { return &collector{runner: r} }

type collector struct{ runner runnerFn }

func (collector) Metadata() scan.Meta {
	return scan.Meta{
		Name:           Name,
		Phase:          workflow.PhaseEnrichment,
		RequiredScope:  scope.KindPassive,
		Description:    "Offline known-exploit lookup against the ExploitDB clone. Consumes TECHNOLOGY entities (e.g. 'wordpress/5.7.1') and emits one finding per matching public exploit.",
		Consumes:       []entity.Kind{entity.KindTechnology},
		Produces:       nil,
		SourceCategory: finding.SourcePublicOSINT,
		Binary:         "searchsploit",
		InstallHint: "Fedora: sudo dnf install exploitdb\n" +
			"Debian/Ubuntu: sudo apt install exploitdb\n" +
			"From source: git clone https://gitlab.com/exploit-database/exploitdb.git /opt/exploitdb && sudo ln -s /opt/exploitdb/searchsploit /usr/local/bin/searchsploit",
		Parameters: []scan.ParameterSpec{
			{Name: "queries", Type: "string_list", Placeholder: "wordpress 5.7.1",
				Description: "Explicit search queries. Empty derives queries from TECHNOLOGY entities (slash-separated tech values are normalized to space-separated)."},
			{Name: "max_per_query", Type: "int", Default: 20,
				Description: "Cap on exploits emitted per query; protects against very noisy version matches."},
			{Name: "binary", Type: "string", Default: "searchsploit"},
			{Name: "timeout_seconds", Type: "float", Default: 120.0},
		},
	}
}

// searchsploitJSON matches the --json output shape. RESULTS_EXPLOIT
// is the standard hits array; RESULTS_SHELLCODE is occasionally
// populated too.
type searchsploitJSON struct {
	ResultsExploit []searchsploitHit `json:"RESULTS_EXPLOIT"`
}

type searchsploitHit struct {
	Title    string `json:"Title"`
	Type     string `json:"Type"`
	Platform string `json:"Platform"`
	Path     string `json:"Path"`
	URL      string `json:"URL"`
	Date     string `json:"Date_Published"`
	EDBID    string `json:"EDB-ID"`
	Author   string `json:"Author"`
	CVE      string `json:"Codes"`
}

func (c *collector) Run(ctx context.Context, cctx scan.Context) error {
	binary := strings.TrimSpace(toString(cctx.Parameters()["binary"]))
	if binary == "" {
		binary = defaultBinary
	}
	timeout := parseTimeout(cctx.Parameters()["timeout_seconds"])
	maxPerQuery := parsePositiveInt(cctx.Parameters()["max_per_query"], 20)

	queries, err := c.resolveQueries(cctx)
	if err != nil {
		return err
	}
	if len(queries) == 0 {
		return errors.New("searchsploit: no queries; pass parameters[\"queries\"] or seed TECHNOLOGY entities")
	}

	run := c.runner
	if run == nil {
		run = subprocess.Run
	}

	emitted := 0
	for _, q := range queries {
		args := []string{"--json", "--colour", q}
		result, err := run(ctx, subprocess.Spec{
			Binary:         binary,
			Args:           args,
			Timeout:        timeout,
			AllowPartialRC: []int{1, 2},
		})
		if err != nil {
			_ = cctx.EmitEvidence(fact.EvidenceFact{
				SourceTool:     Name,
				SourceCategory: finding.SourcePublicOSINT,
				Confidence:     finding.ConfidenceLow,
				Payload:        map[string]any{"query": q, "error": err.Error()},
			})
			continue
		}
		var parsed searchsploitJSON
		if err := json.Unmarshal(result.Stdout, &parsed); err != nil {
			_ = cctx.EmitEvidence(fact.EvidenceFact{
				SourceTool:     Name,
				SourceCategory: finding.SourcePublicOSINT,
				Confidence:     finding.ConfidenceLow,
				Payload:        map[string]any{"query": q, "parse_error": err.Error()},
			})
			continue
		}
		hits := parsed.ResultsExploit
		if len(hits) > maxPerQuery {
			hits = hits[:maxPerQuery]
		}
		for _, h := range hits {
			sev := severityFor(h)
			cves := splitCVE(h.CVE)
			desc := h.Title
			if h.Date != "" {
				desc += fmt.Sprintf(" (published %s)", h.Date)
			}
			if h.Path != "" {
				desc += " — local: " + h.Path
			}
			if _, err := cctx.EmitFinding(fact.FindingFact{
				Title:       fmt.Sprintf("Known exploit: %s — %s", q, h.Title),
				Severity:    sev,
				Confidence:  finding.ConfidenceMedium,
				Category:    "exploitdb",
				Description: desc,
				Attributes: map[string]any{
					"query":      q,
					"edb_id":     h.EDBID,
					"platform":   h.Platform,
					"exploit_url": h.URL,
					"local_path": h.Path,
					"date":       h.Date,
					"author":     h.Author,
					"cve":        cves,
				},
				SupportingEntities: []fact.EntityRef{{Kind: entity.KindTechnology, Value: q}},
			}); err != nil {
				return err
			}
			emitted++
		}
		_ = cctx.EmitEvidence(fact.EvidenceFact{
			SourceTool:     Name,
			SourceCategory: finding.SourcePublicOSINT,
			Confidence:     finding.ConfidenceHigh,
			Payload: map[string]any{
				"query":         q,
				"hits":          len(parsed.ResultsExploit),
				"hits_emitted":  len(hits),
				"max_per_query": maxPerQuery,
			},
		})
	}
	return cctx.EmitEvidence(fact.EvidenceFact{
		SourceTool:     Name,
		SourceCategory: finding.SourcePublicOSINT,
		Confidence:     finding.ConfidenceHigh,
		Payload: map[string]any{
			"queries":          len(queries),
			"findings_emitted": emitted,
		},
	})
}

// severityFor maps the searchsploit Type column to a severity floor.
// RCE / privileges-style exploits land high; DoS lands medium;
// everything else is medium.
func severityFor(h searchsploitHit) finding.Severity {
	title := strings.ToLower(h.Title)
	switch {
	case strings.Contains(title, "remote code execution"),
		strings.Contains(title, "rce"),
		strings.Contains(title, "command injection"),
		strings.Contains(title, "unauthenticated"),
		strings.Contains(title, "privilege escalation"):
		return finding.SeverityHigh
	case strings.Contains(title, "denial of service"),
		strings.Contains(title, "dos"):
		return finding.SeverityMedium
	default:
		return finding.SeverityMedium
	}
}

func splitCVE(raw string) []string {
	if raw == "" {
		return nil
	}
	var out []string
	for _, part := range strings.Split(raw, ";") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(strings.ToUpper(part), "CVE-") {
			out = append(out, part)
		}
	}
	return out
}

func (c *collector) resolveQueries(cctx scan.Context) ([]string, error) {
	explicit := parseStringList(cctx.Parameters()["queries"])
	if len(explicit) > 0 {
		out := make([]string, 0, len(explicit))
		for _, q := range explicit {
			if q = strings.TrimSpace(q); q != "" {
				out = append(out, q)
			}
		}
		if len(out) > 0 {
			return out, nil
		}
	}
	techs, err := cctx.ListEntityValues(entity.KindTechnology)
	if err != nil {
		return nil, err
	}
	seen := map[string]struct{}{}
	var out []string
	for _, t := range techs {
		q := normalizeTechQuery(t)
		if q == "" {
			continue
		}
		if _, dup := seen[q]; dup {
			continue
		}
		seen[q] = struct{}{}
		out = append(out, q)
	}
	return out, nil
}

// normalizeTechQuery turns "wordpress/5.7.1" or "wp-plugin/contact-form-7/5.3.1"
// into a space-separated query searchsploit can use. Drops the
// product-type prefix because searchsploit treats free-text queries
// as ANDed substrings.
func normalizeTechQuery(t string) string {
	t = strings.TrimSpace(t)
	if t == "" {
		return ""
	}
	parts := strings.Split(t, "/")
	// Drop a leading "wp-plugin" / "wp-theme" prefix; the real
	// component name is the second slash-delimited segment.
	if len(parts) > 1 {
		switch parts[0] {
		case "wp-plugin", "wp-theme":
			parts = parts[1:]
		}
	}
	return strings.Join(parts, " ")
}

func parseTimeout(v any) time.Duration {
	switch x := v.(type) {
	case float64:
		if x > 0 {
			return time.Duration(x * float64(time.Second))
		}
	case int:
		if x > 0 {
			return time.Duration(x) * time.Second
		}
	}
	return defaultTimeout
}

func parsePositiveInt(v any, fallback int) int {
	switch x := v.(type) {
	case float64:
		if x > 0 {
			return int(x)
		}
	case int:
		if x > 0 {
			return x
		}
	}
	return fallback
}

func parseStringList(v any) []string {
	switch s := v.(type) {
	case []string:
		return s
	case []any:
		out := make([]string, 0, len(s))
		for _, x := range s {
			if str, ok := x.(string); ok {
				out = append(out, str)
			}
		}
		return out
	case string:
		if s == "" {
			return nil
		}
		return []string{s}
	}
	return nil
}

func toString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}
