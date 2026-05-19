// Package nuclei wraps ProjectDiscovery's nuclei template-driven
// scanner. First CLI-wrapping collector that produces Findings rather
// than just entities.
//
// Conservative gating by default: only "low-impact" template
// categories run (exposure / misconfig / tech / ssl / panel /
// default-login / dns / config) and anything tagged fuzz / dos /
// intrusive / sqli / xss / rce / lfi / ssrf / ssti / oast is
// excluded. Analysts can override via parameters; an explicit empty
// list disables filtering on that axis.
//
// Ported from lantern/tools/nuclei.py.
package nuclei

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
	Name             = "nuclei"
	defaultBinary    = "nuclei"
	defaultTimeout   = 600 * time.Second
	defaultMaxTargets = 100
)

var (
	defaultTags = []string{
		"exposure", "misconfig", "tech", "dns", "ssl", "config",
		"panel", "default-login",
	}
	defaultExcludeTags = []string{
		"fuzz", "dos", "intrusive", "sqli", "xss", "rce",
		"lfi", "ssrf", "ssti", "oast",
	}
	defaultSeverities = []string{"low", "medium", "high", "critical"}
)

// forbiddenExtraArgPrefixes blocks flags that would redirect output
// (desynchronizing the JSONL parser) or load templates / config from
// caller-supplied locations (turning the collector into an arbitrary-
// template-execution surface). Matched as a bare prefix so both
// `-flag value` and `-flag=value` forms reject identically.
var forbiddenExtraArgPrefixes = []string{
	// output redirection / format
	"-o", "--output", "-output",
	"-or", "--output-redirect",
	"-jsonl", "--jsonl", "-json", "--json",
	"-csv", "-html", "-markdown", "-md",
	"-stats-json", "--stats-json",
	"-irr", "-include-rr",
	// template / workflow / config loading
	"-t", "-templates", "--templates",
	"-w", "-workflows", "--workflows",
	"-tu", "-template-url", "--template-url",
	"-wu", "-workflow-url", "--workflow-url",
	"-config", "--config",
	"-iu", "-interactsh-url", "--interactsh-url",
	"-iserver", "--interactsh-server",
	// update side effects
	"-update", "--update",
	"-update-templates", "--update-templates",
	"-ud", "-update-directory", "--update-directory",
}

func validateExtraArgs(args []string) error {
	for _, arg := range args {
		head := arg
		if i := strings.Index(arg, "="); i > 0 {
			head = arg[:i]
		}
		for _, forbidden := range forbiddenExtraArgPrefixes {
			if head == forbidden {
				return fmt.Errorf("nuclei extra_args contains forbidden flag %q "+
					"(matches %q); blocked because it would redirect output, "+
					"change format, or load remote templates/config", arg, forbidden)
			}
		}
	}
	return nil
}

var severityMap = map[string]finding.Severity{
	"info":     finding.SeverityInfo,
	"unknown":  finding.SeverityInfo,
	"low":      finding.SeverityLow,
	"medium":   finding.SeverityMedium,
	"high":     finding.SeverityHigh,
	"critical": finding.SeverityCritical,
}

func New() scan.Collector { return &collector{} }

type runnerFn func(ctx context.Context, spec subprocess.Spec) (subprocess.Result, error)

func newWithRunner(r runnerFn) scan.Collector { return &collector{runner: r} }

type collector struct{ runner runnerFn }

func (collector) Metadata() scan.Meta {
	return scan.Meta{
		Name:               Name,
		Phase:              workflow.PhaseExposure,
		RequiredScope:      scope.KindFullActive,
		Description:        "Run nuclei against in-scope URLs with a conservative tag allowlist; emit a Lantern Finding per non-info hit.",
		Consumes:           []entity.Kind{entity.KindURL},
		SourceCategory:     finding.SourceActiveScan,
		TriggersOnServices: []string{"http", "https"},
		Binary:             "nuclei",
		InstallHint: "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest\n" +
			"# Templates auto-update on first run; `nuclei -update-templates` to refresh.",
		Parameters: []scan.ParameterSpec{
			{Name: "targets", Type: "string_list", Placeholder: "https://api.example.com",
				Description: "URLs to scan. Empty falls back to every URL entity in the project."},
			{Name: "severities", Type: "string_list",
				Description: "Severity floor (default low,medium,high,critical). Hits below the floor are dropped."},
			{Name: "tags", Type: "string_list",
				Description: "Template tag allowlist. Empty list (not unset) disables filtering."},
			{Name: "exclude_tags", Type: "string_list",
				Description: "Template tags to forbid. Empty list (not unset) disables filtering."},
			{Name: "max_targets", Type: "int", Default: 100,
				Description: "Cap on the number of URLs scanned in one run."},
			{Name: "binary", Type: "string", Default: "nuclei",
				Description: "Override the nuclei binary path or name."},
			{Name: "timeout_seconds", Type: "float", Default: 600.0,
				Description: "Wall-clock timeout in seconds for the nuclei subprocess."},
			{Name: "extra_args", Type: "string_list",
				Description: "Extra nuclei flags. Output-redirection and template-source flags are rejected."},
		},
	}
}

// nucleiJSON is the JSONL shape we consume. Unknown fields ignored.
type nucleiJSON struct {
	TemplateID  string   `json:"template-id"`
	TemplateID2 string   `json:"templateID"` // alternate spelling
	Host        string   `json:"host"`
	MatchedAt   string   `json:"matched-at"`
	MatcherName string   `json:"matcher-name"`
	Extracted   []string `json:"extracted-results"`
	Info        struct {
		Name     string          `json:"name"`
		Severity string          `json:"severity"`
		Tags     json.RawMessage `json:"tags"` // string OR []string
	} `json:"info"`
}

type nucleiResult struct {
	TemplateID  string
	Name        string
	Severity    finding.Severity
	RawSeverity string
	Tags        []string
	Host        string
	MatchedAt   string
	MatcherName string
	Extracted   []string
}

func parseJSONL(blob []byte) []nucleiResult {
	var out []nucleiResult
	for _, raw := range strings.Split(string(blob), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		var rec nucleiJSON
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			continue
		}
		tid := rec.TemplateID
		if tid == "" {
			tid = rec.TemplateID2
		}
		host := rec.Host
		if host == "" {
			host = rec.MatchedAt
		}
		if tid == "" || host == "" {
			continue
		}
		rawSev := strings.ToLower(strings.TrimSpace(rec.Info.Severity))
		if rawSev == "" {
			rawSev = "info"
		}
		sev, ok := severityMap[rawSev]
		if !ok {
			sev = finding.SeverityInfo
		}
		out = append(out, nucleiResult{
			TemplateID:  tid,
			Name:        firstNonEmpty(rec.Info.Name, tid),
			Severity:    sev,
			RawSeverity: rawSev,
			Tags:        parseTags(rec.Info.Tags),
			Host:        host,
			MatchedAt:   rec.MatchedAt,
			MatcherName: rec.MatcherName,
			Extracted:   rec.Extracted,
		})
	}
	return out
}

// parseTags handles nuclei's mixed serialization: tags is sometimes a
// comma-separated string, sometimes a JSON array of strings.
func parseTags(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		parts := strings.Split(s, ",")
		out := make([]string, 0, len(parts))
		for _, p := range parts {
			if p = strings.TrimSpace(p); p != "" {
				out = append(out, p)
			}
		}
		return out
	}
	var arr []string
	if err := json.Unmarshal(raw, &arr); err == nil {
		out := make([]string, 0, len(arr))
		for _, t := range arr {
			if t = strings.TrimSpace(t); t != "" {
				out = append(out, t)
			}
		}
		return out
	}
	return nil
}

func (c *collector) Run(ctx context.Context, cctx scan.Context) error {
	binary := strings.TrimSpace(toString(cctx.Parameters()["binary"]))
	if binary == "" {
		binary = defaultBinary
	}
	timeout := parseTimeout(cctx.Parameters()["timeout_seconds"])
	maxTargets := parsePositiveInt(cctx.Parameters()["max_targets"], defaultMaxTargets)
	extraArgs := parseStringList(cctx.Parameters()["extra_args"])
	if err := validateExtraArgs(extraArgs); err != nil {
		return err
	}

	tags := csvParam(cctx.Parameters()["tags"], defaultTags)
	excludeTags := csvParam(cctx.Parameters()["exclude_tags"], defaultExcludeTags)
	severities := csvParam(cctx.Parameters()["severities"], defaultSeverities)

	targets, err := c.resolveTargets(cctx)
	if err != nil {
		return err
	}
	var inScope []string
	for _, t := range targets {
		if cctx.IsInScope(t) {
			inScope = append(inScope, t)
		}
	}
	skipped := len(targets) - len(inScope)
	capped := 0
	if len(inScope) > maxTargets {
		capped = len(inScope) - maxTargets
		inScope = inScope[:maxTargets]
	}
	if len(inScope) == 0 {
		return nil
	}

	args := []string{
		"-silent",
		"-jsonl",
		"-no-color",
		"-disable-update-check",
		"-severity", strings.Join(severities, ","),
	}
	if len(tags) > 0 {
		args = append(args, "-tags", strings.Join(tags, ","))
	}
	if len(excludeTags) > 0 {
		args = append(args, "-exclude-tags", strings.Join(excludeTags, ","))
	}
	args = append(args, extraArgs...)
	stdin := []byte(strings.Join(inScope, "\n") + "\n")

	run := c.runner
	if run == nil {
		run = subprocess.Run
	}
	result, err := run(ctx, subprocess.Spec{
		Binary:  binary,
		Args:    args,
		Stdin:   stdin,
		Timeout: timeout,
	})
	if err != nil {
		return fmt.Errorf("nuclei: %w", err)
	}

	results := parseJSONL(result.Stdout)
	findingsEmitted := 0
	infoOnly := 0
	perSeverity := map[string]int{}

	for _, r := range results {
		perSeverity[string(r.Severity)]++
		if r.Severity == finding.SeverityInfo {
			// nuclei's "info" tier stays as evidence — promoting it to
			// findings would flood the report with noise.
			infoOnly++
			if err := cctx.EmitEvidence(fact.EvidenceFact{
				SourceTool:     Name,
				SourceCategory: finding.SourceActiveScan,
				Confidence:     finding.ConfidenceMedium,
				Payload: map[string]any{
					"template_id": r.TemplateID,
					"name":        r.Name,
					"tags":        r.Tags,
					"matched_at":  r.MatchedAt,
					"extracted":   r.Extracted,
				},
				EntityKind:  entity.KindURL,
				EntityValue: r.Host,
			}); err != nil {
				return err
			}
			continue
		}
		findingsEmitted++
		primaryTag := "misc"
		if len(r.Tags) > 0 {
			primaryTag = r.Tags[0]
		}
		desc := fmt.Sprintf("Template %q matched at %s.", r.TemplateID, firstNonEmpty(r.MatchedAt, r.Host))
		if _, err := cctx.EmitFinding(fact.FindingFact{
			Title:      fmt.Sprintf("nuclei: %s on %s", r.Name, r.Host),
			Severity:   r.Severity,
			Confidence: finding.ConfidenceMedium,
			Category:   "nuclei." + primaryTag,
			Description: desc,
			Attributes: map[string]any{
				"template_id":     r.TemplateID,
				"tags":            r.Tags,
				"matcher_name":    r.MatcherName,
				"matched_at":      r.MatchedAt,
				"extracted":       r.Extracted,
				"nuclei_severity": r.RawSeverity,
			},
			SupportingEntities: []fact.EntityRef{{Kind: entity.KindURL, Value: r.Host}},
		}); err != nil {
			return err
		}
	}

	return cctx.EmitEvidence(fact.EvidenceFact{
		SourceTool:     Name,
		SourceCategory: finding.SourceActiveScan,
		Confidence:     finding.ConfidenceHigh,
		Payload: map[string]any{
			"targets_input":                len(targets),
			"targets_skipped_out_of_scope": skipped,
			"targets_capped_by_max":        capped,
			"targets_scanned":              len(inScope),
			"results_total":                len(results),
			"findings_emitted":             findingsEmitted,
			"info_only_rows":               infoOnly,
			"per_severity":                 perSeverity,
			"tags":                         tags,
			"exclude_tags":                 excludeTags,
			"severities":                   severities,
		},
	})
}

func (c *collector) resolveTargets(cctx scan.Context) ([]string, error) {
	explicit := parseStringList(cctx.Parameters()["targets"])
	if len(explicit) > 0 {
		out := make([]string, 0, len(explicit))
		for _, t := range explicit {
			if t = strings.TrimSpace(t); t != "" {
				out = append(out, t)
			}
		}
		if len(out) > 0 {
			return out, nil
		}
	}
	values, err := cctx.ListEntityValues(entity.KindURL)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, v := range values {
		v = strings.TrimSpace(v)
		lv := strings.ToLower(v)
		if strings.HasPrefix(lv, "http://") || strings.HasPrefix(lv, "https://") {
			out = append(out, v)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("nuclei: no targets to scan; pass parameters[\"targets\"] or seed URL entities")
	}
	return out, nil
}

// csvParam accepts nil (use default), a []string/[]any list, or a CSV
// string. An explicit empty list disables filtering on that axis,
// matching the Python contract.
func csvParam(v any, fallback []string) []string {
	switch x := v.(type) {
	case nil:
		out := make([]string, len(fallback))
		copy(out, fallback)
		return out
	case string:
		if x == "" {
			return nil // explicit-empty disables filtering
		}
		parts := strings.Split(x, ",")
		out := make([]string, 0, len(parts))
		for _, p := range parts {
			if p = strings.TrimSpace(p); p != "" {
				out = append(out, p)
			}
		}
		return out
	case []string:
		return x // empty slice respected
	case []any:
		out := make([]string, 0, len(x))
		for _, e := range x {
			if s, ok := e.(string); ok && strings.TrimSpace(s) != "" {
				out = append(out, strings.TrimSpace(s))
			}
		}
		return out
	}
	out := make([]string, len(fallback))
	copy(out, fallback)
	return out
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

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
