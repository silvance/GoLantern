// Package wpscan wraps the wpscan Ruby gem for WordPress-targeted
// vulnerability assessment. WPScan is the de-facto WordPress audit
// tool; it identifies the WP version, enumerates plugins and themes,
// flags known-vulnerable versions, and reports exposed config files.
//
// The collector intentionally does NOT run username enumeration or
// password attacks by default — those are loud and often violate
// engagement rules of engagement. Enable them explicitly via the
// `enumerate` parameter when authorized.
package wpscan

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
	Name           = "wpscan"
	defaultBinary  = "wpscan"
	defaultTimeout = 900 * time.Second
)

func New() scan.Collector { return &collector{} }

type runnerFn func(ctx context.Context, spec subprocess.Spec) (subprocess.Result, error)

func newWithRunner(r runnerFn) scan.Collector { return &collector{runner: r} }

type collector struct{ runner runnerFn }

func (collector) Metadata() scan.Meta {
	return scan.Meta{
		Name:               Name,
		Phase:              workflow.PhaseExposure,
		RequiredScope:      scope.KindFullActive,
		Description:        "WordPress version, plugin, theme, and known-vulnerability scan via wpscan. Skips non-WP sites cleanly.",
		Consumes:           []entity.Kind{entity.KindURL},
		Produces:           []entity.Kind{entity.KindTechnology},
		SourceCategory:     finding.SourceActiveScan,
		TriggersOnServices: []string{"http", "https"},
		Binary:             "wpscan",
		InstallHint:        "Fedora: sudo dnf install ruby ruby-devel && gem install wpscan\nDebian/Ubuntu: sudo apt install ruby ruby-dev && gem install wpscan",
		Parameters: []scan.ParameterSpec{
			{Name: "targets", Type: "string_list", Placeholder: "https://blog.example.com",
				Description: "URLs to scan. Empty falls back to every URL entity in the project."},
			{Name: "enumerate", Type: "string", Default: "vp,vt", Placeholder: "vp,vt",
				Description: "WPScan -e options. Default 'vp,vt' = vulnerable plugins + themes. Add 'u' for usernames (loud)."},
			{Name: "api_token", Type: "string",
				Description: "Optional WPScan API token for enriched vulnerability data."},
			{Name: "binary", Type: "string", Default: "wpscan"},
			{Name: "timeout_seconds", Type: "float", Default: 900.0},
		},
	}
}

// wpscanJSON captures the slice of wpscan's --format=json output we care
// about. The full object is much larger; we deliberately surface only
// the security-relevant facts.
type wpscanJSON struct {
	TargetURL string `json:"target_url"`
	Version   struct {
		Number     string   `json:"number"`
		Status     string   `json:"status"`
		Confidence float64  `json:"confidence"`
		Vulns      []wpVuln `json:"vulnerabilities"`
	} `json:"version"`
	Plugins map[string]wpComponent `json:"plugins"`
	Themes  map[string]wpComponent `json:"themes"`
	// InterestingFindings can include config-file disclosures, debug
	// logs, backup files, and similar low-but-real exposures.
	InterestingFindings []wpInteresting `json:"interesting_findings"`
}

type wpComponent struct {
	Version struct {
		Number string `json:"number"`
	} `json:"version"`
	LatestVersion   string   `json:"latest_version"`
	Outdated        bool     `json:"outdated"`
	Vulnerabilities []wpVuln `json:"vulnerabilities"`
}

type wpVuln struct {
	Title      string   `json:"title"`
	FixedIn    string   `json:"fixed_in"`
	References struct {
		CVE     []string `json:"cve"`
		URL     []string `json:"url"`
		WPVulnDB []string `json:"wpvulndb"`
	} `json:"references"`
}

type wpInteresting struct {
	Type    string `json:"type"`
	URL     string `json:"url"`
	Message string `json:"to_s"`
}

func (c *collector) Run(ctx context.Context, cctx scan.Context) error {
	binary := strings.TrimSpace(toString(cctx.Parameters()["binary"]))
	if binary == "" {
		binary = defaultBinary
	}
	timeout := parseTimeout(cctx.Parameters()["timeout_seconds"])
	enumerate := strings.TrimSpace(toString(cctx.Parameters()["enumerate"]))
	if enumerate == "" {
		enumerate = "vp,vt"
	}
	apiToken := strings.TrimSpace(toString(cctx.Parameters()["api_token"]))

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
	if len(inScope) == 0 {
		return nil
	}

	run := c.runner
	if run == nil {
		run = subprocess.Run
	}

	totalFindings := 0
	totalScanned := 0
	for _, target := range inScope {
		args := []string{
			"--url", target,
			"--format", "json",
			"--no-banner",
			"--random-user-agent",
			"-e", enumerate,
		}
		if apiToken != "" {
			args = append(args, "--api-token", apiToken)
		}
		result, err := run(ctx, subprocess.Spec{
			Binary:         binary,
			Args:           args,
			Timeout:        timeout,
			AllowPartialRC: []int{1, 2, 3, 4, 5}, // wpscan uses non-zero RC for findings tier
		})
		if err != nil {
			_ = cctx.EmitEvidence(fact.EvidenceFact{
				SourceTool:     Name,
				SourceCategory: finding.SourceActiveScan,
				Confidence:     finding.ConfidenceLow,
				Payload:        map[string]any{"target": target, "error": err.Error()},
				EntityKind:     entity.KindURL,
				EntityValue:    target,
			})
			continue
		}
		totalScanned++
		emitted, err := c.processOutput(cctx, target, result.Stdout)
		if err != nil {
			return err
		}
		totalFindings += emitted
	}
	return cctx.EmitEvidence(fact.EvidenceFact{
		SourceTool:     Name,
		SourceCategory: finding.SourceActiveScan,
		Confidence:     finding.ConfidenceHigh,
		Payload: map[string]any{
			"targets_scanned":  totalScanned,
			"findings_emitted": totalFindings,
			"enumerate":        enumerate,
		},
	})
}

func (c *collector) processOutput(cctx scan.Context, target string, blob []byte) (int, error) {
	// wpscan sometimes emits a leading non-JSON line in verbose modes.
	// Find the first '{' and parse from there.
	idx := strings.IndexByte(string(blob), '{')
	if idx < 0 {
		return 0, nil
	}
	var rec wpscanJSON
	if err := json.Unmarshal(blob[idx:], &rec); err != nil {
		// Not WordPress, or wpscan failed to detect; record evidence
		// and keep going.
		_ = cctx.EmitEvidence(fact.EvidenceFact{
			SourceTool:     Name,
			SourceCategory: finding.SourceActiveScan,
			Confidence:     finding.ConfidenceLow,
			Payload:        map[string]any{"target": target, "parse_error": err.Error()},
			EntityKind:     entity.KindURL,
			EntityValue:    target,
		})
		return 0, nil
	}

	findings := 0

	// WordPress core version + its known vulns.
	if rec.Version.Number != "" {
		if _, err := cctx.EmitEntity(fact.EntityFact{
			Kind:           entity.KindTechnology,
			Value:          "wordpress/" + rec.Version.Number,
			Attributes:     map[string]any{"target": target, "status": rec.Version.Status, "confidence": rec.Version.Confidence},
			Confidence:     finding.ConfidenceHigh,
			SourceCategory: finding.SourceActiveScan,
		}); err != nil {
			return findings, err
		}
		for _, v := range rec.Version.Vulns {
			n, err := c.emitVuln(cctx, target, "wordpress core "+rec.Version.Number, v)
			if err != nil {
				return findings, err
			}
			findings += n
		}
	}

	// Plugins.
	for name, plug := range rec.Plugins {
		ver := plug.Version.Number
		techValue := "wp-plugin/" + name
		if ver != "" {
			techValue += "/" + ver
		}
		if _, err := cctx.EmitEntity(fact.EntityFact{
			Kind:  entity.KindTechnology,
			Value: techValue,
			Attributes: map[string]any{
				"target":         target,
				"name":           name,
				"version":        ver,
				"latest_version": plug.LatestVersion,
				"outdated":       plug.Outdated,
			},
			Confidence:     finding.ConfidenceHigh,
			SourceCategory: finding.SourceActiveScan,
		}); err != nil {
			return findings, err
		}
		for _, v := range plug.Vulnerabilities {
			n, err := c.emitVuln(cctx, target, "wp-plugin "+name, v)
			if err != nil {
				return findings, err
			}
			findings += n
		}
	}

	// Themes.
	for name, theme := range rec.Themes {
		ver := theme.Version.Number
		techValue := "wp-theme/" + name
		if ver != "" {
			techValue += "/" + ver
		}
		if _, err := cctx.EmitEntity(fact.EntityFact{
			Kind:           entity.KindTechnology,
			Value:          techValue,
			Attributes:     map[string]any{"target": target, "name": name, "version": ver, "outdated": theme.Outdated},
			Confidence:     finding.ConfidenceHigh,
			SourceCategory: finding.SourceActiveScan,
		}); err != nil {
			return findings, err
		}
		for _, v := range theme.Vulnerabilities {
			n, err := c.emitVuln(cctx, target, "wp-theme "+name, v)
			if err != nil {
				return findings, err
			}
			findings += n
		}
	}

	// Interesting findings (config files, debug logs, …).
	for _, intf := range rec.InterestingFindings {
		sev := finding.SeverityLow
		if isSensitiveType(intf.Type) {
			sev = finding.SeverityMedium
		}
		if _, err := cctx.EmitFinding(fact.FindingFact{
			Title:       fmt.Sprintf("wpscan: %s exposed", intf.Type),
			Severity:    sev,
			Confidence:  finding.ConfidenceMedium,
			Category:    "wordpress.exposure",
			Description: intf.Message,
			Attributes: map[string]any{
				"target": target,
				"type":   intf.Type,
				"url":    intf.URL,
			},
			SupportingEntities: []fact.EntityRef{{Kind: entity.KindURL, Value: target}},
		}); err != nil {
			return findings, err
		}
		findings++
	}

	return findings, nil
}

func (c *collector) emitVuln(cctx scan.Context, target, component string, v wpVuln) (int, error) {
	if v.Title == "" {
		return 0, nil
	}
	cves := strings.Join(v.References.CVE, ", ")
	desc := fmt.Sprintf("%s in %s.", v.Title, component)
	if v.FixedIn != "" {
		desc += " Fixed in " + v.FixedIn + "."
	}
	if cves != "" {
		desc += " " + cves
	}
	sev := finding.SeverityHigh
	if v.FixedIn == "" {
		// No known fix means it's likely still exploitable on the
		// reported version; bump severity.
		sev = finding.SeverityCritical
	}
	if _, err := cctx.EmitFinding(fact.FindingFact{
		Title:       fmt.Sprintf("wpscan: %s — %s", component, v.Title),
		Severity:    sev,
		Confidence:  finding.ConfidenceMedium,
		Category:    "wordpress.vulnerability",
		Description: desc,
		Attributes: map[string]any{
			"target":     target,
			"component":  component,
			"fixed_in":   v.FixedIn,
			"cve":        v.References.CVE,
			"references": v.References.URL,
		},
		SupportingEntities: []fact.EntityRef{{Kind: entity.KindURL, Value: target}},
	}); err != nil {
		return 0, err
	}
	return 1, nil
}

func isSensitiveType(t string) bool {
	switch strings.ToLower(strings.TrimSpace(t)) {
	case "config_backup", "wp-config-backup", "debug_log", "backup_db",
		"emergency_pwd_reset_script", "full_path_disclosure":
		return true
	}
	return false
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
		return nil, errors.New("wpscan: no targets to scan; pass parameters[\"targets\"] or seed URL entities")
	}
	return out, nil
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
