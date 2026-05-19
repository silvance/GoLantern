// Package nikto wraps nikto2 web-vuln scanner. Produces Findings from
// nikto's JSON output. Severity assigned via a keyword heuristic since
// nikto itself doesn't ship structured severity.
//
// Ported from lantern/tools/nikto.py.
package nikto

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
	Name           = "nikto"
	defaultBinary  = "nikto"
	defaultTimeout = 600 * time.Second
)

var (
	highPatterns = []string{
		"sql injection", "directory traversal", "path traversal", "lfi", "rfi",
		"/.git/", "/.env", "/.svn/", "default credentials", "rce", "remote code",
	}
	mediumPatterns = []string{
		"outdated", "out of date", "vulnerable", "exposed", "admin", "backup",
	}
)

func classifySeverity(msg string) finding.Severity {
	low := strings.ToLower(msg)
	for _, kw := range highPatterns {
		if strings.Contains(low, kw) {
			return finding.SeverityHigh
		}
	}
	for _, kw := range mediumPatterns {
		if strings.Contains(low, kw) {
			return finding.SeverityMedium
		}
	}
	return finding.SeverityLow
}

func New() scan.Collector { return &collector{} }

type runnerFn func(ctx context.Context, spec subprocess.Spec) (subprocess.Result, error)

func newWithRunner(r runnerFn) scan.Collector { return &collector{runner: r} }

type collector struct{ runner runnerFn }

func (collector) Metadata() scan.Meta {
	return scan.Meta{
		Name:               Name,
		Phase:              workflow.PhaseExposure,
		RequiredScope:      scope.KindLightActive,
		Description:        "Web vulnerability and misconfiguration scanner; produces severity-tagged findings.",
		Consumes:           []entity.Kind{entity.KindURL},
		SourceCategory:     finding.SourceLiveProbe,
		TriggersOnServices: []string{"http", "https"},
		Binary:             "nikto",
		InstallHint:        "apt install nikto (Debian/Ubuntu/Kali) | brew install nikto (macOS)",
		Parameters: []scan.ParameterSpec{
			{Name: "targets", Type: "string_list"},
			{Name: "tuning", Type: "string",
				Description: "nikto -Tuning string (1-9, comma-separated)."},
			{Name: "binary", Type: "string", Default: "nikto"},
			{Name: "timeout_seconds", Type: "float", Default: 600.0},
		},
	}
}

type niktoReport struct {
	Vulnerabilities []struct {
		ID         string `json:"id"`
		OSVDB      string `json:"OSVDBlink"`
		Message    string `json:"msg"`
		URI        string `json:"uri"`
		Method     string `json:"method"`
		References string `json:"references"`
	} `json:"vulnerabilities"`
	Host string `json:"host"`
	Port string `json:"port"`
}

func (c *collector) Run(ctx context.Context, cctx scan.Context) error {
	binary := strings.TrimSpace(toString(cctx.Parameters()["binary"]))
	if binary == "" {
		binary = defaultBinary
	}
	timeout := parseTimeout(cctx.Parameters()["timeout_seconds"])
	tuning := strings.TrimSpace(toString(cctx.Parameters()["tuning"]))

	targets, err := c.resolveTargets(cctx)
	if err != nil {
		return err
	}
	var allowed []string
	for _, t := range targets {
		if cctx.IsInScope(t) {
			allowed = append(allowed, t)
		}
	}
	if len(allowed) == 0 {
		return nil
	}

	run := c.runner
	if run == nil {
		run = subprocess.Run
	}

	findingsEmitted := 0
	for _, target := range allowed {
		args := []string{"-host", target, "-Format", "json", "-output", "-", "-ask", "no"}
		if tuning != "" {
			args = append(args, "-Tuning", tuning)
		}
		result, err := run(ctx, subprocess.Spec{
			Binary:         binary,
			Args:           args,
			Timeout:        timeout,
			AllowPartialRC: []int{1, 2},
		})
		if err != nil {
			_ = cctx.EmitEvidence(fact.EvidenceFact{
				SourceTool:     Name,
				SourceCategory: finding.SourceLiveProbe,
				Confidence:     finding.ConfidenceLow,
				Payload:        map[string]any{"target": target, "error": err.Error()},
			})
			continue
		}
		// nikto wraps the JSON in an array sometimes, sometimes not.
		// Try array first, fall back to single object.
		var reports []niktoReport
		body := result.Stdout
		if err := json.Unmarshal(body, &reports); err != nil {
			var single niktoReport
			if err := json.Unmarshal(body, &single); err != nil {
				return fmt.Errorf("nikto: parse JSON: %w", err)
			}
			reports = []niktoReport{single}
		}
		for _, report := range reports {
			for _, vuln := range report.Vulnerabilities {
				msg := strings.TrimSpace(vuln.Message)
				if msg == "" {
					continue
				}
				sev := classifySeverity(msg)
				title := "nikto: " + msg
				if len(title) > 120 {
					title = title[:117] + "..."
				}
				fullURL := target
				if vuln.URI != "" {
					fullURL = strings.TrimRight(target, "/") + vuln.URI
				}
				if _, err := cctx.EmitFinding(fact.FindingFact{
					Title:      title,
					Severity:   sev,
					Confidence: finding.ConfidenceMedium,
					Category:   "nikto",
					Description: fmt.Sprintf("nikto reported %s on %s", msg, fullURL),
					Attributes: map[string]any{
						"id":         vuln.ID,
						"osvdb":      vuln.OSVDB,
						"method":     vuln.Method,
						"uri":        vuln.URI,
						"target":     target,
						"references": vuln.References,
					},
					SupportingEntities: []fact.EntityRef{{Kind: entity.KindURL, Value: target}},
				}); err != nil {
					return err
				}
				findingsEmitted++
			}
		}
	}
	return cctx.EmitEvidence(fact.EvidenceFact{
		SourceTool:     Name,
		SourceCategory: finding.SourceLiveProbe,
		Confidence:     finding.ConfidenceHigh,
		Payload: map[string]any{
			"targets_scanned":  len(allowed),
			"findings_emitted": findingsEmitted,
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
	urls, err := cctx.ListEntityValues(entity.KindURL)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, u := range urls {
		if strings.HasPrefix(strings.ToLower(u), "http") {
			out = append(out, u)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("nikto: no targets; pass parameters[\"targets\"] or seed URL entities")
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
