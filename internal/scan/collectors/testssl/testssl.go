// Package testssl wraps testssl.sh for TLS posture analysis.
// Produces Findings tagged by testssl's severity vocabulary; rows
// below min_severity become evidence-only.
//
// Ported from lantern/tools/testssl.py.
package testssl

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
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
	Name              = "testssl"
	defaultBinary     = "testssl.sh"
	defaultTimeout    = 300 * time.Second
	defaultMaxTargets = 25
)

// severityMap converts testssl.sh's severity vocabulary to Lantern's.
// OK / INFO -> nil severity (evidence-only).
var severityMap = map[string]finding.Severity{
	"FATAL":    finding.SeverityCritical,
	"CRITICAL": finding.SeverityCritical,
	"HIGH":     finding.SeverityHigh,
	"MEDIUM":   finding.SeverityMedium,
	"WARN":     finding.SeverityMedium,
	"LOW":      finding.SeverityLow,
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
		Description:        "Run testssl.sh against HTTPS endpoints; convert severity-tagged output into findings.",
		Consumes:           []entity.Kind{entity.KindURL},
		SourceCategory:     finding.SourceLiveProbe,
		TriggersOnServices: []string{"https"},
		Binary:             "testssl.sh",
		InstallHint:        "https://github.com/drwetter/testssl.sh — `git clone https://github.com/drwetter/testssl.sh.git`",
		Parameters: []scan.ParameterSpec{
			{Name: "targets", Type: "string_list"},
			{Name: "min_severity", Type: "enum", Default: "low",
				Choices:     []string{"info", "low", "medium", "high", "critical"},
				Description: "Severity floor; rows below this get recorded as evidence only."},
			{Name: "max_targets", Type: "int", Default: 25},
			{Name: "binary", Type: "string", Default: "testssl.sh"},
			{Name: "timeout_seconds", Type: "float", Default: 300.0},
			{Name: "extra_args", Type: "string_list"},
		},
	}
}

type testsslEntry struct {
	ID       string `json:"id"`
	Finding  string `json:"finding"`
	Severity string `json:"severity"`
	IP       string `json:"ip"`
	Port     string `json:"port"`
	CVE      string `json:"cve"`
	CWE      string `json:"cwe"`
}

func (c *collector) Run(ctx context.Context, cctx scan.Context) error {
	binary := strings.TrimSpace(toString(cctx.Parameters()["binary"]))
	if binary == "" {
		binary = defaultBinary
	}
	timeout := parseTimeout(cctx.Parameters()["timeout_seconds"])
	maxTargets := parsePositiveInt(cctx.Parameters()["max_targets"], defaultMaxTargets)
	extraArgs := parseStringList(cctx.Parameters()["extra_args"])
	minSev := strings.ToLower(strings.TrimSpace(toString(cctx.Parameters()["min_severity"])))
	if minSev == "" {
		minSev = "low"
	}
	minSevTyped := finding.Severity(minSev)

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
	if len(inScope) > maxTargets {
		inScope = inScope[:maxTargets]
	}
	if len(inScope) == 0 {
		return nil
	}

	run := c.runner
	if run == nil {
		run = subprocess.Run
	}

	findingsEmitted := 0
	for _, target := range inScope {
		tmp, err := os.MkdirTemp("", "golantern-testssl-")
		if err != nil {
			return fmt.Errorf("testssl: tempdir: %w", err)
		}
		jsonOut := filepath.Join(tmp, "out.json")
		args := []string{"--quiet", "--color", "0", "--jsonfile-pretty", jsonOut}
		args = append(args, extraArgs...)
		args = append(args, target)
		_, err = run(ctx, subprocess.Spec{
			Binary: binary, Args: args, Timeout: timeout,
		})
		if err != nil {
			os.RemoveAll(tmp)
			_ = cctx.EmitEvidence(fact.EvidenceFact{
				SourceTool:     Name,
				SourceCategory: finding.SourceLiveProbe,
				Confidence:     finding.ConfidenceLow,
				Payload:        map[string]any{"target": target, "error": err.Error()},
			})
			continue
		}
		body, err := os.ReadFile(jsonOut)
		os.RemoveAll(tmp)
		if err != nil {
			_ = cctx.EmitEvidence(fact.EvidenceFact{
				SourceTool:     Name,
				SourceCategory: finding.SourceLiveProbe,
				Confidence:     finding.ConfidenceLow,
				Payload:        map[string]any{"target": target, "error": "testssl JSON file missing"},
			})
			continue
		}
		var entries []testsslEntry
		if err := json.Unmarshal(body, &entries); err != nil {
			return fmt.Errorf("testssl: decode JSON: %w", err)
		}
		for _, e := range entries {
			rawSev := strings.ToUpper(strings.TrimSpace(e.Severity))
			sev, mapped := severityMap[rawSev]
			if !mapped {
				// OK / INFO: evidence-only.
				_ = cctx.EmitEvidence(fact.EvidenceFact{
					SourceTool:     Name,
					SourceCategory: finding.SourceLiveProbe,
					Confidence:     finding.ConfidenceMedium,
					Payload: map[string]any{
						"target":       target,
						"id":           e.ID,
						"raw_severity": rawSev,
						"finding":      e.Finding,
					},
					EntityKind:  entity.KindURL,
					EntityValue: target,
				})
				continue
			}
			if !sev.AtLeast(minSevTyped) {
				// Below the floor: evidence only.
				_ = cctx.EmitEvidence(fact.EvidenceFact{
					SourceTool:     Name,
					SourceCategory: finding.SourceLiveProbe,
					Confidence:     finding.ConfidenceMedium,
					Payload: map[string]any{
						"target":       target,
						"id":           e.ID,
						"raw_severity": rawSev,
						"finding":      e.Finding,
					},
					EntityKind:  entity.KindURL,
					EntityValue: target,
				})
				continue
			}
			findingsEmitted++
			if _, err := cctx.EmitFinding(fact.FindingFact{
				Title:      fmt.Sprintf("testssl %s: %s on %s", strings.ToLower(rawSev), e.ID, target),
				Severity:   sev,
				Confidence: finding.ConfidenceMedium,
				Category:   "tls." + strings.ToLower(rawSev),
				Description: fmt.Sprintf("testssl.sh reported %s severity for %s against %s: %s.",
					rawSev, e.ID, target, e.Finding),
				Attributes: map[string]any{
					"id":           e.ID,
					"raw_severity": rawSev,
					"cve":          e.CVE,
					"cwe":          e.CWE,
					"target":       target,
				},
				SupportingEntities: []fact.EntityRef{{Kind: entity.KindURL, Value: target}},
			}); err != nil {
				return err
			}
		}
	}
	return cctx.EmitEvidence(fact.EvidenceFact{
		SourceTool:     Name,
		SourceCategory: finding.SourceLiveProbe,
		Confidence:     finding.ConfidenceHigh,
		Payload: map[string]any{
			"targets_scanned":  len(inScope),
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
		if strings.HasPrefix(strings.ToLower(u), "https://") {
			out = append(out, u)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("testssl: no HTTPS targets; pass parameters[\"targets\"] or seed URL entities")
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
