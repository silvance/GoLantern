// Package sshaudit wraps ssh-audit for SSH configuration auditing.
// Pairs with naabu / nmap: once a host has port 22 open, sshaudit
// fingerprints the SSH banner and reports weak key-exchange algos,
// deprecated ciphers, missing MACs, and CVEs the server is exposed
// to.
//
// ssh-audit's JSON output is rich; we surface findings for any
// algorithm flagged "fail" (broken / removed in OpenSSH) or "warn"
// (deprecated). Banner info lands as attributes on the IP entity.
package sshaudit

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
	Name           = "ssh_audit"
	defaultBinary  = "ssh-audit"
	defaultTimeout = 120 * time.Second
)

func New() scan.Collector { return &collector{} }

type runnerFn func(ctx context.Context, spec subprocess.Spec) (subprocess.Result, error)

func newWithRunner(r runnerFn) scan.Collector { return &collector{runner: r} }

type collector struct{ runner runnerFn }

func (collector) Metadata() scan.Meta {
	return scan.Meta{
		Name:               Name,
		Phase:              workflow.PhaseExposure,
		RequiredScope:      scope.KindLightActive,
		Description:        "Audit SSH server configuration via ssh-audit: weak key-exchange algos, deprecated ciphers, missing MACs, and version-bound CVEs.",
		Consumes:           []entity.Kind{entity.KindIP, entity.KindSubdomain},
		Produces:           nil,
		SourceCategory:     finding.SourceLiveProbe,
		TriggersOnServices: []string{"ssh"},
		Binary:             "ssh-audit",
		InstallHint:        "pipx install ssh-audit",
		Parameters: []scan.ParameterSpec{
			{Name: "targets", Type: "string_list", Placeholder: "10.0.0.1",
				Description: "Hosts to audit. Empty falls back to every IP + SUBDOMAIN entity."},
			{Name: "port", Type: "int", Default: 22,
				Description: "SSH port to probe."},
			{Name: "binary", Type: "string", Default: "ssh-audit"},
			{Name: "timeout_seconds", Type: "float", Default: 120.0},
		},
	}
}

// sshauditJSON is a permissive view of ssh-audit's --json output.
// Concrete shape varies between versions — fields we don't recognize
// are tolerated.
type sshauditJSON struct {
	Banner struct {
		Raw      string `json:"raw"`
		Software string `json:"software"`
		Protocol []int  `json:"protocol"`
	} `json:"banner"`
	CVEList   []sshauditCVE       `json:"cves"`
	KEX       []sshauditAlgo      `json:"kex"`
	Key       []sshauditAlgo      `json:"key"`
	Enc       []sshauditAlgo      `json:"enc"`
	Mac       []sshauditAlgo      `json:"mac"`
	Compression []sshauditAlgo    `json:"compression"`
}

type sshauditCVE struct {
	Name        string  `json:"name"`
	CVSSv2      float64 `json:"cvssv2"`
	Description string  `json:"description"`
}

type sshauditAlgo struct {
	Algorithm string   `json:"algorithm"`
	Notes     struct {
		Fail []string `json:"fail"`
		Warn []string `json:"warn"`
		Info []string `json:"info"`
	} `json:"notes"`
}

func (c *collector) Run(ctx context.Context, cctx scan.Context) error {
	binary := strings.TrimSpace(toString(cctx.Parameters()["binary"]))
	if binary == "" {
		binary = defaultBinary
	}
	timeout := parseTimeout(cctx.Parameters()["timeout_seconds"])
	port := parsePositiveInt(cctx.Parameters()["port"], 22)

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
	for _, target := range inScope {
		args := []string{"-j", "-p", fmt.Sprintf("%d", port), target}
		result, err := run(ctx, subprocess.Spec{
			Binary:         binary,
			Args:           args,
			Timeout:        timeout,
			AllowPartialRC: []int{1, 2, 3},
		})
		if err != nil {
			_ = cctx.EmitEvidence(fact.EvidenceFact{
				SourceTool:     Name,
				SourceCategory: finding.SourceLiveProbe,
				Confidence:     finding.ConfidenceLow,
				Payload:        map[string]any{"target": target, "error": err.Error()},
				EntityKind:     entity.KindIP,
				EntityValue:    target,
			})
			continue
		}
		// Find the first JSON object — ssh-audit occasionally prints
		// the banner before the JSON.
		idx := strings.IndexByte(string(result.Stdout), '{')
		if idx < 0 {
			continue
		}
		var parsed sshauditJSON
		if err := json.Unmarshal(result.Stdout[idx:], &parsed); err != nil {
			_ = cctx.EmitEvidence(fact.EvidenceFact{
				SourceTool:     Name,
				SourceCategory: finding.SourceLiveProbe,
				Confidence:     finding.ConfidenceLow,
				Payload:        map[string]any{"target": target, "parse_error": err.Error()},
				EntityKind:     entity.KindIP,
				EntityValue:    target,
			})
			continue
		}

		// Banner info as IP attributes.
		if parsed.Banner.Software != "" || parsed.Banner.Raw != "" {
			attrs := map[string]any{
				"discovered_via": Name,
				"ssh_banner":     parsed.Banner.Raw,
				"ssh_software":   parsed.Banner.Software,
			}
			if _, err := cctx.EmitEntity(fact.EntityFact{
				Kind:           entity.KindIP,
				Value:          target,
				Attributes:     attrs,
				Confidence:     finding.ConfidenceHigh,
				SourceCategory: finding.SourceLiveProbe,
			}); err != nil {
				return err
			}
		}

		// CVE findings — these are version-bound and the most actionable.
		for _, cve := range parsed.CVEList {
			sev := severityFromCVSS(cve.CVSSv2)
			if _, err := cctx.EmitFinding(fact.FindingFact{
				Title:       fmt.Sprintf("ssh_audit: %s on %s (%s)", cve.Name, target, parsed.Banner.Software),
				Severity:    sev,
				Confidence:  finding.ConfidenceHigh,
				Category:    "ssh.cve",
				Description: cve.Description,
				Attributes: map[string]any{
					"target":   target,
					"cve":      cve.Name,
					"cvssv2":   cve.CVSSv2,
					"software": parsed.Banner.Software,
				},
				SupportingEntities: []fact.EntityRef{{Kind: entity.KindIP, Value: target}},
			}); err != nil {
				return err
			}
			totalFindings++
		}

		// Algorithm findings — "fail" = broken, "warn" = deprecated.
		algoGroups := []struct {
			label string
			items []sshauditAlgo
		}{
			{"kex", parsed.KEX},
			{"hostkey", parsed.Key},
			{"cipher", parsed.Enc},
			{"mac", parsed.Mac},
			{"compression", parsed.Compression},
		}
		for _, group := range algoGroups {
			for _, algo := range group.items {
				if len(algo.Notes.Fail) > 0 {
					if _, err := cctx.EmitFinding(fact.FindingFact{
						Title:       fmt.Sprintf("ssh_audit: broken %s algorithm %q on %s", group.label, algo.Algorithm, target),
						Severity:    finding.SeverityMedium,
						Confidence:  finding.ConfidenceHigh,
						Category:    "ssh.weak_algorithm",
						Description: strings.Join(algo.Notes.Fail, "; "),
						Attributes: map[string]any{
							"target":    target,
							"algo_type": group.label,
							"algorithm": algo.Algorithm,
							"severity":  "fail",
						},
						SupportingEntities: []fact.EntityRef{{Kind: entity.KindIP, Value: target}},
					}); err != nil {
						return err
					}
					totalFindings++
				} else if len(algo.Notes.Warn) > 0 {
					if _, err := cctx.EmitFinding(fact.FindingFact{
						Title:       fmt.Sprintf("ssh_audit: deprecated %s algorithm %q on %s", group.label, algo.Algorithm, target),
						Severity:    finding.SeverityLow,
						Confidence:  finding.ConfidenceHigh,
						Category:    "ssh.weak_algorithm",
						Description: strings.Join(algo.Notes.Warn, "; "),
						Attributes: map[string]any{
							"target":    target,
							"algo_type": group.label,
							"algorithm": algo.Algorithm,
							"severity":  "warn",
						},
						SupportingEntities: []fact.EntityRef{{Kind: entity.KindIP, Value: target}},
					}); err != nil {
						return err
					}
					totalFindings++
				}
			}
		}

		_ = cctx.EmitEvidence(fact.EvidenceFact{
			SourceTool:     Name,
			SourceCategory: finding.SourceLiveProbe,
			Confidence:     finding.ConfidenceHigh,
			Payload: map[string]any{
				"target":   target,
				"banner":   parsed.Banner.Raw,
				"software": parsed.Banner.Software,
				"cves":     len(parsed.CVEList),
				"port":     port,
			},
			EntityKind:  entity.KindIP,
			EntityValue: target,
		})
	}
	return cctx.EmitEvidence(fact.EvidenceFact{
		SourceTool:     Name,
		SourceCategory: finding.SourceLiveProbe,
		Confidence:     finding.ConfidenceHigh,
		Payload: map[string]any{
			"targets_audited":  len(inScope),
			"findings_emitted": totalFindings,
		},
	})
}

func severityFromCVSS(cvss float64) finding.Severity {
	switch {
	case cvss >= 9.0:
		return finding.SeverityCritical
	case cvss >= 7.0:
		return finding.SeverityHigh
	case cvss >= 4.0:
		return finding.SeverityMedium
	default:
		return finding.SeverityLow
	}
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
	var out []string
	for _, kind := range []entity.Kind{entity.KindIP, entity.KindSubdomain} {
		values, err := cctx.ListEntityValues(kind)
		if err != nil {
			return nil, err
		}
		out = append(out, values...)
	}
	if len(out) == 0 {
		return nil, errors.New("ssh_audit: no targets; pass parameters[\"targets\"] or seed IP/SUBDOMAIN entities")
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
