// Package dnsx wraps ProjectDiscovery's dnsx for DNS validation of
// previously-discovered subdomains. Light-active: contacts the target's
// authoritative DNS.
//
// Emits IP entities + RESOLVES_TO relations per resolved name, evidence
// rows for CNAME chains, and a MEDIUM finding for any name that has a
// CNAME without an A/AAAA record (potential dangling CNAME → subdomain
// takeover candidate).
//
// Ported from lantern/tools/dnsx.py.
package dnsx

import (
	"context"
	"encoding/json"
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
	Name           = "dnsx"
	defaultBinary  = "dnsx"
	defaultTimeout = 120 * time.Second
)

func New() scan.Collector { return &collector{} }

type runnerFn func(ctx context.Context, spec subprocess.Spec) (subprocess.Result, error)

func newWithRunner(r runnerFn) scan.Collector { return &collector{runner: r} }

type collector struct{ runner runnerFn }

func (collector) Metadata() scan.Meta {
	return scan.Meta{
		Name:           Name,
		Phase:          workflow.PhaseValidation,
		RequiredScope:  scope.KindLightActive,
		Description:    "Resolve discovered subdomains via DNS using ProjectDiscovery's dnsx.",
		Consumes:       []entity.Kind{entity.KindSubdomain},
		Produces:       []entity.Kind{entity.KindIP},
		SourceCategory: finding.SourcePassiveDNS,
		Binary:         "dnsx",
		InstallHint:    "go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
		Parameters: []scan.ParameterSpec{
			{Name: "names", Type: "string_list", Placeholder: "api.example.com",
				Description: "Names to resolve. Empty falls back to every SUBDOMAIN entity."},
			{Name: "binary", Type: "string", Default: "dnsx"},
			{Name: "timeout_seconds", Type: "float", Default: 120.0,
				Description: "Wall-clock timeout in seconds for the dnsx subprocess."},
		},
	}
}

type dnsxRecord struct {
	Host  string   `json:"host"`
	A     []string `json:"a"`
	AAAA  []string `json:"aaaa"`
	CNAME []string `json:"cname"`
}

func (c *collector) Run(ctx context.Context, cctx scan.Context) error {
	binary := strings.TrimSpace(toString(cctx.Parameters()["binary"]))
	if binary == "" {
		binary = defaultBinary
	}
	timeout := parseTimeout(cctx.Parameters()["timeout_seconds"])

	names := parseStringList(cctx.Parameters()["names"])
	if len(names) == 0 {
		v, err := cctx.ListEntityValues(entity.KindSubdomain)
		if err != nil {
			return err
		}
		names = v
	}
	var allowed []string
	for _, n := range names {
		n = strings.ToLower(strings.TrimSpace(n))
		if n != "" && cctx.IsInScope(n) {
			allowed = append(allowed, n)
		}
	}
	if len(allowed) == 0 {
		return nil
	}

	stdin := []byte(strings.Join(allowed, "\n") + "\n")
	args := []string{"-silent", "-resp", "-json", "-a", "-aaaa", "-cname"}

	run := c.runner
	if run == nil {
		run = subprocess.Run
	}
	result, err := run(ctx, subprocess.Spec{
		Binary: binary, Args: args, Stdin: stdin, Timeout: timeout,
	})
	if err != nil {
		return err
	}

	byHost := map[string]dnsxRecord{}
	for _, raw := range strings.Split(string(result.Stdout), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		var rec dnsxRecord
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			continue
		}
		if rec.Host == "" {
			continue
		}
		rec.Host = strings.TrimRight(strings.ToLower(strings.TrimSpace(rec.Host)), ".")
		for i, c := range rec.CNAME {
			rec.CNAME[i] = strings.TrimRight(strings.ToLower(strings.TrimSpace(c)), ".")
		}
		byHost[rec.Host] = rec
	}

	liveCount, danglingCount := 0, 0
	for _, host := range allowed {
		rec, ok := byHost[host]
		if !ok {
			continue
		}
		hasAddress := len(rec.A) > 0 || len(rec.AAAA) > 0
		if hasAddress {
			liveCount++
		}
		for _, ip := range append(append([]string{}, rec.A...), rec.AAAA...) {
			if _, err := cctx.EmitEntity(fact.EntityFact{
				Kind:           entity.KindIP,
				Value:          ip,
				Confidence:     finding.ConfidenceHigh,
				SourceCategory: finding.SourcePassiveDNS,
			}); err != nil {
				return err
			}
			family := "v4"
			if strings.Contains(ip, ":") {
				family = "v6"
			}
			if err := cctx.EmitRelation(fact.RelationFact{
				Src:        fact.EntityRef{Kind: entity.KindSubdomain, Value: host},
				Dst:        fact.EntityRef{Kind: entity.KindIP, Value: ip},
				Kind:       entity.RelResolvesTo,
				Attributes: map[string]any{"family": family},
			}); err != nil {
				return err
			}
		}
		for _, cname := range rec.CNAME {
			if err := cctx.EmitEvidence(fact.EvidenceFact{
				SourceTool:     Name,
				SourceCategory: finding.SourcePassiveDNS,
				Confidence:     finding.ConfidenceHigh,
				Payload:        map[string]any{"cname": cname},
				EntityKind:     entity.KindSubdomain,
				EntityValue:    host,
			}); err != nil {
				return err
			}
		}
		if len(rec.CNAME) > 0 && !hasAddress {
			danglingCount++
			if _, err := cctx.EmitFinding(fact.FindingFact{
				Title:      "Possible dangling CNAME: " + host + " -> " + rec.CNAME[0],
				Severity:   finding.SeverityMedium,
				Confidence: finding.ConfidenceLow,
				Category:   "dangling_cname",
				Description: host + " has a CNAME to " + rec.CNAME[0] + " but no A/AAAA " +
					"record was returned. Review whether the CNAME target is still owned " +
					"by the organization; dangling CNAMEs are a common subdomain " +
					"takeover vector.",
				Recommendation: "Verify ownership of the CNAME target. If the target service " +
					"is no longer in use, remove the CNAME from the authoritative zone.",
				SupportingEntities: []fact.EntityRef{{Kind: entity.KindSubdomain, Value: host}},
			}); err != nil {
				return err
			}
		}
	}

	return cctx.EmitEvidence(fact.EvidenceFact{
		SourceTool:     Name,
		SourceCategory: finding.SourcePassiveDNS,
		Confidence:     finding.ConfidenceHigh,
		Payload: map[string]any{
			"names_input":                len(names),
			"names_skipped_out_of_scope": len(names) - len(allowed),
			"names_resolved":             liveCount,
			"names_dangling_cname":       danglingCount,
		},
	})
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
