// Package subfinder wraps ProjectDiscovery's subfinder for passive
// subdomain enumeration. Higher-coverage complement to crtsh: queries
// many sources (CT logs, OTX, AnubisDB, BinaryEdge, Shodan, etc.)
// instead of just one.
//
// Ported from lantern/tools/subfinder.py.
package subfinder

import (
	"context"
	"errors"
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
	Name           = "subfinder"
	defaultBinary  = "subfinder"
	defaultTimeout = 300 * time.Second
)

func New() scan.Collector { return &collector{} }

type runnerFn func(ctx context.Context, spec subprocess.Spec) (subprocess.Result, error)

func newWithRunner(r runnerFn) scan.Collector { return &collector{runner: r} }

type collector struct{ runner runnerFn }

func (collector) Metadata() scan.Meta {
	return scan.Meta{
		Name:           Name,
		Phase:          workflow.PhaseAssetDiscovery,
		RequiredScope:  scope.KindPassive,
		Description:    "Passive subdomain enumeration via subfinder (CT logs + public DNS aggregators + optional API sources).",
		Consumes:       []entity.Kind{entity.KindDomain},
		Produces:       []entity.Kind{entity.KindSubdomain},
		SourceCategory: finding.SourcePublicOSINT,
		Binary:         "subfinder",
		InstallHint:    "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
		Parameters: []scan.ParameterSpec{
			{Name: "domains", Type: "string_list", Placeholder: "example.com, example.org",
				Description: "Apex domains. Empty falls back to every DOMAIN entity in the project."},
			{Name: "all_sources", Type: "bool", Default: false,
				Description: "Pass -all to query every configured source (slower, higher coverage)."},
			{Name: "binary", Type: "string", Default: "subfinder"},
			{Name: "timeout_seconds", Type: "float", Default: 300.0,
				Description: "Wall-clock timeout per domain."},
		},
	}
}

func (c *collector) Run(ctx context.Context, cctx scan.Context) error {
	binary := strings.TrimSpace(toString(cctx.Parameters()["binary"]))
	if binary == "" {
		binary = defaultBinary
	}
	timeout := parseTimeout(cctx.Parameters()["timeout_seconds"])
	allSources, _ := cctx.Parameters()["all_sources"].(bool)

	domains, err := c.resolveDomains(cctx)
	if err != nil {
		return err
	}
	var inScope []string
	for _, d := range domains {
		if cctx.IsInScope(d) {
			inScope = append(inScope, strings.ToLower(d))
		}
	}
	if len(inScope) == 0 {
		return nil
	}

	run := c.runner
	if run == nil {
		run = subprocess.Run
	}

	totalEmitted := 0
	for _, domain := range inScope {
		args := []string{"-d", domain, "-silent"}
		if allSources {
			args = append(args, "-all")
		}
		result, err := run(ctx, subprocess.Spec{
			Binary:         binary,
			Args:           args,
			Timeout:        timeout,
			AllowPartialRC: []int{1},
		})
		if err != nil {
			// One bad domain shouldn't kill the run; record evidence and
			// continue. Mirrors the Python try/except per-domain pattern.
			_ = cctx.EmitEvidence(fact.EvidenceFact{
				SourceTool:     Name,
				SourceCategory: finding.SourcePublicOSINT,
				Confidence:     finding.ConfidenceLow,
				Payload:        map[string]any{"domain": domain, "error": err.Error()},
				EntityKind:     entity.KindDomain,
				EntityValue:    domain,
			})
			continue
		}
		seen := map[string]struct{}{}
		suffix := "." + domain
		for _, raw := range strings.Split(string(result.Stdout), "\n") {
			sub := strings.ToLower(strings.TrimSpace(raw))
			if sub == "" {
				continue
			}
			if _, dup := seen[sub]; dup {
				continue
			}
			// subfinder occasionally returns the apex or out-of-scope hits
			// depending on source; filter to the input domain's tree.
			if sub != domain && !strings.HasSuffix(sub, suffix) {
				continue
			}
			seen[sub] = struct{}{}
			if _, err := cctx.EmitEntity(fact.EntityFact{
				Kind:           entity.KindSubdomain,
				Value:          sub,
				Confidence:     finding.ConfidenceMedium,
				SourceCategory: finding.SourcePublicOSINT,
				Attributes:     map[string]any{"discovered_via": Name, "source_domain": domain},
			}); err != nil {
				return err
			}
			totalEmitted++
		}
		if err := cctx.EmitEvidence(fact.EvidenceFact{
			SourceTool:     Name,
			SourceCategory: finding.SourcePublicOSINT,
			Confidence:     finding.ConfidenceMedium,
			Payload: map[string]any{
				"domain":           domain,
				"subdomains_found": len(seen),
				"all_sources":      allSources,
			},
			EntityKind:  entity.KindDomain,
			EntityValue: domain,
		}); err != nil {
			return err
		}
	}
	_ = totalEmitted
	return nil
}

func (c *collector) resolveDomains(cctx scan.Context) ([]string, error) {
	explicit := parseStringList(cctx.Parameters()["domains"])
	if len(explicit) > 0 {
		out := make([]string, 0, len(explicit))
		for _, d := range explicit {
			if d = strings.TrimSpace(d); d != "" {
				out = append(out, d)
			}
		}
		if len(out) > 0 {
			return out, nil
		}
	}
	values, err := cctx.ListEntityValues(entity.KindDomain)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, v := range values {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("subfinder: no domains to enumerate; pass parameters[\"domains\"] or seed DOMAIN entities")
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

