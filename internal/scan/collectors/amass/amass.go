// Package amass wraps OWASP amass enum for passive subdomain
// enumeration. Higher-coverage complement to subfinder + crtsh:
// amass correlates across dozens of sources (CT logs, OTX,
// AnubisDB, BinaryEdge, Shodan, RapidDNS, archive.org, …) and
// frequently surfaces subdomains the other two miss.
//
// Run in passive mode by default — active mode does live DNS
// brute-forcing and zone transfers, which requires KindLightActive
// or higher. The collector exposes an `active` parameter, but the
// Required scope on the Meta is Passive so the default invocation
// works in any project.
package amass

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
	Name           = "amass"
	defaultBinary  = "amass"
	defaultTimeout = 600 * time.Second
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
		Description:    "Passive subdomain enumeration via OWASP amass. Aggregates many more sources than subfinder/crtsh and tends to surface assets they miss.",
		Consumes:       []entity.Kind{entity.KindDomain},
		Produces:       []entity.Kind{entity.KindSubdomain},
		SourceCategory: finding.SourcePublicOSINT,
		Binary:         "amass",
		InstallHint:    "go install -v github.com/owasp-amass/amass/v4/...@master",
		Parameters: []scan.ParameterSpec{
			{Name: "domains", Type: "string_list", Placeholder: "example.com, example.org",
				Description: "Apex domains. Empty falls back to every DOMAIN entity in the project."},
			{Name: "active", Type: "bool", Default: false,
				Description: "Enable active mode (live DNS brute, zone transfers). Requires light_active scope at minimum."},
			{Name: "binary", Type: "string", Default: "amass"},
			{Name: "timeout_seconds", Type: "float", Default: 600.0,
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
	active, _ := cctx.Parameters()["active"].(bool)

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

	for _, domain := range inScope {
		args := []string{"enum", "-d", domain, "-nocolor", "-silent"}
		if active {
			args = append(args, "-active")
		} else {
			args = append(args, "-passive")
		}
		// amass v4 writes results to a default output dir; -o /dev/stdout
		// captures plain-text FQDNs on stdout so we can parse them like
		// subfinder's output. amass v3 honors the same flag.
		args = append(args, "-o", "/dev/stdout")

		result, err := run(ctx, subprocess.Spec{
			Binary:         binary,
			Args:           args,
			Timeout:        timeout,
			AllowPartialRC: []int{1},
		})
		if err != nil {
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
			// amass prefixes some lines with metadata in non-silent mode;
			// in silent mode it's plain FQDNs only, but stay defensive.
			if strings.ContainsAny(sub, " \t") {
				continue
			}
			if _, dup := seen[sub]; dup {
				continue
			}
			if sub != domain && !strings.HasSuffix(sub, suffix) {
				continue
			}
			seen[sub] = struct{}{}
			if _, err := cctx.EmitEntity(fact.EntityFact{
				Kind:           entity.KindSubdomain,
				Value:          sub,
				Confidence:     finding.ConfidenceMedium,
				SourceCategory: finding.SourcePublicOSINT,
				Attributes:     map[string]any{"discovered_via": Name, "source_domain": domain, "active": active},
			}); err != nil {
				return err
			}
		}
		if err := cctx.EmitEvidence(fact.EvidenceFact{
			SourceTool:     Name,
			SourceCategory: finding.SourcePublicOSINT,
			Confidence:     finding.ConfidenceMedium,
			Payload: map[string]any{
				"domain":           domain,
				"subdomains_found": len(seen),
				"active":           active,
			},
			EntityKind:  entity.KindDomain,
			EntityValue: domain,
		}); err != nil {
			return err
		}
	}
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
		return nil, errors.New("amass: no domains to enumerate; pass parameters[\"domains\"] or seed DOMAIN entities")
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
