// Package historicalurls wraps waybackurls or gau to discover historical
// URLs for known domains from the Wayback Machine / Common Crawl
// indices. Passive: queries archives, not the target.
//
// Ported from lantern/tools/historical_urls.py.
package historicalurls

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
	Name           = "historical_urls"
	defaultBinary  = "waybackurls"
	defaultTimeout = 120 * time.Second
	defaultMaxDomains = 50
)

var supportedBinaries = map[string]struct{}{
	"waybackurls": {},
	"gau":         {},
}

func New() scan.Collector { return &collector{} }

type runnerFn func(ctx context.Context, spec subprocess.Spec) (subprocess.Result, error)

func newWithRunner(r runnerFn) scan.Collector { return &collector{runner: r} }

type collector struct{ runner runnerFn }

func (collector) Metadata() scan.Meta {
	return scan.Meta{
		Name:           Name,
		Phase:          workflow.PhaseAssetDiscovery,
		RequiredScope:  scope.KindPassive,
		Description:    "Discover historical URLs via the Wayback Machine / Common Crawl using waybackurls or gau.",
		Consumes:       []entity.Kind{entity.KindDomain, entity.KindSubdomain},
		Produces:       []entity.Kind{entity.KindURL},
		SourceCategory: finding.SourcePublicOSINT,
		Binary:         "waybackurls",
		InstallHint:    "go install github.com/tomnomnom/waybackurls@latest\n# or `go install github.com/lc/gau/v2/cmd/gau@latest`",
		Parameters: []scan.ParameterSpec{
			{Name: "domains", Type: "string_list", Placeholder: "example.com, www.example.com",
				Description: "Hostnames to query. Empty falls back to every DOMAIN+SUBDOMAIN entity."},
			{Name: "binary", Type: "enum", Default: "waybackurls",
				Choices: []string{"waybackurls", "gau"}},
			{Name: "timeout_seconds", Type: "float", Default: 120.0,
				Description: "Per-domain timeout in seconds."},
			{Name: "max_domains", Type: "int", Default: 50,
				Description: "Cap on domains queried in one run."},
			{Name: "extra_args", Type: "string_list"},
		},
	}
}

func (c *collector) Run(ctx context.Context, cctx scan.Context) error {
	binary := strings.TrimSpace(toString(cctx.Parameters()["binary"]))
	if binary == "" {
		binary = defaultBinary
	}
	if _, ok := supportedBinaries[binary]; !ok {
		return errors.New("historical_urls: binary must be one of waybackurls, gau")
	}
	timeout := parseTimeout(cctx.Parameters()["timeout_seconds"])
	maxDomains := parsePositiveInt(cctx.Parameters()["max_domains"], defaultMaxDomains)
	extraArgs := parseStringList(cctx.Parameters()["extra_args"])

	domains, err := c.resolveDomains(cctx)
	if err != nil {
		return err
	}
	var allowed []string
	for _, d := range domains {
		if cctx.IsInScope(d) {
			allowed = append(allowed, strings.ToLower(d))
		}
	}
	if len(allowed) > maxDomains {
		allowed = allowed[:maxDomains]
	}
	if len(allowed) == 0 {
		return nil
	}

	// Cache known subdomains so we can wire URL -> SUBDOMAIN CHILD_OF
	// relations without a repository query per emit.
	knownSubs := map[string]struct{}{}
	if subs, err := cctx.ListEntityValues(entity.KindSubdomain); err == nil {
		for _, s := range subs {
			knownSubs[strings.ToLower(strings.TrimSpace(s))] = struct{}{}
		}
	}

	run := c.runner
	if run == nil {
		run = subprocess.Run
	}

	seen := map[string]struct{}{}
	urlsEmitted := 0
	for _, domain := range allowed {
		args := append([]string(nil), extraArgs...)
		stdin := []byte(domain + "\n")
		result, err := run(ctx, subprocess.Spec{
			Binary:  binary,
			Args:    args,
			Stdin:   stdin,
			Timeout: timeout,
		})
		if err != nil {
			// Per-domain failure: record and continue.
			_ = cctx.EmitEvidence(fact.EvidenceFact{
				SourceTool:     Name,
				SourceCategory: finding.SourcePublicOSINT,
				Confidence:     finding.ConfidenceLow,
				Payload:        map[string]any{"domain": domain, "error": err.Error()},
			})
			continue
		}
		suffix := "." + domain
		for _, raw := range strings.Split(string(result.Stdout), "\n") {
			url := strings.TrimSpace(raw)
			if url == "" || strings.HasPrefix(url, "#") {
				continue
			}
			lu := strings.ToLower(url)
			if !strings.HasPrefix(lu, "http://") && !strings.HasPrefix(lu, "https://") {
				continue
			}
			// Host suffix check: drop archive-side cross-domain redirects.
			host := extractHost(url)
			if host != domain && !strings.HasSuffix(host, suffix) {
				continue
			}
			if _, dup := seen[url]; dup {
				continue
			}
			seen[url] = struct{}{}
			if _, err := cctx.EmitEntity(fact.EntityFact{
				Kind:           entity.KindURL,
				Value:          url,
				Confidence:     finding.ConfidenceMedium,
				SourceCategory: finding.SourcePublicOSINT,
				Attributes:     map[string]any{"discovered_via": binary},
			}); err != nil {
				return err
			}
			urlsEmitted++
			if _, ok := knownSubs[host]; ok {
				if err := cctx.EmitRelation(fact.RelationFact{
					Src:  fact.EntityRef{Kind: entity.KindURL, Value: url},
					Dst:  fact.EntityRef{Kind: entity.KindSubdomain, Value: host},
					Kind: entity.RelChildOf,
				}); err != nil {
					return err
				}
			}
		}
	}

	return cctx.EmitEvidence(fact.EvidenceFact{
		SourceTool:     Name,
		SourceCategory: finding.SourcePublicOSINT,
		Confidence:     finding.ConfidenceHigh,
		Payload: map[string]any{
			"binary":          binary,
			"domains_input":   len(domains),
			"domains_queried": len(allowed),
			"urls_emitted":    urlsEmitted,
		},
	})
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
	var out []string
	for _, kind := range []entity.Kind{entity.KindDomain, entity.KindSubdomain} {
		values, err := cctx.ListEntityValues(kind)
		if err != nil {
			return nil, err
		}
		for _, v := range values {
			if v = strings.TrimSpace(v); v != "" {
				out = append(out, v)
			}
		}
	}
	if len(out) == 0 {
		return nil, errors.New("historical_urls: no domains; pass parameters[\"domains\"] or seed DOMAIN/SUBDOMAIN entities")
	}
	return out, nil
}

// extractHost grabs the host component of an http(s) URL without
// dragging in net/url for a few characters worth of parsing.
func extractHost(url string) string {
	if i := strings.Index(url, "://"); i >= 0 {
		url = url[i+3:]
	}
	if i := strings.Index(url, "/"); i >= 0 {
		url = url[:i]
	}
	if i := strings.LastIndex(url, "@"); i >= 0 {
		url = url[i+1:]
	}
	if i := strings.LastIndex(url, ":"); i >= 0 {
		url = url[:i]
	}
	return strings.ToLower(url)
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
