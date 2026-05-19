// Package httpxprobe wraps the ProjectDiscovery httpx CLI as a
// validation-phase collector. Takes subdomains from earlier OSINT
// (or an explicit names list) and produces:
//
//   - URL entity per live origin
//   - TECHNOLOGY entities + USES_TECH relations
//   - SERVES relations from URL -> SUBDOMAIN
//   - LOW-severity findings flagging admin/login portals for review
//
// Ported from lantern/tools/httpx_probe.py.
//
// IMPORTANT: this wraps ProjectDiscovery's `httpx` (Go binary), NOT
// the Python httpx HTTP client library. If `pip install httpx` is on
// PATH ahead of the Go binary, override `binary` or rename the pip
// script.
package httpxprobe

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
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
	Name           = "httpx_probe"
	defaultBinary  = "httpx"
	defaultTimeout = 180 * time.Second
)

// Conservative substrings: matching produces a LOW-severity finding for
// analyst review, never an automatic high-severity conclusion.
var interestingPatterns = []string{
	"login", "sign in", "admin", "dashboard", "console", "vpn", "ssl vpn",
	"outlook web", "owa", "exchange", "phpmyadmin", "jenkins", "grafana",
	"kibana", "gitlab", "jira", "confluence",
}

// New returns a collector using the default httpx binary on PATH.
func New() scan.Collector { return &collector{} }

type runnerFn func(ctx context.Context, spec subprocess.Spec) (subprocess.Result, error)

// newWithRunner is the test-injection point. Production New() uses
// subprocess.Run; tests pass a runner returning canned JSONL.
func newWithRunner(r runnerFn) scan.Collector { return &collector{runner: r} }

type collector struct {
	runner runnerFn
}

func (collector) Metadata() scan.Meta {
	return scan.Meta{
		Name:               Name,
		Phase:              workflow.PhaseValidation,
		RequiredScope:      scope.KindLightActive,
		Description:        "HTTP(S) liveness, status, title, technology + TLS subject for discovered subdomains.",
		Consumes:           []entity.Kind{entity.KindSubdomain},
		Produces:           []entity.Kind{entity.KindURL, entity.KindTechnology},
		SourceCategory:     finding.SourceLiveProbe,
		TriggersOnServices: []string{"http", "https"},
		Binary:             "httpx",
		InstallHint: "go install github.com/projectdiscovery/httpx/cmd/httpx@latest\n" +
			"# IMPORTANT: this is ProjectDiscovery's httpx, NOT the Python `httpx`\n" +
			"# library. If `pip install httpx` is on PATH ahead of the Go binary,\n" +
			"# override the `binary` parameter or rename the pip script.",
		Parameters: []scan.ParameterSpec{
			{Name: "names", Type: "string_list", Placeholder: "api.example.com, www.example.com",
				Description: "Subdomains to probe. Empty falls back to every SUBDOMAIN entity in the project."},
			{Name: "binary", Type: "string", Default: "httpx",
				Description: "Override the httpx binary path or name."},
			{Name: "timeout_seconds", Type: "float", Default: 180.0,
				Description: "Wall-clock timeout in seconds for the httpx subprocess."},
			{Name: "extra_args", Type: "string_list",
				Description: "Extra httpx flags (comma-separated). Output must remain JSONL; -json must stay enabled."},
		},
	}
}

// httpxJSON is the subset of httpx's --json output we consume.
// Unknown fields are ignored; the runner streams `raw` into the
// evidence row so analyst-side debugging keeps full fidelity.
type httpxJSON struct {
	Input         string   `json:"input"`
	URL           string   `json:"url"`
	Scheme        string   `json:"scheme"`
	Host          string   `json:"host"`
	Port          any      `json:"port"` // httpx ships int or string depending on version
	StatusCode    *int     `json:"status_code"`
	Title         string   `json:"title"`
	Webserver     string   `json:"webserver"`
	Tech          []string `json:"tech"`
	ContentLength *int     `json:"content_length"`
	Chain         []string `json:"chain"`
	TLS           struct {
		SubjectDN string `json:"subject_dn"`
	} `json:"tls"`
}

func (c *collector) Run(ctx context.Context, cctx scan.Context) error {
	binary := strings.TrimSpace(toString(cctx.Parameters()["binary"]))
	if binary == "" {
		binary = defaultBinary
	}
	timeout := parseTimeout(cctx.Parameters()["timeout_seconds"])
	extraArgs := parseStringList(cctx.Parameters()["extra_args"])

	names, err := c.resolveNames(cctx)
	if err != nil {
		return err
	}
	var inScope []string
	for _, n := range names {
		if cctx.IsInScope(n) {
			inScope = append(inScope, strings.ToLower(n))
		}
	}
	skipped := len(names) - len(inScope)
	if len(inScope) == 0 {
		// All out-of-scope or empty. Zero-emission diagnostic in the
		// runner surfaces the message when needed.
		return nil
	}

	args := []string{
		"-silent",
		"-json",
		"-status-code",
		"-title",
		"-tech-detect",
		"-server",
		"-content-length",
		"-follow-redirects",
		"-no-color",
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
		return fmt.Errorf("httpx_probe: %w", err)
	}

	records := parseJSONL(result.Stdout)
	liveURLs := 0
	techsSeen := map[string]struct{}{}
	portalCount := 0

	for _, r := range records {
		if r.StatusCode == nil {
			continue
		}
		liveURLs++
		host := strings.ToLower(strings.TrimSpace(r.Host))
		if host == "" {
			host = strings.ToLower(strings.TrimSpace(r.Input))
		}
		urlValue := strings.TrimSpace(r.URL)
		if urlValue == "" {
			continue
		}
		portStr := portToString(r.Port)

		if _, err := cctx.EmitEntity(fact.EntityFact{
			Kind:           entity.KindURL,
			Value:          urlValue,
			SourceCategory: finding.SourceLiveProbe,
			Confidence:     finding.ConfidenceHigh,
			Attributes: map[string]any{
				"scheme":         strings.ToLower(r.Scheme),
				"host":           host,
				"port":           portStr,
				"status_code":    *r.StatusCode,
				"title":          r.Title,
				"webserver":      r.Webserver,
				"content_length": intPtrValue(r.ContentLength),
			},
		}); err != nil {
			return err
		}
		if host != "" {
			if err := cctx.EmitRelation(fact.RelationFact{
				Src:  fact.EntityRef{Kind: entity.KindURL, Value: urlValue},
				Dst:  fact.EntityRef{Kind: entity.KindSubdomain, Value: host},
				Kind: entity.RelServes,
			}); err != nil {
				return err
			}
		}
		for _, t := range r.Tech {
			tv := strings.TrimSpace(t)
			if tv == "" {
				continue
			}
			techsSeen[tv] = struct{}{}
			if _, err := cctx.EmitEntity(fact.EntityFact{
				Kind:           entity.KindTechnology,
				Value:          tv,
				SourceCategory: finding.SourceLiveProbe,
				Confidence:     finding.ConfidenceMedium,
			}); err != nil {
				return err
			}
			if err := cctx.EmitRelation(fact.RelationFact{
				Src:  fact.EntityRef{Kind: entity.KindURL, Value: urlValue},
				Dst:  fact.EntityRef{Kind: entity.KindTechnology, Value: tv},
				Kind: entity.RelUsesTech,
			}); err != nil {
				return err
			}
		}
		if err := cctx.EmitEvidence(fact.EvidenceFact{
			SourceTool:     Name,
			SourceCategory: finding.SourceLiveProbe,
			Confidence:     finding.ConfidenceHigh,
			Payload: map[string]any{
				"status_code":    *r.StatusCode,
				"title":          r.Title,
				"webserver":      r.Webserver,
				"content_length": intPtrValue(r.ContentLength),
				"redirect_chain": r.Chain,
				"tls_subject":    r.TLS.SubjectDN,
			},
			EntityKind:  entity.KindURL,
			EntityValue: urlValue,
		}); err != nil {
			return err
		}

		if kw := matchInterestingKeyword(r.Title, urlValue); kw != "" {
			portalCount++
			if _, err := cctx.EmitFinding(fact.FindingFact{
				Title:      "Externally exposed portal at " + urlValue,
				Severity:   finding.SeverityLow,
				Confidence: finding.ConfidenceLow,
				Category:   "exposed_portal",
				Description: fmt.Sprintf(
					"Live HTTP probe of %s returned status %d with title %q. "+
						"The page or URL contains the keyword %q, which often indicates "+
						"an administrative or authentication-related interface.",
					urlValue, *r.StatusCode, r.Title, kw,
				),
				Recommendation: "Review whether this interface should be reachable from the " +
					"public internet. If exposure is required, ensure MFA, IP allowlisting, " +
					"or VPN gating is in place.",
				SupportingEntities: []fact.EntityRef{
					{Kind: entity.KindURL, Value: urlValue},
					{Kind: entity.KindSubdomain, Value: host},
				},
			}); err != nil {
				return err
			}
		}
	}

	// Sorted tech list for the summary evidence row (deterministic shape).
	techs := make([]string, 0, len(techsSeen))
	for t := range techsSeen {
		techs = append(techs, t)
	}
	sort.Strings(techs)

	return cctx.EmitEvidence(fact.EvidenceFact{
		SourceTool:     Name,
		SourceCategory: finding.SourceLiveProbe,
		Confidence:     finding.ConfidenceHigh,
		Payload: map[string]any{
			"names_input":                len(names),
			"names_skipped_out_of_scope": skipped,
			"live_urls":                  liveURLs,
			"technologies_seen":          techs,
			"portals_flagged":            portalCount,
		},
	})
}

func (c *collector) resolveNames(cctx scan.Context) ([]string, error) {
	explicit := parseStringList(cctx.Parameters()["names"])
	if len(explicit) > 0 {
		out := make([]string, 0, len(explicit))
		for _, n := range explicit {
			if n = strings.TrimSpace(n); n != "" {
				out = append(out, n)
			}
		}
		if len(out) > 0 {
			return out, nil
		}
	}
	values, err := cctx.ListEntityValues(entity.KindSubdomain)
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
		return nil, errors.New("httpx_probe: no targets to probe; pass parameters[\"names\"] or seed SUBDOMAIN entities")
	}
	return out, nil
}

// parseJSONL parses one httpx JSON object per non-blank line. Lines
// that fail to decode are silently skipped — httpx occasionally emits
// progress noise alongside JSON in older versions.
func parseJSONL(blob []byte) []httpxJSON {
	var out []httpxJSON
	for _, raw := range strings.Split(string(blob), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		var rec httpxJSON
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			continue
		}
		out = append(out, rec)
	}
	return out
}

// matchInterestingKeyword returns the first interesting substring
// found in the page title or URL, or "" if nothing matches.
func matchInterestingKeyword(title, url string) string {
	haystack := strings.ToLower(title + " " + url)
	for _, kw := range interestingPatterns {
		if strings.Contains(haystack, kw) {
			return kw
		}
	}
	return ""
}

// portToString handles httpx's mixed int/string port serialization.
func portToString(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case float64:
		if x == 0 {
			return ""
		}
		return fmt.Sprintf("%d", int(x))
	}
	return ""
}

func intPtrValue(p *int) any {
	if p == nil {
		return nil
	}
	return *p
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

