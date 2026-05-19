// Package crtsh discovers subdomains via the public crt.sh certificate
// transparency index.
//
// Passive collector: only queries crt.sh, never the target. The runner
// enforces project scope authorizes passive collectors before this
// starts, and per-target IsInScope rejects the domain when a DENY rule
// covers it.
//
// Ported from lantern/tools/crtsh.py.
package crtsh

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/silvance/golantern/internal/entity"
	"github.com/silvance/golantern/internal/fact"
	"github.com/silvance/golantern/internal/finding"
	"github.com/silvance/golantern/internal/scan"
	"github.com/silvance/golantern/internal/scope"
	"github.com/silvance/golantern/internal/workflow"
)

const (
	Name           = "crtsh"
	defaultBaseURL = "https://crt.sh"
	defaultTimeout = 30 * time.Second
)

// crt.sh sits behind a backend that regularly returns 5xx under load;
// retry a handful of times with exponential backoff before propagating.
var retryStatuses = map[int]struct{}{
	http.StatusBadGateway:         {}, // 502
	http.StatusServiceUnavailable: {}, // 503
	http.StatusGatewayTimeout:     {}, // 504
}

const (
	maxAttempts    = 4
	initialBackoff = 2 * time.Second
)

// New returns a collector instance using the default HTTP client and
// public crt.sh endpoint. Tests construct via NewWithClient to swap in
// an httptest server.
func New() scan.Collector { return NewWithClient(nil, "") }

// NewWithClient lets tests inject a custom HTTP client and base URL.
// An empty baseURL falls back to the public crt.sh endpoint; nil
// client uses http.DefaultClient with a per-request context deadline
// drawn from the `timeout` parameter.
func NewWithClient(client *http.Client, baseURL string) scan.Collector {
	if baseURL == "" {
		baseURL = defaultBaseURL
	}
	if client == nil {
		client = http.DefaultClient
	}
	return &collector{client: client, baseURL: strings.TrimRight(baseURL, "/")}
}

type collector struct {
	client  *http.Client
	baseURL string
}

func (collector) Metadata() scan.Meta {
	return scan.Meta{
		Name:           Name,
		Phase:          workflow.PhaseAssetDiscovery,
		RequiredScope:  scope.KindPassive,
		Description:    "Discover subdomains via the public crt.sh certificate-transparency index.",
		Consumes:       []entity.Kind{entity.KindDomain},
		Produces:       []entity.Kind{entity.KindSubdomain},
		SourceCategory: finding.SourceCertTransparency,
		Parameters: []scan.ParameterSpec{
			{
				Name:        "domain",
				Type:        "string",
				Description: "Apex domain to query (e.g. example.com).",
				Required:    true,
				Placeholder: "example.com",
			},
			{
				Name:        "timeout_seconds",
				Type:        "float",
				Description: "HTTP timeout in seconds for the crt.sh request.",
				Default:     30.0,
			},
		},
	}
}

// crtshEntry mirrors the JSON shape crt.sh returns: each entry's
// name_value is a newline-joined list of subject + SAN names.
type crtshEntry struct {
	NameValue string `json:"name_value"`
}

func (c *collector) Run(ctx context.Context, cctx scan.Context) error {
	rawDomain, _ := cctx.Parameters()["domain"].(string)
	domain := strings.ToLower(strings.TrimSpace(rawDomain))
	if domain == "" {
		return errors.New("crtsh: parameter `domain` is required")
	}
	if !cctx.IsInScope(domain) {
		// Per-target scope reject. Not an error — the runner's
		// zero-emission diagnostic surfaces the operator-facing
		// "everything was out of scope" message when appropriate.
		return nil
	}

	timeout := parseTimeout(cctx.Parameters()["timeout_seconds"])
	httpCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	entries, err := c.fetch(httpCtx, domain)
	if err != nil {
		return err
	}

	subdomains := parseEntries(entries, domain)

	// Parent domain.
	if _, err := cctx.EmitEntity(fact.EntityFact{
		Kind:           entity.KindDomain,
		Value:          domain,
		Attributes:     map[string]any{"role": "primary"},
		Confidence:     finding.ConfidenceHigh,
		SourceCategory: finding.SourceCertTransparency,
	}); err != nil {
		return fmt.Errorf("emit domain: %w", err)
	}

	// Sort subdomains for deterministic output.
	sorted := make([]string, 0, len(subdomains))
	for sub := range subdomains {
		sorted = append(sorted, sub)
	}
	sort.Strings(sorted)

	for _, sub := range sorted {
		if _, err := cctx.EmitEntity(fact.EntityFact{
			Kind:           entity.KindSubdomain,
			Value:          sub,
			Confidence:     finding.ConfidenceMedium,
			SourceCategory: finding.SourceCertTransparency,
		}); err != nil {
			return fmt.Errorf("emit subdomain %q: %w", sub, err)
		}
		if err := cctx.EmitRelation(fact.RelationFact{
			Src:  fact.EntityRef{Kind: entity.KindSubdomain, Value: sub},
			Dst:  fact.EntityRef{Kind: entity.KindDomain, Value: domain},
			Kind: entity.RelChildOf,
		}); err != nil {
			return fmt.Errorf("emit relation %s -> %s: %w", sub, domain, err)
		}
	}

	// Summary evidence on the parent domain.
	if err := cctx.EmitEvidence(fact.EvidenceFact{
		SourceTool:     Name,
		SourceCategory: finding.SourceCertTransparency,
		Confidence:     finding.ConfidenceHigh,
		Payload: map[string]any{
			"domain":           domain,
			"subdomain_count":  len(subdomains),
			"raw_entry_count":  len(entries),
		},
		EntityKind:  entity.KindDomain,
		EntityValue: domain,
	}); err != nil {
		return fmt.Errorf("emit summary evidence: %w", err)
	}
	return nil
}

// fetch makes the crt.sh GET request with retry on transient 5xx.
// Backoff doubles per attempt. Honors ctx cancellation between sleeps
// so a shutdown during a backoff window returns promptly.
func (c *collector) fetch(ctx context.Context, domain string) ([]crtshEntry, error) {
	url := c.baseURL + "/?q=" + percentEncode("%."+domain) + "&output=json"
	backoff := initialBackoff
	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, fmt.Errorf("crtsh build request: %w", err)
		}
		resp, err := c.client.Do(req)
		if err != nil {
			lastErr = err
			// Network error: also retryable until we exhaust attempts.
			if attempt == maxAttempts {
				return nil, fmt.Errorf("crtsh HTTP: %w", err)
			}
		} else if _, retry := retryStatuses[resp.StatusCode]; retry && attempt < maxAttempts {
			resp.Body.Close()
			lastErr = fmt.Errorf("crtsh HTTP %d", resp.StatusCode)
		} else {
			defer resp.Body.Close()
			if resp.StatusCode >= 400 {
				body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
				return nil, fmt.Errorf("crtsh HTTP %d: %s", resp.StatusCode, string(body))
			}
			var entries []crtshEntry
			if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
				return nil, fmt.Errorf("crtsh decode: %w", err)
			}
			return entries, nil
		}
		// Wait before retry, honoring cancellation.
		select {
		case <-time.After(backoff):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		backoff *= 2
	}
	return nil, fmt.Errorf("crtsh exhausted retries: %w", lastErr)
}

// parseEntries extracts in-scope subdomain values from a crt.sh JSON
// response. crt.sh returns name_value as a newline-joined list.
// Wildcard entries (*.example.com) describe a CA-issued cert pattern,
// not a discoverable host — drop them. The root domain is dropped too;
// the caller emits it separately as the parent entity.
func parseEntries(entries []crtshEntry, domain string) map[string]struct{} {
	domainNorm := strings.ToLower(strings.TrimSpace(domain))
	suffix := "." + domainNorm
	out := map[string]struct{}{}
	for _, e := range entries {
		for _, raw := range strings.Split(e.NameValue, "\n") {
			name := strings.ToLower(strings.TrimSpace(raw))
			switch {
			case name == "":
				continue
			case strings.HasPrefix(name, "*"):
				continue
			case name == domainNorm:
				continue
			case !strings.HasSuffix(name, suffix):
				continue
			}
			out[name] = struct{}{}
		}
	}
	return out
}

// parseTimeout coerces the timeout parameter. Accepts float64
// (JSON-decoded), int, or string. Falls back to default on anything
// missing or unparseable.
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

// percentEncode wraps the url.QueryEscape behaviour we need. crt.sh
// expects "%." to remain as "%2E." or the percent itself encoded;
// the safer approach is to encode the whole query value.
func percentEncode(s string) string {
	// We can't import net/url at the top of the file without adding
	// indirection; do a tiny escape covering the characters crt.sh
	// cares about. % becomes %25, space %20, etc.
	var b strings.Builder
	b.Grow(len(s) * 3)
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '%':
			b.WriteString("%25")
		case c == ' ':
			b.WriteString("%20")
		case c == '+':
			b.WriteString("%2B")
		case c == '&':
			b.WriteString("%26")
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}
