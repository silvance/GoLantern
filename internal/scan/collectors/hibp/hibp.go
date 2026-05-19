// Package hibp queries Have I Been Pwned for breach records against
// known email addresses. Breach intel: traffic only goes to
// haveibeenpwned.com.
//
// Requires a HIBP API key — passed via parameters["api_key"] or
// $HIBP_API_KEY. HIBP charges per month; the free tier doesn't cover
// breach lookups.
//
// Ported from lantern/tools/hibp.py (compact form).
package hibp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
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
	Name             = "hibp"
	defaultBaseURL   = "https://haveibeenpwned.com"
	defaultTimeout   = 30 * time.Second
	defaultDelay     = 1500 * time.Millisecond
	defaultUserAgent = "GoLantern/0.1"
	recentDays       = 365
)

func New() scan.Collector { return NewWithClient(nil, "") }

func NewWithClient(client *http.Client, baseURL string) scan.Collector {
	if client == nil {
		client = http.DefaultClient
	}
	if baseURL == "" {
		baseURL = defaultBaseURL
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
		Phase:          workflow.PhaseEnrichment,
		RequiredScope:  scope.KindPassive,
		Description:    "Check known email entities for HIBP breach records; emit a Finding when any are returned.",
		Consumes:       []entity.Kind{entity.KindEmail},
		Produces:       []entity.Kind{entity.KindEmail},
		SourceCategory: finding.SourceBreachIntel,
		Parameters: []scan.ParameterSpec{
			{Name: "emails", Type: "string_list",
				Description: "Email addresses to check. Empty falls back to every EMAIL entity in the project."},
			{Name: "api_key", Type: "string",
				Description: "HIBP API key. Falls back to $HIBP_API_KEY."},
			{Name: "user_agent", Type: "string", Default: defaultUserAgent},
			{Name: "request_delay_ms", Type: "int", Default: 1500,
				Description: "Per-request delay in milliseconds (HIBP rate-limits at 1500ms between calls for k-anonymity tiers)."},
			{Name: "timeout_seconds", Type: "float", Default: 30.0},
		},
	}
}

type hibpBreach struct {
	Name         string `json:"Name"`
	Title        string `json:"Title"`
	Domain       string `json:"Domain"`
	BreachDate   string `json:"BreachDate"`
	IsVerified   bool   `json:"IsVerified"`
	IsSensitive  bool   `json:"IsSensitive"`
	IsFabricated bool   `json:"IsFabricated"`
}

func (c *collector) Run(ctx context.Context, cctx scan.Context) error {
	key, _ := cctx.Parameters()["api_key"].(string)
	key = strings.TrimSpace(key)
	if key == "" {
		key = os.Getenv("HIBP_API_KEY")
	}
	if key == "" {
		return errors.New("hibp: api_key required (parameter or $HIBP_API_KEY)")
	}
	ua, _ := cctx.Parameters()["user_agent"].(string)
	if ua == "" {
		ua = defaultUserAgent
	}
	timeout := parseTimeout(cctx.Parameters()["timeout_seconds"])
	delay := parseDelay(cctx.Parameters()["request_delay_ms"])

	emails, err := c.resolveEmails(cctx)
	if err != nil {
		return err
	}
	var allowed []string
	for _, e := range emails {
		if cctx.IsInScope(e) {
			allowed = append(allowed, strings.ToLower(e))
		}
	}
	if len(allowed) == 0 {
		return nil
	}

	withBreaches, clean, totalBreaches := 0, 0, 0
	for i, email := range allowed {
		if i > 0 && delay > 0 {
			select {
			case <-time.After(delay):
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		breaches, status, err := c.fetchBreaches(ctx, email, key, ua, timeout)
		if err != nil {
			return fmt.Errorf("hibp: %w", err)
		}
		if status == http.StatusNotFound || len(breaches) == 0 {
			clean++
			_ = cctx.EmitEvidence(fact.EvidenceFact{
				SourceTool:     Name,
				SourceCategory: finding.SourceBreachIntel,
				Confidence:     finding.ConfidenceHigh,
				Payload:        map[string]any{"breach_count": 0},
				EntityKind:     entity.KindEmail,
				EntityValue:    email,
				Notes:          "No HIBP breach record for this address.",
			})
			continue
		}
		withBreaches++
		totalBreaches += len(breaches)
		if err := c.emitBreachFindings(cctx, email, breaches); err != nil {
			return err
		}
	}

	return cctx.EmitEvidence(fact.EvidenceFact{
		SourceTool:     Name,
		SourceCategory: finding.SourceBreachIntel,
		Confidence:     finding.ConfidenceHigh,
		Payload: map[string]any{
			"emails_checked":       len(allowed),
			"emails_with_breaches": withBreaches,
			"emails_clean":         clean,
			"total_breach_hits":    totalBreaches,
		},
	})
}

func (c *collector) emitBreachFindings(cctx scan.Context, email string, breaches []hibpBreach) error {
	// Make sure the email entity exists.
	if _, err := cctx.EmitEntity(fact.EntityFact{
		Kind:           entity.KindEmail,
		Value:          email,
		Confidence:     finding.ConfidenceHigh,
		SourceCategory: finding.SourceBreachIntel,
	}); err != nil {
		return err
	}

	// Compute severity: MEDIUM if any breach is recent OR any is
	// sensitive; LOW otherwise.
	var daysToLatest *int
	var latestName string
	anySensitive := false
	for _, b := range breaches {
		if b.IsSensitive {
			anySensitive = true
		}
		if d, ok := daysSince(b.BreachDate); ok {
			if daysToLatest == nil || d < *daysToLatest {
				dd := d
				daysToLatest = &dd
				latestName = b.Title
			}
		}
	}
	isRecent := daysToLatest != nil && *daysToLatest <= recentDays
	severity := finding.SeverityLow
	if isRecent || anySensitive {
		severity = finding.SeverityMedium
	}

	// Sort breaches newest-first for the evidence summary.
	sort.SliceStable(breaches, func(i, j int) bool {
		return breaches[i].BreachDate > breaches[j].BreachDate
	})
	summary := make([]map[string]any, len(breaches))
	for i, b := range breaches {
		summary[i] = map[string]any{
			"name":          b.Name,
			"title":         b.Title,
			"domain":        b.Domain,
			"breach_date":   b.BreachDate,
			"is_verified":   b.IsVerified,
			"is_sensitive":  b.IsSensitive,
			"is_fabricated": b.IsFabricated,
		}
	}

	if err := cctx.EmitEvidence(fact.EvidenceFact{
		SourceTool:     Name,
		SourceCategory: finding.SourceBreachIntel,
		Confidence:     finding.ConfidenceHigh,
		Payload: map[string]any{
			"email":              email,
			"breach_count":       len(breaches),
			"latest_breach_name": latestName,
			"any_sensitive":      anySensitive,
			"breaches":           summary,
		},
		EntityKind:  entity.KindEmail,
		EntityValue: email,
	}); err != nil {
		return err
	}

	title := fmt.Sprintf("Email %s exposed in %d known breach", email, len(breaches))
	if len(breaches) != 1 {
		title += "es"
	}
	desc := fmt.Sprintf("Have I Been Pwned reports %d breach records for %s.", len(breaches), email)
	if latestName != "" && daysToLatest != nil {
		desc = fmt.Sprintf("Have I Been Pwned reports %d breach records for %s; the most recent is %q (%d days ago).",
			len(breaches), email, latestName, *daysToLatest)
	}
	_, err := cctx.EmitFinding(fact.FindingFact{
		Title:      title,
		Severity:   severity,
		Confidence: finding.ConfidenceHigh,
		Category:   "breach_exposure",
		Description: desc,
		Recommendation: "Confirm the address is still in active use. If the user is current, " +
			"force a password reset and review MFA enrollment. If the address belongs to a " +
			"former employee, remove or redirect the mailbox.",
		SupportingEntities: []fact.EntityRef{{Kind: entity.KindEmail, Value: email}},
	})
	return err
}

func (c *collector) fetchBreaches(ctx context.Context, email, key, ua string, timeout time.Duration) ([]hibpBreach, int, error) {
	qctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	endpoint := fmt.Sprintf("%s/api/v3/breachedaccount/%s?truncateResponse=false", c.baseURL, url.PathEscape(email))
	req, err := http.NewRequestWithContext(qctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("hibp-api-key", key)
	req.Header.Set("User-Agent", ua)
	req.Header.Set("Accept", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil, http.StatusNotFound, nil
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return nil, resp.StatusCode, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}
	var breaches []hibpBreach
	if err := json.NewDecoder(resp.Body).Decode(&breaches); err != nil {
		return nil, resp.StatusCode, fmt.Errorf("decode: %w", err)
	}
	return breaches, resp.StatusCode, nil
}

func (c *collector) resolveEmails(cctx scan.Context) ([]string, error) {
	explicit := parseStringList(cctx.Parameters()["emails"])
	if len(explicit) > 0 {
		out := make([]string, 0, len(explicit))
		for _, e := range explicit {
			if e = strings.TrimSpace(e); e != "" {
				out = append(out, e)
			}
		}
		if len(out) > 0 {
			return out, nil
		}
	}
	values, err := cctx.ListEntityValues(entity.KindEmail)
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
		return nil, errors.New("hibp: no emails to check; pass parameters[\"emails\"] or seed EMAIL entities")
	}
	return out, nil
}

// daysSince parses a YYYY-MM-DD breach date and returns the number of
// days between today and that date. Returns ok=false for unparseable
// inputs (which HIBP shouldn't emit but we tolerate).
func daysSince(date string) (int, bool) {
	t, err := time.Parse("2006-01-02", strings.TrimSpace(date))
	if err != nil {
		return 0, false
	}
	hours := time.Since(t).Hours()
	if hours < 0 {
		hours = 0
	}
	return int(hours / 24), true
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

func parseDelay(v any) time.Duration {
	switch x := v.(type) {
	case float64:
		if x >= 0 {
			return time.Duration(x) * time.Millisecond
		}
	case int:
		if x >= 0 {
			return time.Duration(x) * time.Millisecond
		}
	}
	return defaultDelay
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
