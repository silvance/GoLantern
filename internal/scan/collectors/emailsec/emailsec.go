// Package emailsec assesses a domain's email-spoofing posture via
// SPF / DMARC / DKIM / MX records. Pure passive DNS — no contact with
// any infrastructure outside the operator's recursive resolver.
//
// Ported from lantern/tools/email_security.py.
package emailsec

import (
	"context"
	"errors"
	"net"
	"regexp"
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
	Name           = "email_security"
	defaultTimeout = 5 * time.Second
)

// Resolver is the DNS surface the collector consumes. *net.Resolver
// from stdlib satisfies this; tests pass a fake so the suite doesn't
// depend on real DNS.
type Resolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
	LookupMX(ctx context.Context, name string) ([]*net.MX, error)
}

// New returns a collector that uses the default stdlib resolver.
func New() scan.Collector { return NewWithResolver(nil) }

// NewWithResolver lets tests inject a fake Resolver. nil falls back
// to net.DefaultResolver.
func NewWithResolver(r Resolver) scan.Collector {
	if r == nil {
		r = net.DefaultResolver
	}
	return &collector{resolver: r}
}

type collector struct{ resolver Resolver }

func (collector) Metadata() scan.Meta {
	return scan.Meta{
		Name:           Name,
		Phase:          workflow.PhaseExposure,
		RequiredScope:  scope.KindPassive,
		Description:    "Assess SPF / DMARC / DKIM / MX posture for the target domain.",
		Consumes:       []entity.Kind{entity.KindDomain},
		Produces:       []entity.Kind{entity.KindTechnology},
		SourceCategory: finding.SourcePassiveDNS,
		Parameters: []scan.ParameterSpec{
			{Name: "domain", Type: "string", Required: true, Placeholder: "example.com",
				Description: "Apex domain whose email posture is being assessed."},
			{Name: "timeout_seconds", Type: "float", Default: 5.0,
				Description: "Per-query DNS lifetime in seconds."},
			{Name: "dkim_selectors", Type: "string_list",
				Description: "DKIM selectors to probe (comma-separated). Not auto-discoverable; supply the ones in use."},
		},
	}
}

var (
	spfPrefix       = regexp.MustCompile(`(?i)^v=spf1\b`)
	dmarcPrefix     = regexp.MustCompile(`(?i)^v=dmarc1\b`)
	spfAllQualifier = regexp.MustCompile(`(?i)\s([+\-~?])all\b`)
)

func (c *collector) Run(ctx context.Context, cctx scan.Context) error {
	rawDomain, _ := cctx.Parameters()["domain"].(string)
	domain := strings.ToLower(strings.TrimSpace(rawDomain))
	domain = strings.TrimRight(domain, ".")
	if domain == "" {
		return errors.New("email_security: parameter `domain` is required")
	}
	if !cctx.IsInScope(domain) {
		return nil
	}

	timeout := parseTimeout(cctx.Parameters()["timeout_seconds"])
	selectors := parseStringList(cctx.Parameters()["dkim_selectors"])

	// Per-query context: budgets a single lookup, not the full run.
	// Honors the caller's ctx for cancellation.
	lookup := func(name string, fn func(context.Context, string) ([]string, error)) []string {
		qctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		out, err := fn(qctx, name)
		if err != nil && !isNoSuchHost(err) {
			// Non-NXDOMAIN errors are still worth logging upstream
			// but we treat them as "no record" to keep the collector
			// resilient — matches the Python behaviour (catch
			// DNSException, return empty).
			return nil
		}
		return out
	}

	spfTXT := lookup(domain, c.resolver.LookupTXT)
	dmarcTXT := lookup("_dmarc."+domain, c.resolver.LookupTXT)
	mxRecords := c.lookupMX(ctx, domain, timeout)

	spfRecord := selectMatching(spfTXT, spfPrefix)
	dmarcRecord := selectMatching(dmarcTXT, dmarcPrefix)
	dmarcTags := parseDMARC(dmarcRecord)

	if _, err := cctx.EmitEntity(fact.EntityFact{
		Kind:           entity.KindDomain,
		Value:          domain,
		Attributes:     map[string]any{"role": "primary"},
		Confidence:     finding.ConfidenceHigh,
		SourceCategory: finding.SourcePassiveDNS,
	}); err != nil {
		return err
	}

	if err := cctx.EmitEvidence(fact.EvidenceFact{
		SourceTool:     Name,
		SourceCategory: finding.SourcePassiveDNS,
		Confidence:     finding.ConfidenceHigh,
		Payload: map[string]any{
			"spf_record":            spfRecord,
			"dmarc_record":          dmarcRecord,
			"dmarc_policy":          dmarcTags["p"],
			"dmarc_subdomain_policy": dmarcTags["sp"],
			"dmarc_pct":             dmarcTags["pct"],
			"mx_hosts":              mxRecords,
			"dkim_selectors_checked": selectors,
		},
		EntityKind:  entity.KindDomain,
		EntityValue: domain,
	}); err != nil {
		return err
	}

	if err := emitSPFFindings(cctx, domain, spfRecord); err != nil {
		return err
	}
	if err := emitDMARCFindings(cctx, domain, dmarcRecord, dmarcTags); err != nil {
		return err
	}
	return c.checkDKIM(ctx, cctx, domain, selectors, timeout)
}

func (c *collector) lookupMX(ctx context.Context, name string, timeout time.Duration) []string {
	qctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	mx, err := c.resolver.LookupMX(qctx, name)
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(mx))
	for _, r := range mx {
		out = append(out, strings.TrimRight(strings.ToLower(r.Host), "."))
	}
	return out
}

func (c *collector) checkDKIM(
	ctx context.Context, cctx scan.Context, domain string,
	selectors []string, timeout time.Duration,
) error {
	for _, sel := range selectors {
		sel = strings.TrimSpace(sel)
		if sel == "" {
			continue
		}
		name := sel + "._domainkey." + domain
		qctx, cancel := context.WithTimeout(ctx, timeout)
		values, err := c.resolver.LookupTXT(qctx, name)
		cancel()
		hasDKIM := false
		if err == nil {
			for _, v := range values {
				if strings.HasPrefix(strings.ToLower(strings.TrimSpace(v)), "v=dkim1") {
					hasDKIM = true
					break
				}
			}
		}
		if hasDKIM {
			if err := cctx.EmitEvidence(fact.EvidenceFact{
				SourceTool:     Name,
				SourceCategory: finding.SourcePassiveDNS,
				Confidence:     finding.ConfidenceHigh,
				Payload:        map[string]any{"selector": sel, "name": name, "present": true},
				EntityKind:     entity.KindDomain,
				EntityValue:    domain,
			}); err != nil {
				return err
			}
			continue
		}
		if _, err := cctx.EmitFinding(fact.FindingFact{
			Title:      "DKIM selector \"" + sel + "\" not published for " + domain,
			Severity:   finding.SeverityLow,
			Confidence: finding.ConfidenceMedium,
			Category:   "email_dkim",
			Description: "No DKIM record was returned at " + name +
				". If this selector is in use by a sending platform, " +
				"messages it signs will fail DKIM validation and may be rejected.",
			Recommendation: "Confirm the selector value and publish the DKIM TXT record provided " +
				"by the sending platform, or remove the platform from your authorized sender list.",
			SupportingEntities: []fact.EntityRef{{Kind: entity.KindDomain, Value: domain}},
		}); err != nil {
			return err
		}
	}
	return nil
}

func emitSPFFindings(cctx scan.Context, domain, record string) error {
	if record == "" {
		_, err := cctx.EmitFinding(fact.FindingFact{
			Title:      "No SPF record published for " + domain,
			Severity:   finding.SeverityHigh,
			Confidence: finding.ConfidenceHigh,
			Category:   "email_spf",
			Description: "No TXT record matching v=spf1 was returned for " + domain +
				". Receiving mail systems have no policy to evaluate mail " +
				"claiming to come from this domain, making spoofing trivial.",
			Recommendation: "Publish an SPF TXT record listing all authorized mail senders, " +
				"terminating with `-all` to hard-fail unauthorized senders.",
			SupportingEntities: []fact.EntityRef{{Kind: entity.KindDomain, Value: domain}},
		})
		return err
	}
	qual := spfAllQualifier.FindStringSubmatch(" " + record)
	var qualifier string
	if len(qual) > 1 {
		qualifier = qual[1]
	}
	switch qualifier {
	case "+":
		_, err := cctx.EmitFinding(fact.FindingFact{
			Title:      "SPF record terminates with +all on " + domain,
			Severity:   finding.SeverityCritical,
			Confidence: finding.ConfidenceHigh,
			Category:   "email_spf",
			Description: "The SPF record ends with `+all`, authorizing any sender. " +
				"This is functionally equivalent to having no SPF policy.",
			Recommendation:     "Replace `+all` with `-all` (or `~all` during rollout).",
			SupportingEntities: []fact.EntityRef{{Kind: entity.KindDomain, Value: domain}},
		})
		return err
	case "?", "":
		_, err := cctx.EmitFinding(fact.FindingFact{
			Title:      "SPF policy is permissive on " + domain,
			Severity:   finding.SeverityMedium,
			Confidence: finding.ConfidenceHigh,
			Category:   "email_spf",
			Description: "The SPF record `" + record + "` does not terminate with a " +
				"hard or soft fail. Receivers will not reliably reject unauthorized senders.",
			Recommendation:     "Terminate the SPF record with `-all` (or `~all` during rollout).",
			SupportingEntities: []fact.EntityRef{{Kind: entity.KindDomain, Value: domain}},
		})
		return err
	case "~":
		_, err := cctx.EmitFinding(fact.FindingFact{
			Title:      "SPF policy uses softfail (~all) on " + domain,
			Severity:   finding.SeverityLow,
			Confidence: finding.ConfidenceHigh,
			Category:   "email_spf",
			Description: "The SPF record terminates with `~all` (softfail). " +
				"Mail from unauthorized senders is typically still delivered, just marked suspicious.",
			Recommendation:     "Move to `-all` once monitoring confirms all legitimate senders are listed.",
			SupportingEntities: []fact.EntityRef{{Kind: entity.KindDomain, Value: domain}},
		})
		return err
	}
	// '-' qualifier: ideal, no finding.
	return nil
}

func emitDMARCFindings(
	cctx scan.Context, domain, record string, tags map[string]string,
) error {
	if record == "" {
		_, err := cctx.EmitFinding(fact.FindingFact{
			Title:      "No DMARC record published for " + domain,
			Severity:   finding.SeverityHigh,
			Confidence: finding.ConfidenceHigh,
			Category:   "email_dmarc",
			Description: "No TXT record was returned at _dmarc." + domain +
				". Without DMARC, receiving mail systems have no instructions on " +
				"how to handle messages that fail SPF or DKIM alignment.",
			Recommendation: "Publish a DMARC TXT record at _dmarc." + domain +
				", starting with `p=none` for monitoring and progressing to " +
				"`p=quarantine` then `p=reject`.",
			SupportingEntities: []fact.EntityRef{{Kind: entity.KindDomain, Value: domain}},
		})
		return err
	}
	policy := strings.ToLower(tags["p"])
	switch policy {
	case "none":
		_, err := cctx.EmitFinding(fact.FindingFact{
			Title:      "DMARC policy is monitor-only (p=none) on " + domain,
			Severity:   finding.SeverityMedium,
			Confidence: finding.ConfidenceHigh,
			Category:   "email_dmarc",
			Description: "The DMARC record at _dmarc." + domain + " is configured " +
				"with `p=none`, which only requests reports without instructing " +
				"receivers to quarantine or reject spoofed messages.",
			Recommendation: "After confirming all legitimate mail aligns with SPF or DKIM, " +
				"tighten the policy to `p=quarantine` and then `p=reject`.",
			SupportingEntities: []fact.EntityRef{{Kind: entity.KindDomain, Value: domain}},
		})
		return err
	case "quarantine", "reject":
		// Good posture; no finding.
		return nil
	default:
		_, err := cctx.EmitFinding(fact.FindingFact{
			Title:      "DMARC policy on " + domain + " is missing or invalid",
			Severity:   finding.SeverityMedium,
			Confidence: finding.ConfidenceMedium,
			Category:   "email_dmarc",
			Description: "DMARC record `" + record + "` does not specify a valid " +
				"`p=` tag (expected one of: none, quarantine, reject).",
			Recommendation:     "Set `p=quarantine` or `p=reject` once monitoring confirms alignment.",
			SupportingEntities: []fact.EntityRef{{Kind: entity.KindDomain, Value: domain}},
		})
		return err
	}
}

// selectMatching returns the first TXT value matching re, trimmed, or "".
func selectMatching(values []string, re *regexp.Regexp) string {
	for _, v := range values {
		trimmed := strings.TrimSpace(v)
		if re.MatchString(trimmed) {
			return trimmed
		}
	}
	return ""
}

// parseDMARC splits a DMARC record into a tag map. Keys lowercased.
func parseDMARC(record string) map[string]string {
	out := map[string]string{}
	if record == "" {
		return out
	}
	for _, part := range strings.Split(record, ";") {
		eq := strings.Index(part, "=")
		if eq < 0 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(part[:eq]))
		val := strings.TrimSpace(part[eq+1:])
		if key != "" {
			out[key] = val
		}
	}
	return out
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

// parseStringList accepts []string, []any, or a single string. Returns
// nil for empty/missing/unparseable input — the collector skips DKIM
// entirely when no selectors are configured.
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

// isNoSuchHost reports whether err is a DNS NXDOMAIN. We treat it as
// "no record" rather than a runtime failure — matches the Python
// behaviour of catching dns.resolver.NXDOMAIN and returning empty.
func isNoSuchHost(err error) bool {
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return dnsErr.IsNotFound
	}
	return false
}
