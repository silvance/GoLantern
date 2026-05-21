// Package whois wraps the system whois client to enrich domain
// entities with registration metadata: registrar, creation/expiry
// dates, abuse contact, registrant org. Tells an analyst "this
// domain was registered last week" or "this is the brand's real
// domain, not a typosquat" without an external API.
//
// Output formats vary wildly per TLD and registrar. The parser is
// liberal: it picks up well-known key:value pairs and stashes the
// raw output as evidence so the operator can scroll it.
package whois

import (
	"context"
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
	Name           = "whois"
	defaultBinary  = "whois"
	defaultTimeout = 60 * time.Second
)

func New() scan.Collector { return &collector{} }

type runnerFn func(ctx context.Context, spec subprocess.Spec) (subprocess.Result, error)

func newWithRunner(r runnerFn) scan.Collector { return &collector{runner: r} }

type collector struct{ runner runnerFn }

func (collector) Metadata() scan.Meta {
	return scan.Meta{
		Name:           Name,
		Phase:          workflow.PhaseEnrichment,
		RequiredScope:  scope.KindPassive,
		Description:    "Fetch domain registration metadata via whois. Surfaces registrar, creation/expiry dates, registrant org, and abuse contact for every DOMAIN entity.",
		Consumes:       []entity.Kind{entity.KindDomain},
		Produces:       []entity.Kind{entity.KindDomain, entity.KindOrganization},
		SourceCategory: finding.SourcePublicOSINT,
		Binary:         "whois",
		InstallHint:    "Fedora: sudo dnf install whois\nDebian/Ubuntu: sudo apt install whois",
		Parameters: []scan.ParameterSpec{
			{Name: "domains", Type: "string_list", Placeholder: "example.com",
				Description: "Domains to look up. Empty falls back to every DOMAIN entity."},
			{Name: "binary", Type: "string", Default: "whois"},
			{Name: "timeout_seconds", Type: "float", Default: 60.0},
		},
	}
}

// whoisFields holds the parsed structured data; most are optional.
type whoisFields struct {
	Registrar      string
	CreationDate   string
	ExpiryDate     string
	UpdatedDate    string
	RegistrantOrg  string
	AbuseEmail     string
	Nameservers    []string
	Status         []string
}

// fieldMap is the case-insensitive key prefix -> structured field
// router. Multiple keys map to the same field because every
// registrar phrases things slightly differently ("Creation Date",
// "Created On", "Registered:").
var fieldMap = []struct {
	prefixes []string
	apply    func(*whoisFields, string)
}{
	{[]string{"registrar:"}, func(f *whoisFields, v string) {
		if f.Registrar == "" {
			f.Registrar = v
		}
	}},
	{[]string{"creation date:", "created:", "created on:", "registered:", "registered on:"}, func(f *whoisFields, v string) {
		if f.CreationDate == "" {
			f.CreationDate = v
		}
	}},
	{[]string{"registry expiry date:", "expiry date:", "expires:", "expiration date:"}, func(f *whoisFields, v string) {
		if f.ExpiryDate == "" {
			f.ExpiryDate = v
		}
	}},
	{[]string{"updated date:", "last updated:", "modified:"}, func(f *whoisFields, v string) {
		if f.UpdatedDate == "" {
			f.UpdatedDate = v
		}
	}},
	{[]string{"registrant organization:", "registrant org:", "org:"}, func(f *whoisFields, v string) {
		if f.RegistrantOrg == "" {
			f.RegistrantOrg = v
		}
	}},
	{[]string{"registrar abuse contact email:", "abuse-mailbox:", "abuse contact email:"}, func(f *whoisFields, v string) {
		if f.AbuseEmail == "" {
			f.AbuseEmail = v
		}
	}},
	{[]string{"name server:", "nserver:", "nameserver:"}, func(f *whoisFields, v string) {
		v = strings.ToLower(v)
		for _, n := range f.Nameservers {
			if n == v {
				return
			}
		}
		f.Nameservers = append(f.Nameservers, v)
	}},
	{[]string{"domain status:", "status:"}, func(f *whoisFields, v string) {
		for _, s := range f.Status {
			if s == v {
				return
			}
		}
		f.Status = append(f.Status, v)
	}},
}

func parseWhois(raw string) whoisFields {
	var out whoisFields
	for _, line := range strings.Split(raw, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "%") || strings.HasPrefix(trimmed, "#") {
			continue
		}
		lc := strings.ToLower(trimmed)
		for _, m := range fieldMap {
			for _, p := range m.prefixes {
				if strings.HasPrefix(lc, p) {
					value := strings.TrimSpace(trimmed[len(p):])
					if value != "" {
						m.apply(&out, value)
					}
					break
				}
			}
		}
	}
	return out
}

func (c *collector) Run(ctx context.Context, cctx scan.Context) error {
	binary := strings.TrimSpace(toString(cctx.Parameters()["binary"]))
	if binary == "" {
		binary = defaultBinary
	}
	timeout := parseTimeout(cctx.Parameters()["timeout_seconds"])

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
		result, err := run(ctx, subprocess.Spec{
			Binary:         binary,
			Args:           []string{domain},
			Timeout:        timeout,
			AllowPartialRC: []int{1, 2},
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
		fields := parseWhois(string(result.Stdout))

		// Re-emit the domain so the attributes attach to it; the
		// runner dedups on (kind, value) so we don't create duplicates.
		attrs := map[string]any{"discovered_via": Name}
		if fields.Registrar != "" {
			attrs["registrar"] = fields.Registrar
		}
		if fields.CreationDate != "" {
			attrs["creation_date"] = fields.CreationDate
		}
		if fields.ExpiryDate != "" {
			attrs["expiry_date"] = fields.ExpiryDate
		}
		if fields.UpdatedDate != "" {
			attrs["updated_date"] = fields.UpdatedDate
		}
		if fields.RegistrantOrg != "" {
			attrs["registrant_org"] = fields.RegistrantOrg
		}
		if fields.AbuseEmail != "" {
			attrs["abuse_email"] = fields.AbuseEmail
		}
		if len(fields.Nameservers) > 0 {
			attrs["nameservers"] = fields.Nameservers
		}
		if len(fields.Status) > 0 {
			attrs["domain_status"] = fields.Status
		}
		if _, err := cctx.EmitEntity(fact.EntityFact{
			Kind:           entity.KindDomain,
			Value:          domain,
			Attributes:     attrs,
			Confidence:     finding.ConfidenceHigh,
			SourceCategory: finding.SourcePublicOSINT,
		}); err != nil {
			return err
		}

		// Promote the registrant org to its own entity when present;
		// the brand graph then links the domain to the organization.
		if fields.RegistrantOrg != "" {
			if _, err := cctx.EmitEntity(fact.EntityFact{
				Kind:           entity.KindOrganization,
				Value:          fields.RegistrantOrg,
				Attributes:     map[string]any{"discovered_via": Name, "source_domain": domain},
				Confidence:     finding.ConfidenceMedium,
				SourceCategory: finding.SourcePublicOSINT,
			}); err != nil {
				return err
			}
		}

		if err := cctx.EmitEvidence(fact.EvidenceFact{
			SourceTool:     Name,
			SourceCategory: finding.SourcePublicOSINT,
			Confidence:     finding.ConfidenceHigh,
			Payload:        whoisEvidencePayload(domain, fields),
			EntityKind:     entity.KindDomain,
			EntityValue:    domain,
		}); err != nil {
			return err
		}
	}
	return nil
}

func whoisEvidencePayload(domain string, f whoisFields) map[string]any {
	out := map[string]any{"domain": domain}
	if f.Registrar != "" {
		out["registrar"] = f.Registrar
	}
	if f.CreationDate != "" {
		out["creation_date"] = f.CreationDate
	}
	if f.ExpiryDate != "" {
		out["expiry_date"] = f.ExpiryDate
	}
	if f.UpdatedDate != "" {
		out["updated_date"] = f.UpdatedDate
	}
	if f.RegistrantOrg != "" {
		out["registrant_org"] = f.RegistrantOrg
	}
	if f.AbuseEmail != "" {
		out["abuse_email"] = f.AbuseEmail
	}
	if len(f.Nameservers) > 0 {
		out["nameservers"] = f.Nameservers
	}
	if len(f.Status) > 0 {
		out["status"] = f.Status
	}
	return out
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
	if len(values) == 0 {
		return nil, fmt.Errorf("whois: no domains to query; pass parameters[\"domains\"] or seed DOMAIN entities")
	}
	return values, nil
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

var _ = errors.New // retained for future error wrapping
