// Package dnsrecon wraps the dnsrecon CLI for richer DNS recon than
// dnsx covers. Two real wins: it attempts AXFR zone transfers (a
// misconfigured nameserver leaks the entire zone in one query, and
// nothing else in the collector set tries it), and it walks the
// standard record set (A/AAAA/NS/SOA/MX/TXT/SPF) in one invocation.
//
// dnsrecon's JSON output reports each record as a `{type, name,
// address, ...}` row; we map A/AAAA records to IP entities, NS/MX
// records to subdomain entities (the targets are hostnames), and
// AXFR responses surface every record returned by the zone transfer.
package dnsrecon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
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
	Name           = "dnsrecon"
	defaultBinary  = "dnsrecon"
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
		Description:    "DNS reconnaissance via dnsrecon: standard record walk (A/AAAA/NS/MX/SOA/TXT) plus AXFR zone-transfer attempts that catch misconfigured nameservers.",
		Consumes:       []entity.Kind{entity.KindDomain},
		Produces:       []entity.Kind{entity.KindSubdomain, entity.KindIP},
		SourceCategory: finding.SourcePassiveDNS,
		Binary:         "dnsrecon",
		InstallHint:    "pipx install dnsrecon",
		Parameters: []scan.ParameterSpec{
			{Name: "domains", Type: "string_list", Placeholder: "example.com",
				Description: "Domains to enumerate. Empty falls back to every DOMAIN entity."},
			{Name: "types", Type: "string", Default: "std,axfr",
				Description: "Comma-separated dnsrecon -t types. Common: std (records), axfr (zone transfer), zonewalk (DNSSEC NSEC walk)."},
			{Name: "binary", Type: "string", Default: "dnsrecon"},
			{Name: "timeout_seconds", Type: "float", Default: 300.0},
		},
	}
}

// dnsreconRecord matches dnsrecon's -j JSON output rows. Fields are
// optional because shape varies by record type.
type dnsreconRecord struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Target  string `json:"target"`
	Address string `json:"address"`
	Exchange string `json:"exchange"`
	Strings []string `json:"strings"`
	Mname   string `json:"mname"`
	ZoneTransfer string `json:"zone_transfer"`
}

func (c *collector) Run(ctx context.Context, cctx scan.Context) error {
	binary := strings.TrimSpace(toString(cctx.Parameters()["binary"]))
	if binary == "" {
		binary = defaultBinary
	}
	timeout := parseTimeout(cctx.Parameters()["timeout_seconds"])
	types := strings.TrimSpace(toString(cctx.Parameters()["types"]))
	if types == "" {
		types = "std,axfr"
	}

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
		tmp, err := os.MkdirTemp("", "golantern-dnsrecon-")
		if err != nil {
			return fmt.Errorf("dnsrecon: tempdir: %w", err)
		}
		jsonPath := filepath.Join(tmp, domain+".json")
		args := []string{"-d", domain, "-t", types, "-j", jsonPath}
		_, runErr := run(ctx, subprocess.Spec{
			Binary:         binary,
			Args:           args,
			Timeout:        timeout,
			AllowPartialRC: []int{1, 2},
		})
		if runErr != nil {
			os.RemoveAll(tmp)
			_ = cctx.EmitEvidence(fact.EvidenceFact{
				SourceTool:     Name,
				SourceCategory: finding.SourcePassiveDNS,
				Confidence:     finding.ConfidenceLow,
				Payload:        map[string]any{"domain": domain, "error": runErr.Error()},
				EntityKind:     entity.KindDomain,
				EntityValue:    domain,
			})
			continue
		}
		blob, err := os.ReadFile(jsonPath)
		os.RemoveAll(tmp)
		if err != nil {
			_ = cctx.EmitEvidence(fact.EvidenceFact{
				SourceTool:     Name,
				SourceCategory: finding.SourcePassiveDNS,
				Confidence:     finding.ConfidenceLow,
				Payload:        map[string]any{"domain": domain, "json_read_error": err.Error()},
				EntityKind:     entity.KindDomain,
				EntityValue:    domain,
			})
			continue
		}
		if err := c.processRecords(cctx, domain, blob); err != nil {
			return err
		}
	}
	return nil
}

func (c *collector) processRecords(cctx scan.Context, domain string, blob []byte) error {
	var records []dnsreconRecord
	if err := json.Unmarshal(blob, &records); err != nil {
		// dnsrecon sometimes wraps the array in an object. Try a
		// permissive re-parse before giving up.
		var wrapper map[string]json.RawMessage
		if err2 := json.Unmarshal(blob, &wrapper); err2 == nil {
			for _, v := range wrapper {
				var inner []dnsreconRecord
				if json.Unmarshal(v, &inner) == nil {
					records = append(records, inner...)
				}
			}
		}
		if len(records) == 0 {
			_ = cctx.EmitEvidence(fact.EvidenceFact{
				SourceTool:     Name,
				SourceCategory: finding.SourcePassiveDNS,
				Confidence:     finding.ConfidenceLow,
				Payload:        map[string]any{"domain": domain, "parse_error": err.Error()},
				EntityKind:     entity.KindDomain,
				EntityValue:    domain,
			})
			return nil
		}
	}

	axfrSucceeded := false
	subsEmitted := 0
	ipsEmitted := 0
	suffix := "." + domain
	for _, rec := range records {
		// Zone-transfer success row — flag as a finding because it's
		// genuinely a misconfiguration worth surfacing.
		if strings.EqualFold(rec.Type, "info") && rec.ZoneTransfer != "" &&
			strings.EqualFold(rec.ZoneTransfer, "success") {
			axfrSucceeded = true
		}
		switch strings.ToLower(rec.Type) {
		case "a", "aaaa":
			host := strings.ToLower(strings.TrimSpace(rec.Name))
			ip := strings.TrimSpace(rec.Address)
			if host == "" || ip == "" {
				continue
			}
			// Host -> subdomain (when below the apex).
			if host != domain && (host == domain || strings.HasSuffix(host, suffix)) {
				if cctx.IsInScope(host) {
					if _, err := cctx.EmitEntity(fact.EntityFact{
						Kind:           entity.KindSubdomain,
						Value:          host,
						Attributes:     map[string]any{"discovered_via": Name, "via": rec.Type},
						Confidence:     finding.ConfidenceHigh,
						SourceCategory: finding.SourcePassiveDNS,
					}); err != nil {
						return err
					}
					subsEmitted++
				}
			}
			// IP entity.
			if cctx.IsInScope(ip) {
				if _, err := cctx.EmitEntity(fact.EntityFact{
					Kind:           entity.KindIP,
					Value:          ip,
					Attributes:     map[string]any{"discovered_via": Name, "via": rec.Type, "source_host": host},
					Confidence:     finding.ConfidenceHigh,
					SourceCategory: finding.SourcePassiveDNS,
				}); err != nil {
					return err
				}
				ipsEmitted++
			}
		case "ns", "mx":
			target := strings.ToLower(strings.TrimSpace(firstNonEmpty(rec.Target, rec.Exchange)))
			if target == "" || target == domain {
				continue
			}
			if !cctx.IsInScope(target) {
				continue
			}
			if _, err := cctx.EmitEntity(fact.EntityFact{
				Kind:           entity.KindSubdomain,
				Value:          target,
				Attributes:     map[string]any{"discovered_via": Name, "via": rec.Type, "source_domain": domain},
				Confidence:     finding.ConfidenceMedium,
				SourceCategory: finding.SourcePassiveDNS,
			}); err != nil {
				return err
			}
			subsEmitted++
		}
	}

	if axfrSucceeded {
		if _, err := cctx.EmitFinding(fact.FindingFact{
			Title:       fmt.Sprintf("AXFR zone transfer succeeded for %s", domain),
			Severity:    finding.SeverityHigh,
			Confidence:  finding.ConfidenceHigh,
			Category:    "dns.zone_transfer",
			Description: fmt.Sprintf("dnsrecon successfully retrieved the zone for %s via AXFR. The nameserver leaked the full DNS inventory; restrict AXFR to permitted slaves.", domain),
			Attributes:  map[string]any{"domain": domain},
			SupportingEntities: []fact.EntityRef{{Kind: entity.KindDomain, Value: domain}},
		}); err != nil {
			return err
		}
	}

	return cctx.EmitEvidence(fact.EvidenceFact{
		SourceTool:     Name,
		SourceCategory: finding.SourcePassiveDNS,
		Confidence:     finding.ConfidenceHigh,
		Payload: map[string]any{
			"domain":              domain,
			"records_total":       len(records),
			"subdomains_emitted":  subsEmitted,
			"ips_emitted":         ipsEmitted,
			"axfr_succeeded":      axfrSucceeded,
		},
		EntityKind:  entity.KindDomain,
		EntityValue: domain,
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
	values, err := cctx.ListEntityValues(entity.KindDomain)
	if err != nil {
		return nil, err
	}
	if len(values) == 0 {
		return nil, errors.New("dnsrecon: no domains to query; pass parameters[\"domains\"] or seed DOMAIN entities")
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

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
