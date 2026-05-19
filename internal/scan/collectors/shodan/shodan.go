// Package shodan enriches known IPs with Shodan host records: open
// ports, banners, ASN/org metadata, technology fingerprints. Passive:
// traffic only goes to api.shodan.io, never the target.
//
// Requires a Shodan API key — passed via parameters["api_key"] or the
// SHODAN_API_KEY environment variable. Free Shodan accounts work for
// the /shodan/host endpoint we use.
//
// Ported from lantern/tools/shodan.py (compressed shape; we keep the
// IP entity enrichment + SERVICE + TECHNOLOGY + summary evidence and
// drop the per-port banner fingerprinting helpers since they're
// straight projections of the same JSON).
package shodan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
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
	Name           = "shodan"
	defaultBaseURL = "https://api.shodan.io"
	defaultTimeout = 30 * time.Second
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
		Description:    "Enrich known IPs with Shodan host data (ports, banners, ASN, tech).",
		Consumes:       []entity.Kind{entity.KindIP},
		Produces:       []entity.Kind{entity.KindService, entity.KindTechnology},
		SourceCategory: finding.SourcePublicOSINT,
		Parameters: []scan.ParameterSpec{
			{Name: "ips", Type: "string_list",
				Description: "Explicit IPs to enrich. Empty falls back to every IP entity in the project."},
			{Name: "api_key", Type: "string",
				Description: "Shodan API key. Falls back to $SHODAN_API_KEY."},
			{Name: "timeout_seconds", Type: "float", Default: 30.0},
		},
	}
}

type shodanHost struct {
	Org         string   `json:"org"`
	ASN         string   `json:"asn"`
	ISP         string   `json:"isp"`
	CountryCode string   `json:"country_code"`
	Hostnames   []string `json:"hostnames"`
	Data        []struct {
		Port      int    `json:"port"`
		Transport string `json:"transport"`
		Product   string `json:"product"`
		Version   string `json:"version"`
		Banner    string `json:"data"`
		SSL       struct {
			Cert struct {
				Subject struct {
					CN string `json:"CN"`
				} `json:"subject"`
			} `json:"cert"`
		} `json:"ssl"`
	} `json:"data"`
	Vulns      json.RawMessage `json:"vulns"`
	LastUpdate string          `json:"last_update"`
}

func (c *collector) Run(ctx context.Context, cctx scan.Context) error {
	key, _ := cctx.Parameters()["api_key"].(string)
	key = strings.TrimSpace(key)
	if key == "" {
		key = os.Getenv("SHODAN_API_KEY")
	}
	if key == "" {
		return errors.New("shodan: api_key required (parameter or $SHODAN_API_KEY)")
	}
	timeout := parseTimeout(cctx.Parameters()["timeout_seconds"])

	ips, err := c.resolveIPs(cctx)
	if err != nil {
		return err
	}
	var allowed []string
	for _, ip := range ips {
		if cctx.IsInScope(ip) {
			allowed = append(allowed, ip)
		}
	}
	if len(allowed) == 0 {
		return nil
	}

	withData, noData := 0, 0
	servicesEmitted := 0
	techsSeen := map[string]struct{}{}

	for _, ip := range allowed {
		host, status, err := c.fetchHost(ctx, ip, key, timeout)
		if err != nil {
			return fmt.Errorf("shodan: %w", err)
		}
		if status == http.StatusNotFound {
			noData++
			_ = cctx.EmitEvidence(fact.EvidenceFact{
				SourceTool:     Name,
				SourceCategory: finding.SourcePublicOSINT,
				Confidence:     finding.ConfidenceHigh,
				Payload:        map[string]any{"shodan_host": false},
				EntityKind:     entity.KindIP,
				EntityValue:    ip,
				Notes:          "No Shodan host record for this IP.",
			})
			continue
		}
		if status != http.StatusOK {
			return fmt.Errorf("shodan: HTTP %d for %s", status, ip)
		}
		withData++

		// Enrich IP attributes.
		if _, err := cctx.EmitEntity(fact.EntityFact{
			Kind:           entity.KindIP,
			Value:          ip,
			Confidence:     finding.ConfidenceHigh,
			SourceCategory: finding.SourcePublicOSINT,
			Attributes: map[string]any{
				"shodan_org":       host.Org,
				"shodan_asn":       host.ASN,
				"shodan_isp":       host.ISP,
				"shodan_country":   host.CountryCode,
				"shodan_hostnames": host.Hostnames,
			},
		}); err != nil {
			return err
		}
		// Per-service emission.
		for _, svc := range host.Data {
			if svc.Port == 0 {
				continue
			}
			transport := svc.Transport
			if transport == "" {
				transport = "tcp"
			}
			value := fmt.Sprintf("%s:%d/%s", ip, svc.Port, transport)
			bannerHead := svc.Banner
			if len(bannerHead) > 256 {
				bannerHead = bannerHead[:256]
			}
			if _, err := cctx.EmitEntity(fact.EntityFact{
				Kind:           entity.KindService,
				Value:          value,
				Confidence:     finding.ConfidenceHigh,
				SourceCategory: finding.SourcePublicOSINT,
				Attributes: map[string]any{
					"ip":             ip,
					"port":           svc.Port,
					"transport":      transport,
					"product":        svc.Product,
					"version":        svc.Version,
					"banner_head":    bannerHead,
					"ssl_subject_cn": svc.SSL.Cert.Subject.CN,
				},
			}); err != nil {
				return err
			}
			if err := cctx.EmitRelation(fact.RelationFact{
				Src:  fact.EntityRef{Kind: entity.KindIP, Value: ip},
				Dst:  fact.EntityRef{Kind: entity.KindService, Value: value},
				Kind: entity.RelHosts,
			}); err != nil {
				return err
			}
			if svc.Product != "" {
				techsSeen[svc.Product] = struct{}{}
				if _, err := cctx.EmitEntity(fact.EntityFact{
					Kind:           entity.KindTechnology,
					Value:          svc.Product,
					Confidence:     finding.ConfidenceMedium,
					SourceCategory: finding.SourcePublicOSINT,
				}); err != nil {
					return err
				}
				if err := cctx.EmitRelation(fact.RelationFact{
					Src:  fact.EntityRef{Kind: entity.KindService, Value: value},
					Dst:  fact.EntityRef{Kind: entity.KindTechnology, Value: svc.Product},
					Kind: entity.RelUsesTech,
				}); err != nil {
					return err
				}
			}
			servicesEmitted++
		}
	}

	techs := make([]string, 0, len(techsSeen))
	for t := range techsSeen {
		techs = append(techs, t)
	}
	sort.Strings(techs)

	return cctx.EmitEvidence(fact.EvidenceFact{
		SourceTool:     Name,
		SourceCategory: finding.SourcePublicOSINT,
		Confidence:     finding.ConfidenceHigh,
		Payload: map[string]any{
			"ips_checked":       len(allowed),
			"ips_with_data":     withData,
			"ips_no_data":       noData,
			"services_emitted":  servicesEmitted,
			"technologies_seen": techs,
		},
	})
}

func (c *collector) fetchHost(ctx context.Context, ip, key string, timeout time.Duration) (*shodanHost, int, error) {
	qctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	url := fmt.Sprintf("%s/shodan/host/%s?key=%s", c.baseURL, ip, key)
	req, err := http.NewRequestWithContext(qctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, 0, err
	}
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
		return nil, resp.StatusCode, nil
	}
	var host shodanHost
	if err := json.NewDecoder(resp.Body).Decode(&host); err != nil {
		return nil, resp.StatusCode, fmt.Errorf("decode: %w", err)
	}
	return &host, http.StatusOK, nil
}

func (c *collector) resolveIPs(cctx scan.Context) ([]string, error) {
	explicit := parseStringList(cctx.Parameters()["ips"])
	if len(explicit) > 0 {
		out := make([]string, 0, len(explicit))
		for _, ip := range explicit {
			if ip = strings.TrimSpace(ip); ip != "" {
				out = append(out, ip)
			}
		}
		if len(out) > 0 {
			return out, nil
		}
	}
	values, err := cctx.ListEntityValues(entity.KindIP)
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
		return nil, errors.New("shodan: no IPs to enrich; pass parameters[\"ips\"] or seed IP entities")
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
