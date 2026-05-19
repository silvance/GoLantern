// Package censys enriches known IPs with Censys host records: open
// services, software fingerprints, ASN/geo metadata. Sibling to the
// shodan collector with a different upstream API shape.
//
// Requires Censys API ID + secret — pass via api_id/api_secret
// parameters or $CENSYS_API_ID / $CENSYS_API_SECRET. Basic-auth.
//
// Ported from lantern/tools/censys.py (compressed shape).
package censys

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
	Name           = "censys"
	defaultBaseURL = "https://search.censys.io"
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
		Description:    "Enrich known IPs with Censys host data (services, software, ASN).",
		Consumes:       []entity.Kind{entity.KindIP},
		Produces:       []entity.Kind{entity.KindService, entity.KindTechnology},
		SourceCategory: finding.SourcePublicOSINT,
		Parameters: []scan.ParameterSpec{
			{Name: "ips", Type: "string_list"},
			{Name: "api_id", Type: "string", Description: "Falls back to $CENSYS_API_ID."},
			{Name: "api_secret", Type: "string", Description: "Falls back to $CENSYS_API_SECRET."},
			{Name: "timeout_seconds", Type: "float", Default: 30.0},
		},
	}
}

type censysHost struct {
	Result struct {
		Location struct {
			Country string `json:"country"`
		} `json:"location"`
		AS struct {
			ASN  int    `json:"asn"`
			Name string `json:"name"`
		} `json:"autonomous_system"`
		DNS struct {
			Names []string `json:"names"`
		} `json:"dns"`
		Services []struct {
			Port              int      `json:"port"`
			TransportProtocol string   `json:"transport_protocol"`
			ServiceName       string   `json:"service_name"`
			Banner            string   `json:"banner"`
			Software          []struct {
				Vendor  string `json:"vendor"`
				Product string `json:"product"`
				Version string `json:"version"`
			} `json:"software"`
		} `json:"services"`
	} `json:"result"`
}

func (c *collector) Run(ctx context.Context, cctx scan.Context) error {
	id, _ := cctx.Parameters()["api_id"].(string)
	secret, _ := cctx.Parameters()["api_secret"].(string)
	if id == "" {
		id = os.Getenv("CENSYS_API_ID")
	}
	if secret == "" {
		secret = os.Getenv("CENSYS_API_SECRET")
	}
	if id == "" || secret == "" {
		return errors.New("censys: api_id + api_secret required (parameters or $CENSYS_API_ID/$CENSYS_API_SECRET)")
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

	withData, noData, servicesEmitted := 0, 0, 0
	techsSeen := map[string]struct{}{}
	for _, ip := range allowed {
		host, status, err := c.fetchHost(ctx, ip, id, secret, timeout)
		if err != nil {
			return fmt.Errorf("censys: %w", err)
		}
		if status == http.StatusNotFound || host == nil {
			noData++
			_ = cctx.EmitEvidence(fact.EvidenceFact{
				SourceTool:     Name,
				SourceCategory: finding.SourcePublicOSINT,
				Confidence:     finding.ConfidenceHigh,
				Payload:        map[string]any{"censys_host": false},
				EntityKind:     entity.KindIP,
				EntityValue:    ip,
				Notes:          "No Censys host record for this IP.",
			})
			continue
		}
		withData++
		if _, err := cctx.EmitEntity(fact.EntityFact{
			Kind:           entity.KindIP,
			Value:          ip,
			Confidence:     finding.ConfidenceHigh,
			SourceCategory: finding.SourcePublicOSINT,
			Attributes: map[string]any{
				"censys_country":   host.Result.Location.Country,
				"censys_asn":       host.Result.AS.ASN,
				"censys_as_name":   host.Result.AS.Name,
				"censys_dns_names": host.Result.DNS.Names,
			},
		}); err != nil {
			return err
		}
		for _, svc := range host.Result.Services {
			if svc.Port == 0 {
				continue
			}
			transport := strings.ToLower(svc.TransportProtocol)
			if transport == "" {
				transport = "tcp"
			}
			value := fmt.Sprintf("%s:%d/%s", ip, svc.Port, transport)
			var softwareList []string
			for _, s := range svc.Software {
				name := strings.TrimSpace(s.Product)
				if name == "" {
					name = strings.TrimSpace(s.Vendor)
				}
				if name != "" {
					softwareList = append(softwareList, name)
					techsSeen[name] = struct{}{}
				}
			}
			banner := svc.Banner
			if len(banner) > 256 {
				banner = banner[:256]
			}
			if _, err := cctx.EmitEntity(fact.EntityFact{
				Kind:           entity.KindService,
				Value:          value,
				Confidence:     finding.ConfidenceHigh,
				SourceCategory: finding.SourcePublicOSINT,
				Attributes: map[string]any{
					"ip":           ip,
					"port":         svc.Port,
					"transport":    transport,
					"service_name": strings.ToLower(svc.ServiceName),
					"software":     softwareList,
					"banner_head":  banner,
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
			for _, name := range softwareList {
				if _, err := cctx.EmitEntity(fact.EntityFact{
					Kind:           entity.KindTechnology,
					Value:          name,
					Confidence:     finding.ConfidenceMedium,
					SourceCategory: finding.SourcePublicOSINT,
				}); err != nil {
					return err
				}
				if err := cctx.EmitRelation(fact.RelationFact{
					Src:  fact.EntityRef{Kind: entity.KindService, Value: value},
					Dst:  fact.EntityRef{Kind: entity.KindTechnology, Value: name},
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

func (c *collector) fetchHost(ctx context.Context, ip, id, secret string, timeout time.Duration) (*censysHost, int, error) {
	qctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	url := c.baseURL + "/api/v2/hosts/" + ip
	req, err := http.NewRequestWithContext(qctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, 0, err
	}
	req.SetBasicAuth(id, secret)
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
	var host censysHost
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
		return nil, errors.New("censys: no IPs to enrich; pass parameters[\"ips\"] or seed IP entities")
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
