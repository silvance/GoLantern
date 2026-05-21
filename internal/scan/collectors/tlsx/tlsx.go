// Package tlsx wraps ProjectDiscovery's tlsx for fast TLS cert
// enumeration. Pulls the Subject CN and Subject Alternative Names
// from each host's certificate; those SAN entries routinely list
// sibling subdomains (e.g. a wildcard cert for *.api.example.com
// reveals the api.example.com tree).
//
// Complements crt.sh: tlsx hits the host directly and sees what's
// served *right now*, whereas crt.sh sees the historical CT log.
// Together they cover both planes.
package tlsx

import (
	"context"
	"encoding/json"
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
	Name           = "tlsx"
	defaultBinary  = "tlsx"
	defaultTimeout = 300 * time.Second
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
		Description:    "Pull Subject CN + SAN entries from each host's TLS certificate. SAN lists routinely surface sibling subdomains a passive DNS scan misses.",
		Consumes:       []entity.Kind{entity.KindSubdomain, entity.KindDomain, entity.KindIP},
		Produces:       []entity.Kind{entity.KindSubdomain},
		SourceCategory: finding.SourceCertTransparency,
		Binary:         "tlsx",
		InstallHint:    "go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest",
		Parameters: []scan.ParameterSpec{
			{Name: "targets", Type: "string_list", Placeholder: "example.com, 1.2.3.4",
				Description: "Hosts to probe. Empty falls back to every SUBDOMAIN/DOMAIN/IP entity."},
			{Name: "port", Type: "int", Default: 443,
				Description: "TLS port to probe."},
			{Name: "binary", Type: "string", Default: "tlsx"},
			{Name: "timeout_seconds", Type: "float", Default: 300.0},
		},
	}
}

type tlsxJSON struct {
	Host      string   `json:"host"`
	IP        string   `json:"ip"`
	Port      string   `json:"port"`
	SubjectCN string   `json:"subject_cn"`
	SubjectAN []string `json:"subject_an"`
	IssuerDN  string   `json:"issuer_dn"`
	NotBefore string   `json:"not_before"`
	NotAfter  string   `json:"not_after"`
	Wildcard  bool     `json:"wildcard_certificate"`
}

func (c *collector) Run(ctx context.Context, cctx scan.Context) error {
	binary := strings.TrimSpace(toString(cctx.Parameters()["binary"]))
	if binary == "" {
		binary = defaultBinary
	}
	timeout := parseTimeout(cctx.Parameters()["timeout_seconds"])
	port := parsePositiveInt(cctx.Parameters()["port"], 443)

	targets, err := c.resolveTargets(cctx)
	if err != nil {
		return err
	}
	var inScope []string
	for _, t := range targets {
		if cctx.IsInScope(t) {
			inScope = append(inScope, t)
		}
	}
	if len(inScope) == 0 {
		return nil
	}

	args := []string{
		"-l", "-",
		"-json",
		"-silent",
		"-no-color",
		"-san",
		"-cn",
		"-p", fmt.Sprintf("%d", port),
	}
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
		return fmt.Errorf("tlsx: %w", err)
	}

	seen := map[string]struct{}{}
	newSubs := 0
	hostsProbed := 0
	for _, raw := range strings.Split(string(result.Stdout), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		var rec tlsxJSON
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			continue
		}
		hostsProbed++
		names := append([]string{}, rec.SubjectAN...)
		if rec.SubjectCN != "" {
			names = append(names, rec.SubjectCN)
		}
		for _, name := range names {
			n := strings.ToLower(strings.TrimSpace(name))
			if n == "" {
				continue
			}
			// Skip wildcard markers — they're not host entities. The
			// wildcard fact lands in evidence.
			if strings.HasPrefix(n, "*.") {
				continue
			}
			// Skip obvious non-DNS names (e.g. CA-issued internal labels).
			if !strings.Contains(n, ".") {
				continue
			}
			if _, dup := seen[n]; dup {
				continue
			}
			seen[n] = struct{}{}
			if !cctx.IsInScope(n) {
				continue
			}
			if _, err := cctx.EmitEntity(fact.EntityFact{
				Kind:           entity.KindSubdomain,
				Value:          n,
				Attributes:     map[string]any{"discovered_via": Name, "source_host": rec.Host, "issuer_dn": rec.IssuerDN},
				Confidence:     finding.ConfidenceHigh,
				SourceCategory: finding.SourceCertTransparency,
			}); err != nil {
				return err
			}
			newSubs++
		}
		if err := cctx.EmitEvidence(fact.EvidenceFact{
			SourceTool:     Name,
			SourceCategory: finding.SourceCertTransparency,
			Confidence:     finding.ConfidenceHigh,
			Payload: map[string]any{
				"host":       rec.Host,
				"ip":         rec.IP,
				"port":       rec.Port,
				"subject_cn": rec.SubjectCN,
				"subject_an": rec.SubjectAN,
				"issuer_dn":  rec.IssuerDN,
				"not_before": rec.NotBefore,
				"not_after":  rec.NotAfter,
				"wildcard":   rec.Wildcard,
			},
			EntityKind:  entity.KindSubdomain,
			EntityValue: rec.Host,
		}); err != nil {
			return err
		}
	}
	return cctx.EmitEvidence(fact.EvidenceFact{
		SourceTool:     Name,
		SourceCategory: finding.SourceCertTransparency,
		Confidence:     finding.ConfidenceHigh,
		Payload: map[string]any{
			"hosts_probed":   hostsProbed,
			"new_subdomains": newSubs,
			"port":           port,
		},
	})
}

func (c *collector) resolveTargets(cctx scan.Context) ([]string, error) {
	explicit := parseStringList(cctx.Parameters()["targets"])
	if len(explicit) > 0 {
		out := make([]string, 0, len(explicit))
		for _, t := range explicit {
			if t = strings.TrimSpace(t); t != "" {
				out = append(out, t)
			}
		}
		if len(out) > 0 {
			return out, nil
		}
	}
	var out []string
	for _, kind := range []entity.Kind{entity.KindSubdomain, entity.KindDomain, entity.KindIP} {
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
		return nil, errors.New("tlsx: no targets to probe; pass parameters[\"targets\"] or seed SUBDOMAIN/DOMAIN/IP entities")
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
