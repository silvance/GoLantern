// Package naabu wraps ProjectDiscovery's naabu port scanner. Modern
// Go-native alternative to the "first half" of an nmap sweep: find
// open TCP ports fast, then hand the live host:port pairs to nmap
// for service+version fingerprinting.
//
// naabu does not do service detection. The collector emits one
// SERVICE entity per (host, port) with service_name="open" so a
// follow-up nmap run on the same project upgrades the row in place
// (same host:port/<svc> key when the operator chooses to merge).
package naabu

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
	Name           = "naabu"
	defaultBinary  = "naabu"
	defaultTimeout = 600 * time.Second
)

func New() scan.Collector { return &collector{} }

type runnerFn func(ctx context.Context, spec subprocess.Spec) (subprocess.Result, error)

func newWithRunner(r runnerFn) scan.Collector { return &collector{runner: r} }

type collector struct{ runner runnerFn }

func (collector) Metadata() scan.Meta {
	return scan.Meta{
		Name:           Name,
		Phase:          workflow.PhaseValidation,
		RequiredScope:  scope.KindLightActive,
		Description:    "Fast TCP port discovery via naabu. Lightweight alternative to nmap for the 'live host:port' sweep; hand results to nmap for service detection.",
		Consumes:       []entity.Kind{entity.KindIP, entity.KindSubdomain, entity.KindDomain},
		Produces:       []entity.Kind{entity.KindService},
		SourceCategory: finding.SourceLiveProbe,
		Binary:         "naabu",
		InstallHint:    "go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
		Parameters: []scan.ParameterSpec{
			{Name: "targets", Type: "string_list", Placeholder: "1.2.3.4, host.example.com",
				Description: "Hosts to scan. Empty falls back to every IP, SUBDOMAIN, and DOMAIN entity in the project."},
			{Name: "ports", Type: "string", Default: "top-100", Placeholder: "top-100",
				Description: "Port spec. 'top-100', 'top-1000', '1-65535', or a comma list like '22,80,443'."},
			{Name: "rate", Type: "int", Default: 1000,
				Description: "Packets per second."},
			{Name: "binary", Type: "string", Default: "naabu"},
			{Name: "timeout_seconds", Type: "float", Default: 600.0,
				Description: "Wall-clock timeout."},
		},
	}
}

type naabuJSON struct {
	Host     string `json:"host"`
	IP       string `json:"ip"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	TLS      bool   `json:"tls"`
}

func (c *collector) Run(ctx context.Context, cctx scan.Context) error {
	binary := strings.TrimSpace(toString(cctx.Parameters()["binary"]))
	if binary == "" {
		binary = defaultBinary
	}
	timeout := parseTimeout(cctx.Parameters()["timeout_seconds"])
	ports := strings.TrimSpace(toString(cctx.Parameters()["ports"]))
	if ports == "" {
		ports = "top-100"
	}
	rate := parsePositiveInt(cctx.Parameters()["rate"], 1000)

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

	args := []string{"-list", "-", "-json", "-silent", "-rate", fmt.Sprintf("%d", rate)}
	switch ports {
	case "top-100":
		args = append(args, "-top-ports", "100")
	case "top-1000":
		args = append(args, "-top-ports", "1000")
	default:
		args = append(args, "-p", ports)
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
		return fmt.Errorf("naabu: %w", err)
	}

	emitted := 0
	for _, raw := range strings.Split(string(result.Stdout), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		var rec naabuJSON
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			continue
		}
		if rec.Port == 0 || (rec.Host == "" && rec.IP == "") {
			continue
		}
		host := rec.Host
		if host == "" {
			host = rec.IP
		}
		// Defense in depth: naabu output should already be scoped to
		// what we fed it, but recheck so a misconfigured run can't
		// emit findings against out-of-scope hosts.
		if !cctx.IsInScope(host) {
			continue
		}
		proto := strings.ToLower(rec.Protocol)
		if proto == "" {
			proto = "tcp"
		}
		svcName := "open"
		if rec.TLS {
			svcName = "tls"
		}
		value := fmt.Sprintf("%s:%d/%s", host, rec.Port, svcName)
		attrs := map[string]any{
			"target":         host,
			"ip":             rec.IP,
			"port":           rec.Port,
			"protocol":       proto,
			"tls":            rec.TLS,
			"discovered_via": Name,
		}
		if _, err := cctx.EmitEntity(fact.EntityFact{
			Kind:           entity.KindService,
			Value:          value,
			Attributes:     attrs,
			Confidence:     finding.ConfidenceMedium,
			SourceCategory: finding.SourceLiveProbe,
		}); err != nil {
			return err
		}
		if err := cctx.EmitEvidence(fact.EvidenceFact{
			SourceTool:     Name,
			SourceCategory: finding.SourceLiveProbe,
			Confidence:     finding.ConfidenceMedium,
			Payload:        attrs,
			EntityKind:     entity.KindService,
			EntityValue:    value,
		}); err != nil {
			return err
		}
		emitted++
	}
	return cctx.EmitEvidence(fact.EvidenceFact{
		SourceTool:     Name,
		SourceCategory: finding.SourceLiveProbe,
		Confidence:     finding.ConfidenceHigh,
		Payload: map[string]any{
			"targets_scanned": len(inScope),
			"open_ports":      emitted,
			"ports_spec":      ports,
			"rate":            rate,
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
	for _, kind := range []entity.Kind{entity.KindIP, entity.KindSubdomain, entity.KindDomain} {
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
		return nil, errors.New("naabu: no targets to scan; pass parameters[\"targets\"] or seed IP/SUBDOMAIN/DOMAIN entities")
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
