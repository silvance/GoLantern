// Package snmpwalk wraps snmpwalk (from net-snmp) for community-
// string-based SNMP enumeration. Probes each target with a small
// set of common community strings ("public", "private") and walks
// the system OID tree (1.3.6.1.2.1.1) when one works.
//
// A working community-string discovery is itself a finding: SNMP
// information disclosure with a default community string is a
// long-standing finding category. We also extract sysDescr,
// sysName, sysContact, and sysLocation from the walk and store
// them as attributes on the corresponding IP entity.
package snmpwalk

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
	Name           = "snmpwalk"
	defaultBinary  = "snmpwalk"
	defaultTimeout = 60 * time.Second
)

var defaultCommunities = []string{"public", "private"}

func New() scan.Collector { return &collector{} }

type runnerFn func(ctx context.Context, spec subprocess.Spec) (subprocess.Result, error)

func newWithRunner(r runnerFn) scan.Collector { return &collector{runner: r} }

type collector struct{ runner runnerFn }

func (collector) Metadata() scan.Meta {
	return scan.Meta{
		Name:               Name,
		Phase:              workflow.PhaseValidation,
		RequiredScope:      scope.KindLightActive,
		Description:        "Probe SNMP targets with common community strings (public, private) and walk the system OID tree on success. A working default community is itself a finding.",
		Consumes:           []entity.Kind{entity.KindIP},
		Produces:           []entity.Kind{entity.KindIP},
		SourceCategory:     finding.SourceLiveProbe,
		TriggersOnServices: []string{"snmp"},
		Binary:             "snmpwalk",
		InstallHint:        "Fedora: sudo dnf install net-snmp-utils\nDebian/Ubuntu: sudo apt install snmp",
		Parameters: []scan.ParameterSpec{
			{Name: "targets", Type: "string_list", Placeholder: "10.0.0.1",
				Description: "Targets to probe. Empty falls back to every IP entity."},
			{Name: "communities", Type: "string_list", Default: []string{"public", "private"},
				Description: "Community strings to try, in order."},
			{Name: "binary", Type: "string", Default: "snmpwalk"},
			{Name: "timeout_seconds", Type: "float", Default: 60.0},
		},
	}
}

// Known sysX OIDs we extract from the walk. snmpwalk text output:
//   SNMPv2-MIB::sysDescr.0 = STRING: Linux foo 5.10.0
//   SNMPv2-MIB::sysName.0 = STRING: foo
var sysOIDs = map[string]string{
	"sysDescr.0":    "sys_descr",
	"sysName.0":     "sys_name",
	"sysContact.0":  "sys_contact",
	"sysLocation.0": "sys_location",
	"sysObjectID.0": "sys_object_id",
	"sysUpTime.0":   "sys_uptime",
}

func parseSysOIDs(stdout string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(stdout, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || !strings.Contains(line, "=") {
			continue
		}
		// Find the key after the last "::" or "." separator before "="
		eq := strings.Index(line, "=")
		left := strings.TrimSpace(line[:eq])
		// Last segment after "::" if present.
		if i := strings.Index(left, "::"); i >= 0 {
			left = left[i+2:]
		}
		for oid, key := range sysOIDs {
			if left == oid {
				val := strings.TrimSpace(line[eq+1:])
				// Strip the "STRING:" / "OID:" / similar type prefix.
				if i := strings.Index(val, ":"); i > 0 && i < 12 {
					val = strings.TrimSpace(val[i+1:])
				}
				val = strings.Trim(val, `"`)
				if val != "" {
					out[key] = val
				}
				break
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
	communities := parseStringList(cctx.Parameters()["communities"])
	if len(communities) == 0 {
		communities = defaultCommunities
	}

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

	run := c.runner
	if run == nil {
		run = subprocess.Run
	}

	hitCount := 0
	for _, target := range inScope {
		var workingCommunity string
		var walkOutput string
		for _, comm := range communities {
			args := []string{"-v2c", "-c", comm, "-t", "5", "-r", "1", target, "1.3.6.1.2.1.1"}
			result, err := run(ctx, subprocess.Spec{
				Binary:         binary,
				Args:           args,
				Timeout:        timeout,
				AllowPartialRC: []int{1},
			})
			if err != nil {
				continue
			}
			s := string(result.Stdout)
			// snmpwalk prints "Timeout: No Response from ..." on
			// failure even with rc=0; treat empty walks as misses.
			if strings.Contains(s, "Timeout:") || strings.Contains(s, "No Response") {
				continue
			}
			if !strings.Contains(s, "SNMPv2-MIB::sys") && !strings.Contains(s, "sysDescr") {
				continue
			}
			workingCommunity = comm
			walkOutput = s
			break
		}

		if workingCommunity == "" {
			_ = cctx.EmitEvidence(fact.EvidenceFact{
				SourceTool:     Name,
				SourceCategory: finding.SourceLiveProbe,
				Confidence:     finding.ConfidenceMedium,
				Payload:        map[string]any{"target": target, "result": "no community string responded"},
				EntityKind:     entity.KindIP,
				EntityValue:    target,
			})
			continue
		}

		sys := parseSysOIDs(walkOutput)
		attrs := map[string]any{
			"discovered_via": Name,
			"snmp_community": workingCommunity,
		}
		for k, v := range sys {
			attrs[k] = v
		}
		if _, err := cctx.EmitEntity(fact.EntityFact{
			Kind:           entity.KindIP,
			Value:          target,
			Attributes:     attrs,
			Confidence:     finding.ConfidenceHigh,
			SourceCategory: finding.SourceLiveProbe,
		}); err != nil {
			return err
		}

		// Default-community-string finding. "public" + responding =
		// information disclosure. "private" is worse (write access in
		// SNMPv1/2 contexts).
		sev := finding.SeverityMedium
		if strings.EqualFold(workingCommunity, "private") {
			sev = finding.SeverityHigh
		}
		if _, err := cctx.EmitFinding(fact.FindingFact{
			Title:       fmt.Sprintf("SNMP default community string %q on %s", workingCommunity, target),
			Severity:    sev,
			Confidence:  finding.ConfidenceHigh,
			Category:    "snmp.default_community",
			Description: fmt.Sprintf("Host %s responds to SNMPv2c queries with community string %q, exposing system information. Restrict SNMP to authorized monitoring hosts and rotate to a random community (or move to SNMPv3 with auth+privacy).", target, workingCommunity),
			Attributes: map[string]any{
				"target":    target,
				"community": workingCommunity,
				"sys_descr": sys["sys_descr"],
				"sys_name":  sys["sys_name"],
			},
			SupportingEntities: []fact.EntityRef{{Kind: entity.KindIP, Value: target}},
		}); err != nil {
			return err
		}
		_ = cctx.EmitEvidence(fact.EvidenceFact{
			SourceTool:     Name,
			SourceCategory: finding.SourceLiveProbe,
			Confidence:     finding.ConfidenceHigh,
			Payload: map[string]any{
				"target":         target,
				"community":      workingCommunity,
				"system_oid_map": sys,
			},
			EntityKind:  entity.KindIP,
			EntityValue: target,
		})
		hitCount++
	}
	return cctx.EmitEvidence(fact.EvidenceFact{
		SourceTool:     Name,
		SourceCategory: finding.SourceLiveProbe,
		Confidence:     finding.ConfidenceHigh,
		Payload: map[string]any{
			"targets_probed":    len(inScope),
			"snmp_responsive":   hitCount,
			"communities_tried": communities,
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
	values, err := cctx.ListEntityValues(entity.KindIP)
	if err != nil {
		return nil, err
	}
	if len(values) == 0 {
		return nil, errors.New("snmpwalk: no targets; pass parameters[\"targets\"] or seed IP entities")
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
