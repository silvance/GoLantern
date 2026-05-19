// Package smbmap wraps smbmap for SMB share + permission enumeration.
// Anonymous by default; supply username/password for authenticated
// probes.
//
// Ported from lantern/tools/smbmap.py.
//
// We deliberately port smbmap as the canonical SMB-enum wrapper and
// skip enum4linux_ng / netexec / kerbrute — they overlap heavily with
// smbmap's surface; operators who need them can pass extra_args.
package smbmap

import (
	"context"
	"errors"
	"fmt"
	"regexp"
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
	Name           = "smbmap"
	defaultBinary  = "smbmap"
	defaultTimeout = 300 * time.Second
)

var (
	hostRE = regexp.MustCompile(
		`^\[\+\]\s+(?:Guest\s+session\s+)?IP:\s*(\S+):(\d+)\s+Name:\s*(\S+)`,
	)
	shareRE = regexp.MustCompile(
		`^\s+(\S+)\s+(NO ACCESS|READ ONLY|READ,? ?WRITE|WRITE|READ)\s*(.*)$`,
	)
	systemShares = map[string]struct{}{
		"ADMIN$": {}, "C$": {}, "IPC$": {}, "PRINT$": {}, "FAX$": {},
	}
)

func New() scan.Collector { return &collector{} }

type runnerFn func(ctx context.Context, spec subprocess.Spec) (subprocess.Result, error)

func newWithRunner(r runnerFn) scan.Collector { return &collector{runner: r} }

type collector struct{ runner runnerFn }

func (collector) Metadata() scan.Meta {
	return scan.Meta{
		Name:               Name,
		Phase:              workflow.PhaseValidation,
		RequiredScope:      scope.KindLightActive,
		Description:        "SMB share + permission enumeration; emit findings for non-system shares with READ/WRITE.",
		Consumes:           []entity.Kind{entity.KindIP},
		Produces:           []entity.Kind{entity.KindService},
		SourceCategory:     finding.SourceLiveProbe,
		TriggersOnServices: []string{"smb"},
		Binary:             "smbmap",
		InstallHint:        "pipx install smbmap (or apt install smbmap on Kali)",
		Parameters: []scan.ParameterSpec{
			{Name: "targets", Type: "string_list", Placeholder: "10.0.0.5, 10.0.0.6",
				Description: "Hosts to probe. Empty falls back to every IP entity."},
			{Name: "username", Type: "string"},
			{Name: "password", Type: "string"},
			{Name: "domain", Type: "string"},
			{Name: "binary", Type: "string", Default: "smbmap"},
			{Name: "timeout_seconds", Type: "float", Default: 300.0},
		},
	}
}

type hostRecord struct {
	Host   string
	Port   int
	Name   string
	Shares []shareRecord
}

type shareRecord struct {
	Share, Perm, Comment string
}

func parseOutput(blob string) []hostRecord {
	var out []hostRecord
	var current *hostRecord
	for _, raw := range strings.Split(blob, "\n") {
		if m := hostRE.FindStringSubmatch(strings.TrimSpace(raw)); m != nil {
			if current != nil {
				out = append(out, *current)
			}
			port := 0
			fmt.Sscanf(m[2], "%d", &port)
			current = &hostRecord{Host: m[1], Port: port, Name: m[3]}
			continue
		}
		if current == nil {
			continue
		}
		if m := shareRE.FindStringSubmatch(raw); m != nil {
			current.Shares = append(current.Shares, shareRecord{
				Share:   m[1],
				Perm:    strings.ToUpper(m[2]),
				Comment: strings.TrimSpace(m[3]),
			})
		}
	}
	if current != nil {
		out = append(out, *current)
	}
	return out
}

func (c *collector) Run(ctx context.Context, cctx scan.Context) error {
	binary := strings.TrimSpace(toString(cctx.Parameters()["binary"]))
	if binary == "" {
		binary = defaultBinary
	}
	timeout := parseTimeout(cctx.Parameters()["timeout_seconds"])
	username := strings.TrimSpace(toString(cctx.Parameters()["username"]))
	password := strings.TrimSpace(toString(cctx.Parameters()["password"]))
	domain := strings.TrimSpace(toString(cctx.Parameters()["domain"]))

	targets, err := c.resolveTargets(cctx)
	if err != nil {
		return err
	}
	var allowed []string
	for _, t := range targets {
		if cctx.IsInScope(t) {
			allowed = append(allowed, t)
		}
	}
	if len(allowed) == 0 {
		return nil
	}

	run := c.runner
	if run == nil {
		run = subprocess.Run
	}

	authenticated := username != ""
	for _, host := range allowed {
		args := []string{"-H", host}
		if username != "" {
			args = append(args, "-u", username)
		}
		if password != "" {
			args = append(args, "-p", password)
		}
		if domain != "" {
			args = append(args, "-d", domain)
		}
		result, err := run(ctx, subprocess.Spec{
			Binary:         binary,
			Args:           args,
			Timeout:        timeout,
			AllowPartialRC: []int{1, 2},
		})
		if err != nil {
			_ = cctx.EmitEvidence(fact.EvidenceFact{
				SourceTool:     Name,
				SourceCategory: finding.SourceLiveProbe,
				Confidence:     finding.ConfidenceLow,
				Payload:        map[string]any{"host": host, "error": err.Error()},
			})
			continue
		}
		for _, h := range parseOutput(string(result.Stdout)) {
			serviceValue := fmt.Sprintf("%s:%d/smb", h.Host, h.Port)
			if _, err := cctx.EmitEntity(fact.EntityFact{
				Kind:           entity.KindService,
				Value:          serviceValue,
				Confidence:     finding.ConfidenceHigh,
				SourceCategory: finding.SourceLiveProbe,
				Attributes: map[string]any{
					"ip":           h.Host,
					"port":         h.Port,
					"transport":    "tcp",
					"service_name": "smb",
					"server_name":  h.Name,
				},
			}); err != nil {
				return err
			}
			for _, s := range h.Shares {
				if _, sys := systemShares[s.Share]; sys && !authenticated {
					// Default Windows admin shares; reading them from
					// an anonymous session is uninteresting noise.
					continue
				}
				isWritable := strings.Contains(s.Perm, "WRITE")
				if !strings.Contains(s.Perm, "READ") && !isWritable {
					continue
				}
				sev := finding.SeverityMedium
				access := "READ"
				if isWritable {
					sev = finding.SeverityHigh
					access = "WRITE"
				}
				principal := "Anonymous"
				if authenticated {
					principal = username
				}
				if _, err := cctx.EmitFinding(fact.FindingFact{
					Title: fmt.Sprintf("%s %s access to SMB share %s on %s",
						principal, access, s.Share, h.Host),
					Severity:   sev,
					Confidence: finding.ConfidenceHigh,
					Category:   "smb_share_exposure",
					Description: fmt.Sprintf("smbmap reported %s permission %q on share %s of %s.",
						principal, s.Perm, s.Share, h.Host),
					Attributes: map[string]any{
						"host":          h.Host,
						"share":         s.Share,
						"perm":          s.Perm,
						"authenticated": authenticated,
						"comment":       s.Comment,
					},
					SupportingEntities: []fact.EntityRef{
						{Kind: entity.KindIP, Value: h.Host},
					},
				}); err != nil {
					return err
				}
			}
		}
	}
	return nil
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
	ips, err := cctx.ListEntityValues(entity.KindIP)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, ip := range ips {
		if ip = strings.TrimSpace(ip); ip != "" {
			out = append(out, ip)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("smbmap: no targets; pass parameters[\"targets\"] or seed IP entities")
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

func toString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}
