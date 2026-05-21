// Package netexec wraps NetExec (formerly crackmapexec) for SMB
// authentication + share enumeration. Default mode is null-session
// probing: a fast no-creds sweep that catches the most common
// CTF/internal-engagement finding (anonymous SMB exposing share
// lists, exposing the local users list, weak signing).
//
// Authenticated mode kicks in when credentials are passed via
// parameters; the collector then enumerates shares and flags
// "(Pwn3d!)" responses as admin-access findings.
//
// The wrapper deliberately does NOT do password-spraying — that's
// a different use case with engagement-rules-of-engagement
// implications and belongs in a separate tool.
package netexec

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
	Name           = "netexec"
	defaultBinary  = "netexec"
	defaultTimeout = 300 * time.Second
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
		Description:        "SMB authentication + share enumeration via NetExec. Null-session sweep by default; flags anonymous share lists, weak signing, and admin access (Pwn3d!) on authenticated runs.",
		Consumes:           []entity.Kind{entity.KindIP, entity.KindSubdomain},
		Produces:           []entity.Kind{entity.KindIP},
		SourceCategory:     finding.SourceActiveScan,
		TriggersOnServices: []string{"smb", "microsoft-ds", "netbios-ssn"},
		Binary:             "netexec",
		InstallHint:        "pipx install netexec",
		Parameters: []scan.ParameterSpec{
			{Name: "targets", Type: "string_list", Placeholder: "10.0.0.1",
				Description: "SMB targets. Empty falls back to every IP + SUBDOMAIN entity."},
			{Name: "username", Type: "string", Default: "",
				Description: "Optional username. Empty = null session probe (anonymous)."},
			{Name: "password", Type: "string", Default: "",
				Description: "Optional password (or NT hash via --hash semantics — pass directly)."},
			{Name: "domain", Type: "string", Default: "",
				Description: "Optional Windows domain for authenticated runs."},
			{Name: "enumerate_shares", Type: "bool", Default: true,
				Description: "Pass --shares to list available shares with READ/WRITE markers."},
			{Name: "enumerate_users", Type: "bool", Default: false,
				Description: "Pass --users to RPC-list local users (works on many old Windows / Samba)."},
			{Name: "binary", Type: "string", Default: "netexec"},
			{Name: "timeout_seconds", Type: "float", Default: 300.0},
		},
	}
}

// NetExec's SMB output rows follow the format:
//   SMB    10.0.0.1  445  HOSTNAME  [marker] message
// where marker is one of [*] [+] [-] (info / success / fail).
// We parse those columns plus the trailing message for the facts we
// care about: signing state, OS name, admin access flag.
var rowRE = regexp.MustCompile(`^SMB\s+(\S+)\s+\d+\s+(\S+)\s+\[([+\-*])\]\s+(.*)$`)

type smbRow struct {
	IP       string
	Hostname string
	Marker   string // +, -, *
	Body     string
}

func parseRows(stdout string) []smbRow {
	var out []smbRow
	for _, raw := range strings.Split(stdout, "\n") {
		line := strings.TrimSpace(stripANSI(raw))
		if line == "" {
			continue
		}
		m := rowRE.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		out = append(out, smbRow{IP: m[1], Hostname: m[2], Marker: m[3], Body: m[4]})
	}
	return out
}

// stripANSI removes ANSI color escape sequences. NetExec colors
// output by default; we don't pass --no-colour because some builds
// don't honour it.
var ansiRE = regexp.MustCompile(`\x1b\[[0-9;]*m`)

func stripANSI(s string) string { return ansiRE.ReplaceAllString(s, "") }

func (c *collector) Run(ctx context.Context, cctx scan.Context) error {
	binary := strings.TrimSpace(toString(cctx.Parameters()["binary"]))
	if binary == "" {
		binary = defaultBinary
	}
	timeout := parseTimeout(cctx.Parameters()["timeout_seconds"])
	username := strings.TrimSpace(toString(cctx.Parameters()["username"]))
	password := toString(cctx.Parameters()["password"]) // don't TrimSpace — passwords may have leading/trailing spaces intentionally
	domain := strings.TrimSpace(toString(cctx.Parameters()["domain"]))
	enumerateShares := parseBool(cctx.Parameters()["enumerate_shares"], true)
	enumerateUsers := parseBool(cctx.Parameters()["enumerate_users"], false)

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

	args := []string{"smb"}
	args = append(args, inScope...)
	if username == "" {
		// Null session probe.
		args = append(args, "-u", "", "-p", "")
	} else {
		args = append(args, "-u", username, "-p", password)
		if domain != "" {
			args = append(args, "-d", domain)
		}
	}
	if enumerateShares {
		args = append(args, "--shares")
	}
	if enumerateUsers {
		args = append(args, "--users")
	}

	run := c.runner
	if run == nil {
		run = subprocess.Run
	}
	result, err := run(ctx, subprocess.Spec{
		Binary:         binary,
		Args:           args,
		Timeout:        timeout,
		AllowPartialRC: []int{1, 2, 3, 255},
	})
	if err != nil {
		return fmt.Errorf("netexec: %w", err)
	}

	rows := parseRows(string(result.Stdout))
	hostFacts := map[string]*hostState{}
	for _, r := range rows {
		hs, ok := hostFacts[r.IP]
		if !ok {
			hs = &hostState{ip: r.IP, hostname: r.Hostname}
			hostFacts[r.IP] = hs
		}
		hs.update(r)
	}

	authMode := "null_session"
	if username != "" {
		authMode = "authenticated"
	}

	findingsEmitted := 0
	for _, hs := range hostFacts {
		if !cctx.IsInScope(hs.ip) {
			continue
		}
		// Update the IP entity with the SMB banner attributes.
		attrs := map[string]any{
			"discovered_via": Name,
			"smb_hostname":   hs.hostname,
		}
		if hs.os != "" {
			attrs["smb_os"] = hs.os
		}
		if hs.signing != "" {
			attrs["smb_signing"] = hs.signing
		}
		if hs.smbv1 {
			attrs["smb_v1"] = true
		}
		if _, err := cctx.EmitEntity(fact.EntityFact{
			Kind:           entity.KindIP,
			Value:          hs.ip,
			Attributes:     attrs,
			Confidence:     finding.ConfidenceHigh,
			SourceCategory: finding.SourceActiveScan,
		}); err != nil {
			return err
		}

		// Findings.
		if hs.pwn3d {
			if _, err := cctx.EmitFinding(fact.FindingFact{
				Title:       fmt.Sprintf("SMB admin access on %s as %s", hs.ip, username),
				Severity:    finding.SeverityCritical,
				Confidence:  finding.ConfidenceHigh,
				Category:    "smb.admin_access",
				Description: fmt.Sprintf("NetExec reports admin (Pwn3d!) on %s with the supplied credentials. The account can read LSASS, schedule tasks, and access ADMIN$.", hs.ip),
				Attributes:  map[string]any{"target": hs.ip, "user": username, "domain": domain},
				SupportingEntities: []fact.EntityRef{{Kind: entity.KindIP, Value: hs.ip}},
			}); err != nil {
				return err
			}
			findingsEmitted++
		}
		if hs.nullSessionOK {
			if _, err := cctx.EmitFinding(fact.FindingFact{
				Title:       fmt.Sprintf("SMB null session accepted on %s", hs.ip),
				Severity:    finding.SeverityMedium,
				Confidence:  finding.ConfidenceHigh,
				Category:    "smb.null_session",
				Description: fmt.Sprintf("Host %s accepts anonymous (null-session) SMB authentication. Restrict via 'RestrictAnonymous'/'RestrictNullSessAccess' or upgrade beyond SMBv1.", hs.ip),
				Attributes: map[string]any{
					"target":   hs.ip,
					"hostname": hs.hostname,
					"shares":   hs.shares,
					"users":    hs.users,
				},
				SupportingEntities: []fact.EntityRef{{Kind: entity.KindIP, Value: hs.ip}},
			}); err != nil {
				return err
			}
			findingsEmitted++
		}
		if hs.signing == "False" || hs.signing == "disabled" {
			if _, err := cctx.EmitFinding(fact.FindingFact{
				Title:       fmt.Sprintf("SMB signing disabled on %s", hs.ip),
				Severity:    finding.SeverityMedium,
				Confidence:  finding.ConfidenceHigh,
				Category:    "smb.signing_disabled",
				Description: fmt.Sprintf("SMB signing is not enforced on %s. NTLMv2 relay attacks (impacket-ntlmrelayx) succeed against unsigned SMB.", hs.ip),
				Attributes:  map[string]any{"target": hs.ip},
				SupportingEntities: []fact.EntityRef{{Kind: entity.KindIP, Value: hs.ip}},
			}); err != nil {
				return err
			}
			findingsEmitted++
		}
		if hs.smbv1 {
			if _, err := cctx.EmitFinding(fact.FindingFact{
				Title:       fmt.Sprintf("SMBv1 enabled on %s", hs.ip),
				Severity:    finding.SeverityHigh,
				Confidence:  finding.ConfidenceHigh,
				Category:    "smb.legacy_protocol",
				Description: fmt.Sprintf("Host %s still speaks SMBv1. Removed in modern Windows; targeted by EternalBlue and similar exploits. Disable via Set-SmbServerConfiguration or Server Manager.", hs.ip),
				Attributes:  map[string]any{"target": hs.ip},
				SupportingEntities: []fact.EntityRef{{Kind: entity.KindIP, Value: hs.ip}},
			}); err != nil {
				return err
			}
			findingsEmitted++
		}

		_ = cctx.EmitEvidence(fact.EvidenceFact{
			SourceTool:     Name,
			SourceCategory: finding.SourceActiveScan,
			Confidence:     finding.ConfidenceHigh,
			Payload: map[string]any{
				"target":          hs.ip,
				"hostname":        hs.hostname,
				"os":              hs.os,
				"signing":         hs.signing,
				"smbv1":           hs.smbv1,
				"null_session_ok": hs.nullSessionOK,
				"pwn3d":           hs.pwn3d,
				"shares":          hs.shares,
				"users":           hs.users,
				"auth_mode":       authMode,
			},
			EntityKind:  entity.KindIP,
			EntityValue: hs.ip,
		})
	}
	return cctx.EmitEvidence(fact.EvidenceFact{
		SourceTool:     Name,
		SourceCategory: finding.SourceActiveScan,
		Confidence:     finding.ConfidenceHigh,
		Payload: map[string]any{
			"targets_scanned":  len(inScope),
			"findings_emitted": findingsEmitted,
			"auth_mode":        authMode,
		},
	})
}

type hostState struct {
	ip            string
	hostname      string
	os            string
	signing       string
	smbv1         bool
	nullSessionOK bool
	pwn3d         bool
	shares        []shareInfo
	users         []string
}

type shareInfo struct {
	Name        string `json:"name"`
	Permissions string `json:"permissions"`
}

// bannerRE pulls the SMB banner facts out of the * marker line, which
// looks like:
//   Windows 10.0 Build 19041 x64 (name:HOSTNAME) (domain:DOMAIN) (signing:False) (SMBv1:True)
var bannerRE = regexp.MustCompile(`^(.*?)\s*\(name:([^)]+)\)\s*\(domain:([^)]+)\)\s*\(signing:([^)]+)\)\s*\(SMBv1:([^)]+)\)`)

// shareRE matches a "+" marker share-list row:
//   ADMIN$           READ      Remote Admin
var shareRE = regexp.MustCompile(`^(\S+)\s+(READ|WRITE|READ,WRITE)(?:\s+(.*))?$`)

func (h *hostState) update(r smbRow) {
	switch r.Marker {
	case "*":
		// Banner / info row. Try to pull the SMB facts.
		if m := bannerRE.FindStringSubmatch(r.Body); m != nil {
			h.os = strings.TrimSpace(m[1])
			h.signing = strings.TrimSpace(m[4])
			h.smbv1 = strings.EqualFold(strings.TrimSpace(m[5]), "True")
		}
		if strings.Contains(strings.ToLower(r.Body), "guest session enabled") ||
			strings.Contains(strings.ToLower(r.Body), "null session") {
			h.nullSessionOK = true
		}
	case "+":
		body := strings.TrimSpace(r.Body)
		if strings.Contains(body, "(Pwn3d!)") {
			h.pwn3d = true
		}
		// Authentication confirmation includes the user/domain; if it
		// arrived via null session, also flag that.
		if strings.Contains(body, `\:`) || strings.HasPrefix(body, ":") {
			// "DOMAIN\:" or ":" — empty user means null session succeeded.
			h.nullSessionOK = true
		}
		// Share row.
		if m := shareRE.FindStringSubmatch(body); m != nil {
			h.shares = append(h.shares, shareInfo{Name: m[1], Permissions: m[2]})
			return
		}
		// User row (RPC --users mode): "user: SID rid: ...".
		if strings.HasPrefix(body, "user:") {
			parts := strings.Fields(body)
			if len(parts) >= 2 {
				h.users = append(h.users, parts[1])
			}
		}
	}
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
	for _, kind := range []entity.Kind{entity.KindIP, entity.KindSubdomain} {
		values, err := cctx.ListEntityValues(kind)
		if err != nil {
			return nil, err
		}
		out = append(out, values...)
	}
	if len(out) == 0 {
		return nil, errors.New("netexec: no targets; pass parameters[\"targets\"] or seed IP/SUBDOMAIN entities")
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

func parseBool(v any, fallback bool) bool {
	if b, ok := v.(bool); ok {
		return b
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
