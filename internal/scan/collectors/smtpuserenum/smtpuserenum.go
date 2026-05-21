// Package smtpuserenum wraps smtp-user-enum for SMTP VRFY/EXPN/RCPT
// user enumeration. Niche but real: misconfigured mail servers
// confirm or deny the existence of local user accounts via these
// SMTP verbs, giving an analyst a verified user list for downstream
// phishing or password-spray work.
//
// Modern mail servers usually disable VRFY/EXPN, but plenty of
// internal Postfix/Sendmail boxes still respond. The collector
// runs only when seeded with a username list (the input that's
// most likely to be intentional) and a target SMTP server.
package smtpuserenum

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
	Name           = "smtp_user_enum"
	defaultBinary  = "smtp-user-enum"
	defaultTimeout = 600 * time.Second
)

// Conservative whitelist for the username argv. smtp-user-enum
// passes the list to the SMTP server verbatim; we still apply
// our own filter to keep nonsense out of the command line.
var usernameRE = regexp.MustCompile(`^[A-Za-z0-9._\-+]{1,64}$`)

// hitRE matches smtp-user-enum's hit lines:
//   target_host: username exists
//   target_host:25: username (RCPT TO)
var hitRE = regexp.MustCompile(`(?i):\s*(\S+)\s+(?:exists|\(RCPT TO\))`)

func New() scan.Collector { return &collector{} }

type runnerFn func(ctx context.Context, spec subprocess.Spec) (subprocess.Result, error)

func newWithRunner(r runnerFn) scan.Collector { return &collector{runner: r} }

type collector struct{ runner runnerFn }

func (collector) Metadata() scan.Meta {
	return scan.Meta{
		Name:               Name,
		Phase:              workflow.PhaseExposure,
		RequiredScope:      scope.KindLightActive,
		Description:        "Probe an SMTP server for valid local users via VRFY/EXPN/RCPT. Niche but high-signal on misconfigured internal mail servers.",
		Consumes:           []entity.Kind{entity.KindIP, entity.KindSubdomain},
		Produces:           []entity.Kind{entity.KindEmail},
		SourceCategory:     finding.SourceActiveScan,
		TriggersOnServices: []string{"smtp", "smtps"},
		Binary:             "smtp-user-enum",
		InstallHint:        "Fedora: not packaged — see https://github.com/pentestmonkey/smtp-user-enum\nDebian/Ubuntu: sudo apt install smtp-user-enum\nKali: pre-installed",
		Parameters: []scan.ParameterSpec{
			{Name: "targets", Type: "string_list", Placeholder: "mail.example.com",
				Description: "SMTP servers to probe. Empty falls back to every IP + SUBDOMAIN entity (usually noisy — be deliberate)."},
			{Name: "usernames", Type: "string_list", Required: true,
				Description: "Usernames to test."},
			{Name: "mode", Type: "enum", Default: "VRFY",
				Choices:     []string{"VRFY", "EXPN", "RCPT"},
				Description: "SMTP verb. VRFY and EXPN are direct; RCPT injects RCPT TO commands during a partial mail transaction."},
			{Name: "port", Type: "int", Default: 25,
				Description: "SMTP port."},
			{Name: "binary", Type: "string", Default: "smtp-user-enum"},
			{Name: "timeout_seconds", Type: "float", Default: 600.0},
		},
	}
}

func (c *collector) Run(ctx context.Context, cctx scan.Context) error {
	binary := strings.TrimSpace(toString(cctx.Parameters()["binary"]))
	if binary == "" {
		binary = defaultBinary
	}
	timeout := parseTimeout(cctx.Parameters()["timeout_seconds"])
	port := parsePositiveInt(cctx.Parameters()["port"], 25)
	mode := strings.ToUpper(strings.TrimSpace(toString(cctx.Parameters()["mode"])))
	if mode == "" {
		mode = "VRFY"
	}

	usernames := parseStringList(cctx.Parameters()["usernames"])
	var validUsers []string
	for _, u := range usernames {
		u = strings.TrimSpace(u)
		if usernameRE.MatchString(u) {
			validUsers = append(validUsers, u)
		}
	}
	if len(validUsers) == 0 {
		return errors.New("smtp_user_enum: parameter `usernames` is required (non-empty, allowed chars only)")
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

	totalHits := 0
	for _, target := range inScope {
		// smtp-user-enum has flags: -M mode, -t host, -p port, -U userfile.
		// We feed users via stdin to avoid creating a temp file per run.
		args := []string{"-M", mode, "-t", target, "-p", fmt.Sprintf("%d", port), "-U", "/dev/stdin"}
		stdin := []byte(strings.Join(validUsers, "\n") + "\n")

		result, err := run(ctx, subprocess.Spec{
			Binary:         binary,
			Args:           args,
			Stdin:          stdin,
			Timeout:        timeout,
			AllowPartialRC: []int{1, 2, 3},
		})
		if err != nil {
			_ = cctx.EmitEvidence(fact.EvidenceFact{
				SourceTool:     Name,
				SourceCategory: finding.SourceActiveScan,
				Confidence:     finding.ConfidenceLow,
				Payload:        map[string]any{"target": target, "error": err.Error()},
				EntityKind:     entity.KindIP,
				EntityValue:    target,
			})
			continue
		}

		hits := parseHits(string(result.Stdout))
		if len(hits) == 0 {
			_ = cctx.EmitEvidence(fact.EvidenceFact{
				SourceTool:     Name,
				SourceCategory: finding.SourceActiveScan,
				Confidence:     finding.ConfidenceMedium,
				Payload: map[string]any{
					"target":    target,
					"mode":      mode,
					"tried":     len(validUsers),
					"confirmed": 0,
				},
				EntityKind:  entity.KindIP,
				EntityValue: target,
			})
			continue
		}

		// Emit one EMAIL entity per confirmed user (target acts as
		// the implicit domain).
		for _, user := range hits {
			email := user + "@" + target
			if _, err := cctx.EmitEntity(fact.EntityFact{
				Kind:           entity.KindEmail,
				Value:          email,
				Attributes:     map[string]any{"discovered_via": Name, "mode": mode, "smtp_host": target},
				Confidence:     finding.ConfidenceMedium,
				SourceCategory: finding.SourceActiveScan,
			}); err != nil {
				return err
			}
		}

		// One finding per host that leaked at least one user.
		if _, err := cctx.EmitFinding(fact.FindingFact{
			Title:       fmt.Sprintf("SMTP user enumeration via %s on %s", mode, target),
			Severity:    finding.SeverityMedium,
			Confidence:  finding.ConfidenceHigh,
			Category:    "smtp.user_enumeration",
			Description: fmt.Sprintf("Mail server %s confirmed %d local users via SMTP %s. Disable VRFY/EXPN and harden RCPT TO responses so valid and invalid recipients return identical responses.", target, len(hits), mode),
			Attributes: map[string]any{
				"target":     target,
				"mode":       mode,
				"users":      hits,
				"port":       port,
				"users_tried": len(validUsers),
			},
			SupportingEntities: []fact.EntityRef{{Kind: entity.KindIP, Value: target}},
		}); err != nil {
			return err
		}

		_ = cctx.EmitEvidence(fact.EvidenceFact{
			SourceTool:     Name,
			SourceCategory: finding.SourceActiveScan,
			Confidence:     finding.ConfidenceHigh,
			Payload: map[string]any{
				"target":    target,
				"mode":      mode,
				"tried":     len(validUsers),
				"confirmed": len(hits),
				"users":     hits,
			},
			EntityKind:  entity.KindIP,
			EntityValue: target,
		})
		totalHits += len(hits)
	}
	return cctx.EmitEvidence(fact.EvidenceFact{
		SourceTool:     Name,
		SourceCategory: finding.SourceActiveScan,
		Confidence:     finding.ConfidenceHigh,
		Payload: map[string]any{
			"targets_probed":  len(inScope),
			"users_tried":     len(validUsers),
			"users_confirmed": totalHits,
			"mode":            mode,
		},
	})
}

func parseHits(stdout string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, raw := range strings.Split(stdout, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		m := hitRE.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		user := strings.TrimSpace(m[1])
		if user == "" || !usernameRE.MatchString(user) {
			continue
		}
		if _, dup := seen[user]; dup {
			continue
		}
		seen[user] = struct{}{}
		out = append(out, user)
	}
	return out
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
		return nil, errors.New("smtp_user_enum: no targets; pass parameters[\"targets\"] or seed IP/SUBDOMAIN entities")
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
