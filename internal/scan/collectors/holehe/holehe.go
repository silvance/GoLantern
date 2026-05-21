// Package holehe wraps holehe for email-driven account enumeration.
// holehe is sherlock's email cousin: given an email address, it asks
// each of ~120 sites' password-reset / signup endpoints whether
// they recognize the address, without triggering any user-visible
// notification on the target account.
//
// Fills a real gap in the collector set — nothing previously
// consumed KindEmail to discover associated accounts. Lives in the
// enrichment phase because it enriches an existing email entity
// with the list of sites where that email is registered.
package holehe

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
	Name           = "holehe"
	defaultBinary  = "holehe"
	defaultTimeout = 300 * time.Second
)

// emailRE is the conservative check we apply before shelling out.
// holehe itself rejects malformed addresses, but rejecting them
// here gives a clearer error and prevents shell-injection-via-arg
// even though subprocess.Run uses exec.CommandContext (not shell).
var emailRE = regexp.MustCompile(`^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$`)

// hitRE matches the "[+] sitename" output lines holehe prints for
// every site that recognizes the email. holehe's other markers
// ([-] not used, [x] error, [*] rate limited) are deliberately
// ignored because they're not actionable signal.
var hitRE = regexp.MustCompile(`^\[\+\]\s+(\S+)`)

func New() scan.Collector { return &collector{} }

type runnerFn func(ctx context.Context, spec subprocess.Spec) (subprocess.Result, error)

func newWithRunner(r runnerFn) scan.Collector { return &collector{runner: r} }

type collector struct{ runner runnerFn }

func (collector) Metadata() scan.Meta {
	return scan.Meta{
		Name:           Name,
		Phase:          workflow.PhaseEnrichment,
		RequiredScope:  scope.KindPassive,
		Description:    "Given an email, enumerate which of ~120 sites recognize it (forgot-password / signup probes). No notification reaches the account holder.",
		Consumes:       []entity.Kind{entity.KindEmail},
		Produces:       []entity.Kind{entity.KindEmail},
		SourceCategory: finding.SourcePublicOSINT,
		Binary:         "holehe",
		InstallHint:    "pipx install holehe",
		Parameters: []scan.ParameterSpec{
			{Name: "emails", Type: "string_list", Placeholder: "alice@example.com",
				Description: "Emails to look up. Empty falls back to every EMAIL entity in the project."},
			{Name: "binary", Type: "string", Default: "holehe"},
			{Name: "timeout_seconds", Type: "float", Default: 300.0,
				Description: "Wall-clock timeout per email."},
		},
	}
}

func (c *collector) Run(ctx context.Context, cctx scan.Context) error {
	binary := strings.TrimSpace(toString(cctx.Parameters()["binary"]))
	if binary == "" {
		binary = defaultBinary
	}
	timeout := parseTimeout(cctx.Parameters()["timeout_seconds"])

	emails, err := c.resolveEmails(cctx)
	if err != nil {
		return err
	}
	var valid []string
	for _, e := range emails {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		if !emailRE.MatchString(e) {
			// Skip malformed addresses; record evidence and keep going
			// so one bad row doesn't sink the run.
			_ = cctx.EmitEvidence(fact.EvidenceFact{
				SourceTool:     Name,
				SourceCategory: finding.SourcePublicOSINT,
				Confidence:     finding.ConfidenceLow,
				Payload:        map[string]any{"email": e, "skipped": "malformed"},
			})
			continue
		}
		valid = append(valid, e)
	}
	if len(valid) == 0 {
		return errors.New("holehe: no valid emails to probe; pass parameters[\"emails\"] or seed EMAIL entities")
	}

	run := c.runner
	if run == nil {
		run = subprocess.Run
	}

	totalHits := 0
	for _, email := range valid {
		args := []string{email, "--no-color", "--only-used"}
		result, err := run(ctx, subprocess.Spec{
			Binary:         binary,
			Args:           args,
			Timeout:        timeout,
			AllowPartialRC: []int{1},
		})
		if err != nil {
			_ = cctx.EmitEvidence(fact.EvidenceFact{
				SourceTool:     Name,
				SourceCategory: finding.SourcePublicOSINT,
				Confidence:     finding.ConfidenceLow,
				Payload:        map[string]any{"email": email, "error": err.Error()},
				EntityKind:     entity.KindEmail,
				EntityValue:    strings.ToLower(email),
			})
			continue
		}
		sites := parseHits(string(result.Stdout))
		// Make sure the email entity exists so the evidence attaches
		// to something. The runner dedups on (kind, value).
		if _, err := cctx.EmitEntity(fact.EntityFact{
			Kind:           entity.KindEmail,
			Value:          email,
			Confidence:     finding.ConfidenceMedium,
			SourceCategory: finding.SourcePublicOSINT,
		}); err != nil {
			return err
		}
		for _, site := range sites {
			if err := cctx.EmitEvidence(fact.EvidenceFact{
				SourceTool:     Name,
				SourceCategory: finding.SourcePublicOSINT,
				Confidence:     finding.ConfidenceMedium,
				Payload: map[string]any{
					"email": email,
					"site":  site,
				},
				EntityKind:  entity.KindEmail,
				EntityValue: strings.ToLower(email),
			}); err != nil {
				return err
			}
		}
		// Per-email rollup makes the entity-detail view legible at a
		// glance — analyst sees "this address is on 17 services"
		// without scrolling through 17 evidence rows.
		if err := cctx.EmitEvidence(fact.EvidenceFact{
			SourceTool:     Name,
			SourceCategory: finding.SourcePublicOSINT,
			Confidence:     finding.ConfidenceHigh,
			Payload: map[string]any{
				"email":         email,
				"sites_matched": sites,
				"hit_count":     len(sites),
			},
			EntityKind:  entity.KindEmail,
			EntityValue: strings.ToLower(email),
		}); err != nil {
			return err
		}
		totalHits += len(sites)
	}
	return cctx.EmitEvidence(fact.EvidenceFact{
		SourceTool:     Name,
		SourceCategory: finding.SourcePublicOSINT,
		Confidence:     finding.ConfidenceHigh,
		Payload: map[string]any{
			"emails_probed": len(valid),
			"total_hits":    totalHits,
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
		site := strings.ToLower(strings.TrimSpace(m[1]))
		if site == "" {
			continue
		}
		if _, dup := seen[site]; dup {
			continue
		}
		seen[site] = struct{}{}
		out = append(out, site)
	}
	return out
}

func (c *collector) resolveEmails(cctx scan.Context) ([]string, error) {
	explicit := parseStringList(cctx.Parameters()["emails"])
	if len(explicit) > 0 {
		out := make([]string, 0, len(explicit))
		for _, e := range explicit {
			if e = strings.TrimSpace(e); e != "" {
				out = append(out, e)
			}
		}
		if len(out) > 0 {
			return out, nil
		}
	}
	values, err := cctx.ListEntityValues(entity.KindEmail)
	if err != nil {
		return nil, err
	}
	if len(values) == 0 {
		return nil, fmt.Errorf("holehe: no emails to probe; pass parameters[\"emails\"] or seed EMAIL entities")
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
