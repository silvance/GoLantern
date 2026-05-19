// Package theharvester wraps theHarvester for passive identity
// discovery: emails, subdomains, and (when sources support it) people
// associated with a target domain.
//
// theHarvester writes a JSON file to disk (-f basename → basename.json
// next to the basename). We allocate a temp directory per invocation,
// point -f there, and parse the JSON; the temp dir disappears whether
// the process succeeds or crashes.
//
// Ported from lantern/tools/theharvester.py.
package theharvester

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
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
	Name           = "theharvester"
	defaultBinary  = "theHarvester"
	defaultTimeout = 300 * time.Second
	defaultLimit   = 200
	defaultSources = "duckduckgo,otx,crtsh,hackertarget,rapiddns"
)

func New() scan.Collector { return &collector{} }

// runnerFn lets tests stub out the subprocess; the test fn is also
// responsible for writing the JSON output file the collector expects
// to read post-run.
type runnerFn func(ctx context.Context, spec subprocess.Spec) (subprocess.Result, error)

func newWithRunner(r runnerFn) scan.Collector { return &collector{runner: r} }

type collector struct{ runner runnerFn }

func (collector) Metadata() scan.Meta {
	return scan.Meta{
		Name:           Name,
		Phase:          workflow.PhaseOSINT,
		RequiredScope:  scope.KindPassive,
		Description:    "Discover emails, names, and subdomains via theHarvester's public OSINT sources.",
		Consumes:       []entity.Kind{entity.KindDomain},
		Produces:       []entity.Kind{entity.KindEmail, entity.KindSubdomain, entity.KindPerson},
		SourceCategory: finding.SourcePublicOSINT,
		Binary:         "theHarvester",
		InstallHint: "pipx install git+https://github.com/laramies/theHarvester.git\n" +
			"# Kali ships it as a distro package: apt install theharvester",
		Parameters: []scan.ParameterSpec{
			{Name: "domain", Type: "string", Required: true, Placeholder: "example.com"},
			{Name: "sources", Type: "string", Default: defaultSources,
				Description: "Comma-separated theHarvester sources (passed as -b)."},
			{Name: "limit", Type: "int", Default: 200, Description: "Results per source (-l)."},
			{Name: "binary", Type: "string", Default: "theHarvester"},
			{Name: "timeout_seconds", Type: "float", Default: 300.0},
		},
	}
}

type theharvesterJSON struct {
	Hosts          []string `json:"hosts"`
	Emails         []string `json:"emails"`
	People         []string `json:"people"`
	LinkedInPeople []string `json:"linkedin_people"`
}

func (c *collector) Run(ctx context.Context, cctx scan.Context) error {
	rawDomain, _ := cctx.Parameters()["domain"].(string)
	domain := strings.ToLower(strings.TrimSpace(rawDomain))
	if domain == "" {
		return errors.New("theharvester: parameter `domain` is required")
	}
	if !cctx.IsInScope(domain) {
		return nil
	}

	binary := strings.TrimSpace(toString(cctx.Parameters()["binary"]))
	if binary == "" {
		binary = defaultBinary
	}
	sources := strings.TrimSpace(toString(cctx.Parameters()["sources"]))
	if sources == "" {
		sources = defaultSources
	}
	limit := parsePositiveInt(cctx.Parameters()["limit"], defaultLimit)
	timeout := parseTimeout(cctx.Parameters()["timeout_seconds"])

	tmp, err := os.MkdirTemp("", "golantern-harvester-")
	if err != nil {
		return fmt.Errorf("theharvester: tempdir: %w", err)
	}
	defer os.RemoveAll(tmp)

	basename := filepath.Join(tmp, "out")
	args := []string{
		"-d", domain,
		"-b", sources,
		"-l", strconv.Itoa(limit),
		"-f", basename,
	}

	run := c.runner
	if run == nil {
		run = subprocess.Run
	}
	if _, err := run(ctx, subprocess.Spec{
		Binary:  binary,
		Args:    args,
		Timeout: timeout,
	}); err != nil {
		return fmt.Errorf("theharvester: %w", err)
	}

	jsonPath := basename + ".json"
	body, err := os.ReadFile(jsonPath)
	if err != nil {
		return fmt.Errorf("theharvester: did not produce %s: %w", jsonPath, err)
	}
	var parsed theharvesterJSON
	if err := json.Unmarshal(body, &parsed); err != nil {
		return fmt.Errorf("theharvester: decode JSON: %w", err)
	}

	if _, err := cctx.EmitEntity(fact.EntityFact{
		Kind:           entity.KindDomain,
		Value:          domain,
		Confidence:     finding.ConfidenceHigh,
		SourceCategory: finding.SourcePublicOSINT,
		Attributes:     map[string]any{"role": "primary"},
	}); err != nil {
		return err
	}

	emittedSubs := map[string]struct{}{}
	subSuffix := "." + domain
	for _, host := range parsed.Hosts {
		sub := extractSubdomain(host, domain, subSuffix)
		if sub == "" {
			continue
		}
		if _, dup := emittedSubs[sub]; dup {
			continue
		}
		emittedSubs[sub] = struct{}{}
		if _, err := cctx.EmitEntity(fact.EntityFact{
			Kind:           entity.KindSubdomain,
			Value:          sub,
			Confidence:     finding.ConfidenceMedium,
			SourceCategory: finding.SourcePublicOSINT,
		}); err != nil {
			return err
		}
		if err := cctx.EmitRelation(fact.RelationFact{
			Src:  fact.EntityRef{Kind: entity.KindSubdomain, Value: sub},
			Dst:  fact.EntityRef{Kind: entity.KindDomain, Value: domain},
			Kind: entity.RelChildOf,
		}); err != nil {
			return err
		}
	}

	// Filter emails to those whose address belongs to the apex or to
	// one of the just-emitted subdomains. theHarvester's sources
	// frequently return collateral addresses (forum signatures, docs).
	emittedEmails := map[string]struct{}{}
	emailsDropped := 0
	domainSuffix := "@" + domain
	for _, raw := range parsed.Emails {
		email := strings.ToLower(strings.TrimSpace(raw))
		if email == "" || !strings.Contains(email, "@") {
			continue
		}
		if _, dup := emittedEmails[email]; dup {
			continue
		}
		matches := strings.HasSuffix(email, domainSuffix)
		if !matches {
			for sub := range emittedSubs {
				if strings.HasSuffix(email, "@"+sub) {
					matches = true
					break
				}
			}
		}
		if !matches {
			emailsDropped++
			continue
		}
		emittedEmails[email] = struct{}{}
		if _, err := cctx.EmitEntity(fact.EntityFact{
			Kind:           entity.KindEmail,
			Value:          email,
			Confidence:     finding.ConfidenceMedium,
			SourceCategory: finding.SourcePublicOSINT,
		}); err != nil {
			return err
		}
	}

	emittedPeople := map[string]struct{}{}
	people := parsed.People
	if len(people) == 0 {
		people = parsed.LinkedInPeople
	}
	for _, raw := range people {
		name := strings.TrimSpace(raw)
		if name == "" {
			continue
		}
		key := strings.ToLower(name)
		if _, dup := emittedPeople[key]; dup {
			continue
		}
		emittedPeople[key] = struct{}{}
		if _, err := cctx.EmitEntity(fact.EntityFact{
			Kind:           entity.KindPerson,
			Value:          name,
			Confidence:     finding.ConfidenceLow,
			SourceCategory: finding.SourcePublicOSINT,
		}); err != nil {
			return err
		}
	}

	return cctx.EmitEvidence(fact.EvidenceFact{
		SourceTool:     Name,
		SourceCategory: finding.SourcePublicOSINT,
		Confidence:     finding.ConfidenceHigh,
		Payload: map[string]any{
			"domain":                       domain,
			"sources":                      sources,
			"subdomains_emitted":           len(emittedSubs),
			"emails_emitted":               len(emittedEmails),
			"emails_dropped_out_of_scope":  emailsDropped,
			"people_emitted":               len(emittedPeople),
		},
		EntityKind:  entity.KindDomain,
		EntityValue: domain,
	})
}

// extractSubdomain pulls a clean subdomain out of theHarvester's mixed
// host strings ("api.example.com:1.2.3.4", "api.example.com", or bare
// IP). Returns "" for entries that aren't subdomains under domain.
func extractSubdomain(hostEntry, domain, suffix string) string {
	raw := strings.ToLower(strings.TrimSpace(hostEntry))
	if raw == "" {
		return ""
	}
	if i := strings.Index(raw, ":"); i >= 0 {
		raw = raw[:i]
	}
	if raw == "" || raw == domain {
		return ""
	}
	// Drop bare IPs.
	if !strings.Contains(raw, ".") || isAllDigitsAndDots(raw) {
		return ""
	}
	if !strings.HasSuffix(raw, suffix) {
		return ""
	}
	return raw
}

func isAllDigitsAndDots(s string) bool {
	for _, r := range s {
		if r != '.' && (r < '0' || r > '9') {
			return false
		}
	}
	return true
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

func toString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}
