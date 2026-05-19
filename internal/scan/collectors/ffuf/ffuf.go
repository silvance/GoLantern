// Package ffuf wraps the ffuf content-discovery fuzzer. Brute-force
// URL discovery: directories, files, hidden parameters that aren't
// linked from the public site.
//
// Ported from lantern/tools/ffuf.py. Lantern's port supports
// gobuster / feroxbuster / katana with similar shapes; we port ffuf
// as the canonical content-discovery wrapper and skip the others —
// they're near-duplicates.
package ffuf

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
	Name                  = "ffuf"
	defaultBinary         = "ffuf"
	defaultTimeout        = 600 * time.Second
	defaultThreads        = 40
	defaultStatusCodes    = "200,204,301,302,307,401,403,405"
	defaultFuzzKeyword    = "FUZZ"
	defaultContentWordlist = "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt"
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
		Description:        "Brute-force web content / endpoint discovery via ffuf.",
		Consumes:           []entity.Kind{entity.KindURL},
		Produces:           []entity.Kind{entity.KindURL},
		SourceCategory:     finding.SourceLiveProbe,
		TriggersOnServices: []string{"http", "https"},
		Binary:             "ffuf",
		InstallHint:        "go install github.com/ffuf/ffuf/v2@latest",
		Parameters: []scan.ParameterSpec{
			{Name: "targets", Type: "string_list", Placeholder: "https://www.example.com/FUZZ",
				Description: "URL templates. Each must contain the keyword (default FUZZ); /FUZZ is auto-appended."},
			{Name: "wordlist", Type: "string", Default: defaultContentWordlist,
				Description: "Path to the wordlist."},
			{Name: "extensions", Type: "string_list",
				Description: "Extensions to append to each word."},
			{Name: "status_codes", Type: "string", Default: defaultStatusCodes,
				Description: "Comma-separated status-code allowlist."},
			{Name: "threads", Type: "int", Default: 40, Description: "Concurrent request count."},
			{Name: "keyword", Type: "string", Default: "FUZZ", Description: "Substitution keyword."},
			{Name: "binary", Type: "string", Default: "ffuf"},
			{Name: "timeout_seconds", Type: "float", Default: 600.0,
				Description: "Wall-clock timeout per target."},
		},
	}
}

type ffufReport struct {
	Results []ffufResult `json:"results"`
}

type ffufResult struct {
	URL              string `json:"url"`
	Status           int    `json:"status"`
	Length           int    `json:"length"`
	Words            int    `json:"words"`
	RedirectLocation string `json:"redirectlocation"`
	ContentType      string `json:"content-type"`
}

func (c *collector) Run(ctx context.Context, cctx scan.Context) error {
	binary := strings.TrimSpace(toString(cctx.Parameters()["binary"]))
	if binary == "" {
		binary = defaultBinary
	}
	timeout := parseTimeout(cctx.Parameters()["timeout_seconds"])
	wordlist := strings.TrimSpace(toString(cctx.Parameters()["wordlist"]))
	if wordlist == "" {
		wordlist = defaultContentWordlist
	}
	if wordlist == "" {
		return errors.New("ffuf: wordlist is required")
	}
	threads := parsePositiveInt(cctx.Parameters()["threads"], defaultThreads)
	keyword := strings.TrimSpace(toString(cctx.Parameters()["keyword"]))
	if keyword == "" {
		keyword = defaultFuzzKeyword
	}
	statusCodes := strings.TrimSpace(toString(cctx.Parameters()["status_codes"]))
	if statusCodes == "" {
		statusCodes = defaultStatusCodes
	}
	rawExts := parseStringList(cctx.Parameters()["extensions"])
	var extensions []string
	for _, e := range rawExts {
		e = strings.TrimSpace(strings.TrimPrefix(e, "."))
		if e != "" {
			extensions = append(extensions, "."+e)
		}
	}

	templates, err := c.resolveTemplates(cctx, keyword)
	if err != nil {
		return err
	}
	var inScope []string
	for _, t := range templates {
		// Scope-check the template with the keyword stripped so the
		// scope matcher sees a real URL.
		probe := strings.Replace(t, keyword, "", 1)
		if cctx.IsInScope(probe) {
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

	for _, template := range inScope {
		args := []string{
			"-u", template,
			"-w", wordlist,
			"-mc", statusCodes,
			"-t", strconv.Itoa(threads),
			"-of", "json",
			"-o", "-",
			"-s",
		}
		for _, ext := range extensions {
			args = append(args, "-e", ext)
		}
		result, err := run(ctx, subprocess.Spec{
			Binary:         binary,
			Args:           args,
			Timeout:        timeout,
			AllowPartialRC: []int{1},
		})
		if err != nil {
			return fmt.Errorf("ffuf: %w", err)
		}
		var report ffufReport
		if err := json.Unmarshal(result.Stdout, &report); err != nil {
			return fmt.Errorf("ffuf JSON decode: %w", err)
		}
		for _, r := range report.Results {
			url := strings.TrimSpace(r.URL)
			if url == "" {
				continue
			}
			if _, err := cctx.EmitEntity(fact.EntityFact{
				Kind:           entity.KindURL,
				Value:          url,
				SourceCategory: finding.SourceLiveProbe,
				Confidence:     finding.ConfidenceHigh,
				Attributes: map[string]any{
					"status_code":     r.Status,
					"content_length":  r.Length,
					"discovered_via":  Name,
					"source_template": template,
				},
			}); err != nil {
				return err
			}
			if err := cctx.EmitEvidence(fact.EvidenceFact{
				SourceTool:     Name,
				SourceCategory: finding.SourceLiveProbe,
				Confidence:     finding.ConfidenceHigh,
				Payload: map[string]any{
					"url":          url,
					"status":       r.Status,
					"length":       r.Length,
					"words":        r.Words,
					"redirect":     r.RedirectLocation,
					"content_type": r.ContentType,
					"template":     template,
				},
				EntityKind:  entity.KindURL,
				EntityValue: url,
			}); err != nil {
				return err
			}
		}
	}
	return nil
}

func (c *collector) resolveTemplates(cctx scan.Context, keyword string) ([]string, error) {
	explicit := parseStringList(cctx.Parameters()["targets"])
	var raw []string
	if len(explicit) > 0 {
		for _, t := range explicit {
			if t = strings.TrimSpace(t); t != "" {
				raw = append(raw, t)
			}
		}
	}
	if len(raw) == 0 {
		urls, err := cctx.ListEntityValues(entity.KindURL)
		if err != nil {
			return nil, err
		}
		for _, u := range urls {
			if u = strings.TrimSpace(u); u != "" {
				raw = append(raw, strings.TrimRight(u, "/")+"/"+keyword)
			}
		}
	}
	if len(raw) == 0 {
		return nil, errors.New("ffuf: no targets to fuzz; pass parameters[\"targets\"] or seed URL entities")
	}
	out := make([]string, 0, len(raw))
	for _, t := range raw {
		if strings.Contains(t, keyword) {
			out = append(out, t)
		} else {
			out = append(out, strings.TrimRight(t, "/")+"/"+keyword)
		}
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
