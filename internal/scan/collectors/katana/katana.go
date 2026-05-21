// Package katana wraps ProjectDiscovery's katana crawler. Modern
// crawler that follows JavaScript-emitted endpoints alongside the
// static HTML graph — closes the SPA gap that ffuf (a brute-forcer)
// and nikto (a vuln scanner) leave open.
//
// Emits one URL entity per unique endpoint discovered. The default
// depth is conservative (2 hops) so a single katana run on a busy
// site doesn't balloon into thousands of entities; operators bump
// depth/max_pages explicitly when they want more.
package katana

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
	Name           = "katana"
	defaultBinary  = "katana"
	defaultTimeout = 600 * time.Second
)

func New() scan.Collector { return &collector{} }

type runnerFn func(ctx context.Context, spec subprocess.Spec) (subprocess.Result, error)

func newWithRunner(r runnerFn) scan.Collector { return &collector{runner: r} }

type collector struct{ runner runnerFn }

func (collector) Metadata() scan.Meta {
	return scan.Meta{
		Name:               Name,
		Phase:              workflow.PhaseExposure,
		RequiredScope:      scope.KindFullActive,
		Description:        "Modern web crawler that follows JS-emitted endpoints. Fills the SPA-route gap that ffuf and nikto miss.",
		Consumes:           []entity.Kind{entity.KindURL},
		Produces:           []entity.Kind{entity.KindURL},
		SourceCategory:     finding.SourceActiveScan,
		TriggersOnServices: []string{"http", "https"},
		Binary:             "katana",
		InstallHint:        "go install github.com/projectdiscovery/katana/cmd/katana@latest",
		Parameters: []scan.ParameterSpec{
			{Name: "targets", Type: "string_list", Placeholder: "https://example.com",
				Description: "URLs to crawl. Empty falls back to every URL entity in the project."},
			{Name: "depth", Type: "int", Default: 2,
				Description: "Maximum crawl depth in hops from each seed URL."},
			{Name: "max_pages", Type: "int", Default: 500,
				Description: "Per-host page cap; prevents runaway crawls."},
			{Name: "js_crawl", Type: "bool", Default: true,
				Description: "Parse JavaScript files for endpoint references."},
			{Name: "binary", Type: "string", Default: "katana"},
			{Name: "timeout_seconds", Type: "float", Default: 600.0,
				Description: "Wall-clock timeout."},
		},
	}
}

// katanaJSON covers both the "modern" shape (endpoint/method at top level)
// and the legacy nested {request:{endpoint, method}} shape so we don't
// silently drop output when katana ships a new format.
type katanaJSON struct {
	Endpoint string `json:"endpoint"`
	Method   string `json:"method"`
	Request  struct {
		Endpoint string `json:"endpoint"`
		Method   string `json:"method"`
	} `json:"request"`
	Response struct {
		StatusCode int `json:"status_code"`
	} `json:"response"`
	Source string `json:"source"`
}

func (r katanaJSON) URL() string {
	if r.Endpoint != "" {
		return r.Endpoint
	}
	return r.Request.Endpoint
}

func (r katanaJSON) HTTPMethod() string {
	if r.Method != "" {
		return r.Method
	}
	return r.Request.Method
}

func (c *collector) Run(ctx context.Context, cctx scan.Context) error {
	binary := strings.TrimSpace(toString(cctx.Parameters()["binary"]))
	if binary == "" {
		binary = defaultBinary
	}
	timeout := parseTimeout(cctx.Parameters()["timeout_seconds"])
	depth := parsePositiveInt(cctx.Parameters()["depth"], 2)
	maxPages := parsePositiveInt(cctx.Parameters()["max_pages"], 500)
	jsCrawl := parseBoolDefault(cctx.Parameters()["js_crawl"], true)

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
		"-list", "-",
		"-jsonl",
		"-silent",
		"-no-color",
		"-d", fmt.Sprintf("%d", depth),
		"-c", fmt.Sprintf("%d", maxPages),
	}
	if jsCrawl {
		args = append(args, "-jc")
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
		return fmt.Errorf("katana: %w", err)
	}

	seen := map[string]struct{}{}
	emitted := 0
	for _, raw := range strings.Split(string(result.Stdout), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		var rec katanaJSON
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			continue
		}
		u := strings.TrimSpace(rec.URL())
		if u == "" {
			continue
		}
		lu := strings.ToLower(u)
		if !strings.HasPrefix(lu, "http://") && !strings.HasPrefix(lu, "https://") {
			continue
		}
		if _, dup := seen[u]; dup {
			continue
		}
		seen[u] = struct{}{}
		if !cctx.IsInScope(u) {
			continue
		}
		attrs := map[string]any{
			"discovered_via": Name,
			"method":         rec.HTTPMethod(),
			"source":         rec.Source,
		}
		if rec.Response.StatusCode > 0 {
			attrs["status_code"] = rec.Response.StatusCode
		}
		if _, err := cctx.EmitEntity(fact.EntityFact{
			Kind:           entity.KindURL,
			Value:          u,
			Attributes:     attrs,
			Confidence:     finding.ConfidenceHigh,
			SourceCategory: finding.SourceActiveScan,
		}); err != nil {
			return err
		}
		emitted++
	}
	return cctx.EmitEvidence(fact.EvidenceFact{
		SourceTool:     Name,
		SourceCategory: finding.SourceActiveScan,
		Confidence:     finding.ConfidenceHigh,
		Payload: map[string]any{
			"seeds":          len(inScope),
			"urls_emitted":   emitted,
			"depth":          depth,
			"max_pages":      maxPages,
			"js_crawl":       jsCrawl,
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
	values, err := cctx.ListEntityValues(entity.KindURL)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, v := range values {
		v = strings.TrimSpace(v)
		lv := strings.ToLower(v)
		if strings.HasPrefix(lv, "http://") || strings.HasPrefix(lv, "https://") {
			out = append(out, v)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("katana: no targets to crawl; pass parameters[\"targets\"] or seed URL entities")
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

func parseBoolDefault(v any, fallback bool) bool {
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
