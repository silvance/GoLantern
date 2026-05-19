// Package gowitness wraps ProjectDiscovery/sensepost's gowitness CLI
// to take screenshots of HTTP(S) endpoints. Each screenshot is
// persisted via the runner's artifact subsystem; the resulting
// lantern://artifacts/<id> URI is attached to an evidence row keyed
// to the URL entity so the report and SPA can render the image inline.
//
// Ported from lantern/tools/gowitness.py.
//
// gowitness v3 changed the CLI; this port targets v3 (`gowitness scan
// file`). We pin --write-jsonl for parseable output and
// --screenshot-path so we know where to look for the PNGs. The output
// directory is created fresh per run inside the OS temp dir so a
// crashed previous run can't leak state into this one.
package gowitness

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
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
	Name           = "gowitness"
	defaultBinary  = "gowitness"
	defaultTimeout = 300 * time.Second
)

// New returns a collector using the default gowitness binary on PATH.
func New() scan.Collector { return &collector{} }

// runnerFn is the test-injection seam. It receives the screenshotDir
// the collector wants gowitness to write into; the production runner
// passes it through to gowitness, and tests use it to drop synthetic
// PNGs the collector then reads back.
type runnerFn func(ctx context.Context, binary, screenshotDir string, urls []string, timeout time.Duration, extraArgs []string) (stdoutJSONL []byte, err error)

func newWithRunner(r runnerFn) scan.Collector { return &collector{runner: r} }

type collector struct {
	runner runnerFn
}

func (collector) Metadata() scan.Meta {
	return scan.Meta{
		Name:               Name,
		Phase:              workflow.PhaseValidation,
		RequiredScope:      scope.KindLightActive,
		Description:        "Screenshots HTTP(S) endpoints and stores each PNG as a Lantern artifact attached to the URL entity.",
		Consumes:           []entity.Kind{entity.KindURL},
		Produces:           []entity.Kind{}, // attaches evidence to existing URL entities; no new kinds
		SourceCategory:     finding.SourceLiveProbe,
		TriggersOnServices: []string{"http", "https"},
		Binary:             "gowitness",
		InstallHint: "go install github.com/sensepost/gowitness@latest\n" +
			"# Requires Chromium / Chrome installed on the host:\n" +
			"#   Debian/Ubuntu: apt install chromium\n" +
			"#   macOS:         brew install --cask chromium",
		Parameters: []scan.ParameterSpec{
			{Name: "urls", Type: "string_list", Placeholder: "https://example.com, https://api.example.com",
				Description: "URLs to screenshot. Empty falls back to every URL entity in the project."},
			{Name: "binary", Type: "string", Default: "gowitness",
				Description: "Override the gowitness binary path or name."},
			{Name: "timeout_seconds", Type: "float", Default: 300.0,
				Description: "Wall-clock timeout in seconds for the gowitness subprocess."},
			{Name: "extra_args", Type: "string_list",
				Description: "Extra flags passed verbatim to `gowitness scan file`. --write-jsonl and --screenshot-path are managed by the collector and must not be overridden."},
		},
	}
}

// gowitnessJSON is the subset of gowitness --write-jsonl output we
// consume. gowitness writes one JSON object per URL processed; failed
// URLs still get a line but with status_code=0 and an empty filename.
// Unknown fields are ignored.
type gowitnessJSON struct {
	URL        string `json:"url"`
	FinalURL   string `json:"final_url"`
	Title      string `json:"title"`
	StatusCode int    `json:"response_code"`
	Filename   string `json:"file_name"`
	Failed     bool   `json:"failed"`
	FailReason string `json:"failed_reason"`
}

func (c *collector) Run(ctx context.Context, cctx scan.Context) error {
	binary := strings.TrimSpace(toString(cctx.Parameters()["binary"]))
	if binary == "" {
		binary = defaultBinary
	}
	timeout := parseTimeout(cctx.Parameters()["timeout_seconds"])
	extraArgs := parseStringList(cctx.Parameters()["extra_args"])

	urls, err := c.resolveURLs(cctx)
	if err != nil {
		return err
	}
	var inScope []string
	for _, u := range urls {
		if cctx.IsInScope(u) {
			inScope = append(inScope, u)
		}
	}
	if len(inScope) == 0 {
		// Zero-emission diagnostic in the runner surfaces the message.
		return nil
	}

	// Fresh screenshot dir per run so a previous failed invocation
	// can't pollute this one. Cleaned up on return.
	screenshotDir, err := os.MkdirTemp("", "golantern-gowitness-*")
	if err != nil {
		return fmt.Errorf("gowitness: mkdir temp: %w", err)
	}
	defer os.RemoveAll(screenshotDir)

	run := c.runner
	if run == nil {
		run = defaultRunner
	}
	stdoutJSONL, err := run(ctx, binary, screenshotDir, inScope, timeout, extraArgs)
	if err != nil {
		return fmt.Errorf("gowitness: %w", err)
	}

	records := parseJSONL(stdoutJSONL)
	screenshots := 0
	failures := 0

	for _, rec := range records {
		urlValue := strings.TrimSpace(rec.FinalURL)
		if urlValue == "" {
			urlValue = strings.TrimSpace(rec.URL)
		}
		if urlValue == "" {
			continue
		}
		if rec.Failed || rec.Filename == "" {
			failures++
			if err := cctx.EmitEvidence(fact.EvidenceFact{
				SourceTool:     Name,
				SourceCategory: finding.SourceLiveProbe,
				Confidence:     finding.ConfidenceLow,
				EntityKind:     entity.KindURL,
				EntityValue:    urlValue,
				Payload: map[string]any{
					"failed":        true,
					"failed_reason": rec.FailReason,
					"status_code":   rec.StatusCode,
				},
				Notes: "gowitness failed to screenshot this URL",
			}); err != nil {
				return err
			}
			continue
		}

		pngPath := filepath.Join(screenshotDir, rec.Filename)
		content, err := os.ReadFile(pngPath)
		if err != nil {
			// gowitness reported a filename but the file is missing.
			// Treat as a per-target failure rather than aborting the
			// whole collector run.
			failures++
			if err := cctx.EmitEvidence(fact.EvidenceFact{
				SourceTool:     Name,
				SourceCategory: finding.SourceLiveProbe,
				Confidence:     finding.ConfidenceLow,
				EntityKind:     entity.KindURL,
				EntityValue:    urlValue,
				Payload: map[string]any{
					"failed":        true,
					"failed_reason": fmt.Sprintf("screenshot file missing: %v", err),
				},
			}); err != nil {
				return err
			}
			continue
		}

		// Stable, human-readable filename so the artifact row's
		// download attachment makes sense out of context.
		artifactFilename := sanitizeFilename(urlValue) + ".png"
		uri, err := cctx.StoreArtifact(content, artifactFilename, "image/png")
		if err != nil {
			return fmt.Errorf("gowitness: store screenshot for %s: %w", urlValue, err)
		}
		screenshots++

		if err := cctx.EmitEvidence(fact.EvidenceFact{
			SourceTool:     Name,
			SourceCategory: finding.SourceLiveProbe,
			Confidence:     finding.ConfidenceHigh,
			EntityKind:     entity.KindURL,
			EntityValue:    urlValue,
			ArtifactURI:    uri,
			Payload: map[string]any{
				"title":       rec.Title,
				"status_code": rec.StatusCode,
				"final_url":   rec.FinalURL,
				"size_bytes":  len(content),
			},
			Notes: "Screenshot captured by gowitness",
		}); err != nil {
			return err
		}
	}

	return cctx.EmitEvidence(fact.EvidenceFact{
		SourceTool:     Name,
		SourceCategory: finding.SourceLiveProbe,
		Confidence:     finding.ConfidenceHigh,
		Payload: map[string]any{
			"urls_input":   len(urls),
			"urls_skipped": len(urls) - len(inScope),
			"screenshots":  screenshots,
			"failures":     failures,
		},
	})
}

func (c *collector) resolveURLs(cctx scan.Context) ([]string, error) {
	explicit := parseStringList(cctx.Parameters()["urls"])
	if len(explicit) > 0 {
		out := make([]string, 0, len(explicit))
		for _, u := range explicit {
			if u = strings.TrimSpace(u); u != "" {
				out = append(out, u)
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
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("gowitness: no URLs to screenshot; pass parameters[\"urls\"] or seed URL entities (run httpx_probe first)")
	}
	return out, nil
}

// defaultRunner is the production shell-out path. It writes the URL
// list to a tempfile (gowitness's `scan file` reads from a path, not
// stdin) and invokes gowitness with our managed screenshot path and
// --write-jsonl. Returns the JSONL stdout.
func defaultRunner(ctx context.Context, binary, screenshotDir string, urls []string, timeout time.Duration, extraArgs []string) ([]byte, error) {
	urlsFile, err := os.CreateTemp("", "golantern-gowitness-urls-*.txt")
	if err != nil {
		return nil, fmt.Errorf("urls file: %w", err)
	}
	defer os.Remove(urlsFile.Name())
	if _, err := urlsFile.WriteString(strings.Join(urls, "\n") + "\n"); err != nil {
		urlsFile.Close()
		return nil, fmt.Errorf("urls file write: %w", err)
	}
	urlsFile.Close()

	args := []string{
		"scan", "file",
		"-f", urlsFile.Name(),
		"--screenshot-path", screenshotDir,
		"--write-jsonl",
	}
	args = append(args, extraArgs...)
	result, err := subprocess.Run(ctx, subprocess.Spec{
		Binary:  binary,
		Args:    args,
		Timeout: timeout,
	})
	if err != nil {
		return result.Stdout, err
	}
	return result.Stdout, nil
}

// parseJSONL parses one gowitness JSON object per non-blank line.
// Malformed lines are skipped — older versions occasionally emit
// progress noise next to JSON.
func parseJSONL(blob []byte) []gowitnessJSON {
	var out []gowitnessJSON
	for _, raw := range strings.Split(string(blob), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		var rec gowitnessJSON
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			continue
		}
		out = append(out, rec)
	}
	return out
}

// sanitizeFilename converts a URL into a filesystem-safe stem matching
// gowitness's own convention (scheme stripped, special chars replaced
// with '-'). Keeps reports legible — analysts can recognize a target
// from the attachment filename alone.
func sanitizeFilename(url string) string {
	s := url
	for _, prefix := range []string{"https://", "http://"} {
		if strings.HasPrefix(s, prefix) {
			s = s[len(prefix):]
			break
		}
	}
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '.', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteRune('-')
		}
	}
	out := b.String()
	if out == "" {
		return "screenshot"
	}
	if len(out) > 200 {
		out = out[:200]
	}
	return out
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
