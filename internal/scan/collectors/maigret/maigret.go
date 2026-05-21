// Package maigret wraps the maigret OSINT tool for username enum.
// Complementary to sherlock: maigret's site database is ~3000 entries
// vs sherlock's ~400, with limited overlap in practice. It also
// harvests profile metadata (avatar URLs, account ages, bios) that
// sherlock skips.
//
// Use sherlock for a fast first pass and maigret when you want depth
// on a high-value handle. The two emit compatible URL entities, so
// dedup is automatic when both run on the same person.
package maigret

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
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
	Name                  = "maigret"
	defaultBinary         = "maigret"
	defaultRequestTimeout = 10
	defaultTotalTimeout   = 900 * time.Second
)

var usernameRE = regexp.MustCompile(`^[A-Za-z0-9_.\-]{1,64}$`)

func New() scan.Collector { return &collector{} }

type runnerFn func(ctx context.Context, spec subprocess.Spec) (subprocess.Result, error)

func newWithRunner(r runnerFn) scan.Collector { return &collector{runner: r} }

type collector struct {
	runner runnerFn
	// readDir is injected by tests so the in-memory stub can return
	// the JSON file maigret would have written. nil in production.
	readDir func(dir string) ([]os.DirEntry, error)
	readFile func(name string) ([]byte, error)
}

func (collector) Metadata() scan.Meta {
	return scan.Meta{
		Name:           Name,
		Phase:          workflow.PhaseOSINT,
		RequiredScope:  scope.KindPassive,
		Description:    "Username enumeration across 3000+ sites via maigret. Deeper coverage than sherlock at the cost of a longer run; also captures profile metadata where available.",
		Consumes:       []entity.Kind{entity.KindPerson},
		Produces:       []entity.Kind{entity.KindPerson, entity.KindURL},
		SourceCategory: finding.SourcePublicOSINT,
		Binary:         "maigret",
		InstallHint:    "pipx install maigret",
		Parameters: []scan.ParameterSpec{
			{Name: "username", Type: "string", Required: true,
				Description: "Handle to look up."},
			{Name: "top_sites", Type: "int", Default: 500,
				Description: "Limit to the top N sites by popularity (1500 ≈ full set; lower = faster)."},
			{Name: "request_timeout_seconds", Type: "int", Default: 10},
			{Name: "total_timeout_seconds", Type: "float", Default: 900.0},
			{Name: "binary", Type: "string", Default: "maigret"},
		},
	}
}

// maigretSimpleJSON is the shape produced by `--json simple`: a flat
// map from site name to record. Unknown fields are tolerated.
type maigretSimpleEntry struct {
	URL        string                 `json:"url_user"`
	Status     string                 `json:"status"`        // "Claimed" / "Available" / "Unknown"
	HTTPStatus int                    `json:"http_status"`
	IDs        map[string]any         `json:"ids"`
	Tags       []string               `json:"tags"`
	Username   string                 `json:"username"`
	Errors     string                 `json:"error"`
}

func (c *collector) Run(ctx context.Context, cctx scan.Context) error {
	username := strings.TrimSpace(toString(cctx.Parameters()["username"]))
	if username == "" {
		return errors.New("maigret: parameter `username` is required")
	}
	if !usernameRE.MatchString(username) {
		return fmt.Errorf("maigret: username %q has unsupported characters; only letters/digits/underscore/dot/dash allowed", username)
	}
	binary := strings.TrimSpace(toString(cctx.Parameters()["binary"]))
	if binary == "" {
		binary = defaultBinary
	}
	requestTimeout := parsePositiveInt(cctx.Parameters()["request_timeout_seconds"], defaultRequestTimeout)
	totalTimeout := parseTimeout(cctx.Parameters()["total_timeout_seconds"])
	topSites := parsePositiveInt(cctx.Parameters()["top_sites"], 500)

	tmp, err := os.MkdirTemp("", "golantern-maigret-")
	if err != nil {
		return fmt.Errorf("maigret: tempdir: %w", err)
	}
	defer os.RemoveAll(tmp)

	args := []string{
		username,
		"--json", "simple",
		"--folderoutput", tmp,
		"--no-color",
		"--no-progressbar",
		"--timeout", strconv.Itoa(requestTimeout),
		"--top-sites", strconv.Itoa(topSites),
	}

	run := c.runner
	if run == nil {
		run = subprocess.Run
	}
	if _, err := run(ctx, subprocess.Spec{
		Binary:         binary,
		Args:           args,
		Timeout:        totalTimeout,
		AllowPartialRC: []int{1},
	}); err != nil {
		return fmt.Errorf("maigret: %w", err)
	}

	jsonPath, err := c.locateJSON(tmp, username)
	if err != nil {
		return err
	}
	readFile := c.readFile
	if readFile == nil {
		readFile = os.ReadFile
	}
	blob, err := readFile(jsonPath)
	if err != nil {
		return fmt.Errorf("maigret: read JSON: %w", err)
	}

	parsed, err := parseSimpleJSON(blob)
	if err != nil {
		return fmt.Errorf("maigret: parse JSON: %w", err)
	}

	if _, err := cctx.EmitEntity(fact.EntityFact{
		Kind:           entity.KindPerson,
		Value:          username,
		Confidence:     finding.ConfidenceMedium,
		SourceCategory: finding.SourcePublicOSINT,
	}); err != nil {
		return err
	}

	hits := 0
	for site, entry := range parsed {
		if !strings.EqualFold(strings.TrimSpace(entry.Status), "claimed") {
			continue
		}
		url := strings.TrimSpace(entry.URL)
		if url == "" {
			continue
		}
		attrs := map[string]any{
			"site":           site,
			"discovered_via": Name,
		}
		if len(entry.IDs) > 0 {
			attrs["profile_ids"] = entry.IDs
		}
		if len(entry.Tags) > 0 {
			attrs["tags"] = entry.Tags
		}
		if _, err := cctx.EmitEntity(fact.EntityFact{
			Kind:           entity.KindURL,
			Value:          url,
			Confidence:     finding.ConfidenceMedium,
			SourceCategory: finding.SourcePublicOSINT,
			Attributes:     attrs,
		}); err != nil {
			return err
		}
		if err := cctx.EmitEvidence(fact.EvidenceFact{
			SourceTool:     Name,
			SourceCategory: finding.SourcePublicOSINT,
			Confidence:     finding.ConfidenceMedium,
			Payload: map[string]any{
				"site":        site,
				"url":         url,
				"http_status": entry.HTTPStatus,
				"username":    username,
				"ids":         entry.IDs,
				"tags":        entry.Tags,
			},
			EntityKind:  entity.KindPerson,
			EntityValue: username,
		}); err != nil {
			return err
		}
		hits++
	}
	return cctx.EmitEvidence(fact.EvidenceFact{
		SourceTool:     Name,
		SourceCategory: finding.SourcePublicOSINT,
		Confidence:     finding.ConfidenceHigh,
		Payload: map[string]any{
			"username":  username,
			"hits":      hits,
			"top_sites": topSites,
		},
	})
}

// locateJSON finds the file maigret wrote. Naming differs between
// versions: report_USERNAME_simple.json (modern), USERNAME.json
// (older). Scan the directory and pick the first .json file matching
// the username.
func (c *collector) locateJSON(dir, username string) (string, error) {
	readDir := c.readDir
	if readDir == nil {
		readDir = os.ReadDir
	}
	entries, err := readDir(dir)
	if err != nil {
		return "", fmt.Errorf("maigret: list output dir: %w", err)
	}
	var best string
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".json") {
			continue
		}
		if !strings.Contains(name, username) {
			continue
		}
		if strings.Contains(name, "_simple.json") {
			return filepath.Join(dir, name), nil
		}
		best = filepath.Join(dir, name)
	}
	if best == "" {
		return "", fmt.Errorf("maigret: no JSON output found in %s", dir)
	}
	return best, nil
}

// parseSimpleJSON accepts either the {site: entry} object shape or a
// list of records keyed by an embedded "sitename" field.
func parseSimpleJSON(blob []byte) (map[string]maigretSimpleEntry, error) {
	out := map[string]maigretSimpleEntry{}
	trimmed := strings.TrimSpace(string(blob))
	if trimmed == "" {
		return out, nil
	}
	if strings.HasPrefix(trimmed, "{") {
		if err := json.Unmarshal(blob, &out); err != nil {
			return nil, err
		}
		return out, nil
	}
	if strings.HasPrefix(trimmed, "[") {
		var arr []struct {
			Sitename string `json:"sitename"`
			maigretSimpleEntry
		}
		if err := json.Unmarshal(blob, &arr); err != nil {
			return nil, err
		}
		for _, e := range arr {
			if e.Sitename == "" {
				continue
			}
			out[e.Sitename] = e.maigretSimpleEntry
		}
		return out, nil
	}
	return nil, fmt.Errorf("unrecognized JSON root %q", trimmed[:1])
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
	return defaultTotalTimeout
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
