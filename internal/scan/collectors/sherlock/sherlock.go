// Package sherlock wraps Sherlock for username enumeration across
// 400+ social/forum/dev platforms. Passive: every check is a plain
// GET against a public URL.
//
// Ported from lantern/tools/sherlock.py.
//
// We deliberately port sherlock as the canonical username-enum
// wrapper and skip maigret / whatsmyname — they target the same
// problem with the same shape (username in, profile URLs out).
package sherlock

import (
	"context"
	"encoding/csv"
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
	Name                   = "sherlock"
	defaultBinary          = "sherlock"
	defaultRequestTimeout  = 10 * time.Second
	defaultTotalTimeout    = 600 * time.Second
)

var usernameRE = regexp.MustCompile(`^[A-Za-z0-9_.\-]{1,64}$`)

func New() scan.Collector { return &collector{} }

type runnerFn func(ctx context.Context, spec subprocess.Spec) (subprocess.Result, error)

func newWithRunner(r runnerFn) scan.Collector { return &collector{runner: r} }

type collector struct{ runner runnerFn }

func (collector) Metadata() scan.Meta {
	return scan.Meta{
		Name:           Name,
		Phase:          workflow.PhaseOSINT,
		RequiredScope:  scope.KindPassive,
		Description:    "Look up a handle across 400+ social/forum/dev platforms via Sherlock.",
		Consumes:       []entity.Kind{entity.KindPerson},
		Produces:       []entity.Kind{entity.KindPerson, entity.KindURL},
		SourceCategory: finding.SourcePublicOSINT,
		Binary:         "sherlock",
		InstallHint:    "pipx install sherlock-project",
		Parameters: []scan.ParameterSpec{
			{Name: "username", Type: "string", Required: true,
				Description: "Handle to look up."},
			{Name: "sites", Type: "string_list",
				Description: "Restrict the lookup to a subset of sites (comma-separated)."},
			{Name: "request_timeout_seconds", Type: "int", Default: 10},
			{Name: "total_timeout_seconds", Type: "float", Default: 600.0},
			{Name: "binary", Type: "string", Default: "sherlock"},
		},
	}
}

func (c *collector) Run(ctx context.Context, cctx scan.Context) error {
	username := strings.TrimSpace(toString(cctx.Parameters()["username"]))
	if username == "" {
		return errors.New("sherlock: parameter `username` is required")
	}
	if !usernameRE.MatchString(username) {
		return fmt.Errorf("sherlock: username %q has unsupported characters; only letters/digits/underscore/dot/dash allowed", username)
	}
	binary := strings.TrimSpace(toString(cctx.Parameters()["binary"]))
	if binary == "" {
		binary = defaultBinary
	}
	requestTimeout := parsePositiveInt(cctx.Parameters()["request_timeout_seconds"], 10)
	totalTimeout := parseTimeout(cctx.Parameters()["total_timeout_seconds"], defaultTotalTimeout)
	sites := parseStringList(cctx.Parameters()["sites"])

	tmp, err := os.MkdirTemp("", "golantern-sherlock-")
	if err != nil {
		return fmt.Errorf("sherlock: tempdir: %w", err)
	}
	defer os.RemoveAll(tmp)

	args := []string{
		"--csv",
		"--folderoutput", tmp,
		"--timeout", strconv.Itoa(requestTimeout),
		"--print-found",
		"--no-color",
	}
	for _, s := range sites {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		args = append(args, "--site", s)
	}
	args = append(args, username)

	run := c.runner
	if run == nil {
		run = subprocess.Run
	}
	if _, err := run(ctx, subprocess.Spec{
		Binary:  binary,
		Args:    args,
		Timeout: totalTimeout,
	}); err != nil {
		return fmt.Errorf("sherlock: %w", err)
	}

	csvPath := filepath.Join(tmp, username+".csv")
	f, err := os.Open(csvPath)
	if err != nil {
		return fmt.Errorf("sherlock: missing CSV at %s: %w", csvPath, err)
	}
	defer f.Close()
	reader := csv.NewReader(f)
	header, err := reader.Read()
	if err != nil {
		return fmt.Errorf("sherlock: read CSV header: %w", err)
	}
	cols := map[string]int{}
	for i, h := range header {
		cols[strings.TrimSpace(h)] = i
	}

	// Make sure the PERSON entity exists.
	if _, err := cctx.EmitEntity(fact.EntityFact{
		Kind:           entity.KindPerson,
		Value:          username,
		Confidence:     finding.ConfidenceMedium,
		SourceCategory: finding.SourcePublicOSINT,
	}); err != nil {
		return err
	}

	hits := 0
	for {
		row, err := reader.Read()
		if err != nil {
			break
		}
		exists := getCol(row, cols, "exists")
		if exists != "Claimed" {
			continue
		}
		url := strings.TrimSpace(getCol(row, cols, "url_user"))
		site := strings.TrimSpace(getCol(row, cols, "name"))
		if url == "" || site == "" {
			continue
		}
		if _, err := cctx.EmitEntity(fact.EntityFact{
			Kind:           entity.KindURL,
			Value:          url,
			Confidence:     finding.ConfidenceMedium,
			SourceCategory: finding.SourcePublicOSINT,
			Attributes:     map[string]any{"site": site, "discovered_via": Name},
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
				"http_status": getCol(row, cols, "http_status"),
				"username":    username,
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
			"username":      username,
			"hits":          hits,
			"sites_queried": len(sites),
		},
	})
}

func getCol(row []string, cols map[string]int, name string) string {
	idx, ok := cols[name]
	if !ok || idx >= len(row) {
		return ""
	}
	return row[idx]
}

func parseTimeout(v any, fallback time.Duration) time.Duration {
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
	return fallback
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
