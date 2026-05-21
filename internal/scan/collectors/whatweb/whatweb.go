// Package whatweb wraps the whatweb tech-fingerprint scanner. Has
// ~1800 plugin signatures vs httpx_probe's ProjectDiscovery set;
// catches CMS/framework/server versions that httpx misses.
//
// Emits one TECHNOLOGY entity per matched plugin per URL. Plugin
// versions surface as `name/version` so they dedupe cleanly with
// wpscan's WordPress tech entities.
package whatweb

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
	Name           = "whatweb"
	defaultBinary  = "whatweb"
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
		Description:        "Fingerprint web technologies (CMS, frameworks, servers, plugins) per URL via whatweb's ~1800-plugin signature DB.",
		Consumes:           []entity.Kind{entity.KindURL},
		Produces:           []entity.Kind{entity.KindTechnology},
		SourceCategory:     finding.SourceLiveProbe,
		TriggersOnServices: []string{"http", "https"},
		Binary:             "whatweb",
		InstallHint:        "Fedora: sudo dnf install whatweb (EPEL) — or gem install whatweb\nDebian/Ubuntu: sudo apt install whatweb",
		Parameters: []scan.ParameterSpec{
			{Name: "targets", Type: "string_list", Placeholder: "https://example.com",
				Description: "URLs to fingerprint. Empty falls back to every URL entity."},
			{Name: "aggression", Type: "int", Default: 1,
				Description: "whatweb -a level: 1 stealthy, 3 aggressive (more requests), 4 heavy. Stay at 1 unless you've authorized active probing."},
			{Name: "binary", Type: "string", Default: "whatweb"},
			{Name: "timeout_seconds", Type: "float", Default: 300.0},
		},
	}
}

// whatwebRecord is the shape of one JSON line in whatweb's
// --log-json output. plugins is a map of plugin-name -> arbitrary
// metadata, where the metadata typically contains "string" or
// "version" arrays.
type whatwebRecord struct {
	Target      string                            `json:"target"`
	HTTPStatus  int                               `json:"http_status"`
	RequestConfig any                             `json:"request_config"`
	Plugins     map[string]map[string]any         `json:"plugins"`
}

func (c *collector) Run(ctx context.Context, cctx scan.Context) error {
	binary := strings.TrimSpace(toString(cctx.Parameters()["binary"]))
	if binary == "" {
		binary = defaultBinary
	}
	timeout := parseTimeout(cctx.Parameters()["timeout_seconds"])
	aggression := parsePositiveInt(cctx.Parameters()["aggression"], 1)
	if aggression < 1 {
		aggression = 1
	}
	if aggression > 4 {
		aggression = 4
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

	// whatweb's --log-json-verbose writes one JSON object per line
	// to stdout. --no-errors suppresses connection-error rows that
	// would pollute the output stream.
	args := []string{
		fmt.Sprintf("-a%d", aggression),
		"--log-json-verbose=-",
		"--no-errors",
		"--quiet",
	}
	args = append(args, inScope...)

	run := c.runner
	if run == nil {
		run = subprocess.Run
	}
	result, err := run(ctx, subprocess.Spec{
		Binary:         binary,
		Args:           args,
		Timeout:        timeout,
		AllowPartialRC: []int{1, 2, 3, 4},
	})
	if err != nil {
		return fmt.Errorf("whatweb: %w", err)
	}

	totalTech := 0
	for _, raw := range splitJSONStream(result.Stdout) {
		var rec whatwebRecord
		if err := json.Unmarshal(raw, &rec); err != nil {
			continue
		}
		target := strings.TrimSpace(rec.Target)
		if target == "" {
			continue
		}
		if !cctx.IsInScope(target) {
			continue
		}
		for plugin, meta := range rec.Plugins {
			plugin = strings.TrimSpace(plugin)
			if plugin == "" {
				continue
			}
			versions := extractStringField(meta, "version")
			if len(versions) == 0 {
				// Emit a versionless entity so the operator at least
				// knows the tech is present.
				if _, err := cctx.EmitEntity(fact.EntityFact{
					Kind:           entity.KindTechnology,
					Value:          plugin,
					Attributes:     map[string]any{"discovered_via": Name, "target": target},
					Confidence:     finding.ConfidenceMedium,
					SourceCategory: finding.SourceLiveProbe,
				}); err != nil {
					return err
				}
				totalTech++
				continue
			}
			for _, v := range versions {
				if _, err := cctx.EmitEntity(fact.EntityFact{
					Kind:           entity.KindTechnology,
					Value:          plugin + "/" + v,
					Attributes:     map[string]any{"discovered_via": Name, "target": target, "version": v},
					Confidence:     finding.ConfidenceHigh,
					SourceCategory: finding.SourceLiveProbe,
				}); err != nil {
					return err
				}
				totalTech++
			}
		}
		if err := cctx.EmitEvidence(fact.EvidenceFact{
			SourceTool:     Name,
			SourceCategory: finding.SourceLiveProbe,
			Confidence:     finding.ConfidenceHigh,
			Payload: map[string]any{
				"target":      target,
				"http_status": rec.HTTPStatus,
				"plugins":     pluginNames(rec.Plugins),
				"aggression":  aggression,
			},
			EntityKind:  entity.KindURL,
			EntityValue: target,
		}); err != nil {
			return err
		}
	}
	return cctx.EmitEvidence(fact.EvidenceFact{
		SourceTool:     Name,
		SourceCategory: finding.SourceLiveProbe,
		Confidence:     finding.ConfidenceHigh,
		Payload: map[string]any{
			"targets_scanned": len(inScope),
			"tech_emitted":    totalTech,
			"aggression":      aggression,
		},
	})
}

// splitJSONStream tolerates whatweb's mixed output: it normally
// emits one object per line but older builds wrap the whole run in
// an array. Try array first, then fall back to per-line objects.
func splitJSONStream(blob []byte) [][]byte {
	trimmed := strings.TrimSpace(string(blob))
	if trimmed == "" {
		return nil
	}
	if strings.HasPrefix(trimmed, "[") {
		var arr []json.RawMessage
		if err := json.Unmarshal(blob, &arr); err == nil {
			out := make([][]byte, len(arr))
			for i := range arr {
				out[i] = arr[i]
			}
			return out
		}
	}
	var out [][]byte
	for _, line := range strings.Split(string(blob), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || !strings.HasPrefix(line, "{") {
			continue
		}
		out = append(out, []byte(line))
	}
	return out
}

func extractStringField(meta map[string]any, key string) []string {
	v, ok := meta[key]
	if !ok || v == nil {
		return nil
	}
	switch x := v.(type) {
	case string:
		if x = strings.TrimSpace(x); x != "" {
			return []string{x}
		}
	case []any:
		var out []string
		for _, e := range x {
			if s, ok := e.(string); ok {
				if s = strings.TrimSpace(s); s != "" {
					out = append(out, s)
				}
			}
		}
		return out
	}
	return nil
}

func pluginNames(p map[string]map[string]any) []string {
	out := make([]string, 0, len(p))
	for k := range p {
		out = append(out, k)
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
		return nil, errors.New("whatweb: no targets to scan; pass parameters[\"targets\"] or seed URL entities")
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
