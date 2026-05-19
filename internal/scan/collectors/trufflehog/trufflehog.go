// Package trufflehog scans known git repositories for committed
// secrets via trufflehog. Raw secret values are never persisted —
// only trufflehog's redacted fingerprint (e.g. AKIA****).
//
// Ported from lantern/tools/trufflehog.py.
package trufflehog

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
	Name           = "trufflehog"
	defaultBinary  = "trufflehog"
	defaultTimeout = 600 * time.Second
	defaultMaxRepos = 25
)

func New() scan.Collector { return &collector{} }

type runnerFn func(ctx context.Context, spec subprocess.Spec) (subprocess.Result, error)

func newWithRunner(r runnerFn) scan.Collector { return &collector{runner: r} }

type collector struct{ runner runnerFn }

func (collector) Metadata() scan.Meta {
	return scan.Meta{
		Name:           Name,
		Phase:          workflow.PhaseEnrichment,
		RequiredScope:  scope.KindPassive,
		Description:    "Scan known git repositories for committed credentials with trufflehog. Raw values are redacted.",
		Consumes:       []entity.Kind{entity.KindRepository},
		SourceCategory: finding.SourcePublicOSINT,
		Binary:         "trufflehog",
		InstallHint:    "curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin",
		Parameters: []scan.ParameterSpec{
			{Name: "repos", Type: "string_list",
				Description: "Repo URLs. Empty falls back to every REPOSITORY entity."},
			{Name: "only_verified", Type: "bool", Default: false,
				Description: "Pass --only-verified so trufflehog drops hits it can't live-verify."},
			{Name: "max_repos", Type: "int", Default: 25},
			{Name: "binary", Type: "string", Default: "trufflehog"},
			{Name: "timeout_seconds", Type: "float", Default: 600.0},
			{Name: "extra_args", Type: "string_list"},
		},
	}
}

// trufflehogJSON is the per-line shape. Raw / RawV2 deliberately not
// fielded — the live secret is dropped on the floor.
type trufflehogJSON struct {
	DetectorName string `json:"DetectorName"`
	DetectorType string `json:"DetectorType"`
	DecoderName  string `json:"DecoderName"`
	Verified     bool   `json:"Verified"`
	Redacted     string `json:"Redacted"`
	SourceMeta   struct {
		Data struct {
			Git struct {
				Repository string `json:"repository"`
				Commit     string `json:"commit"`
				File       string `json:"file"`
				Line       any    `json:"line"`
				Email      string `json:"email"`
				Timestamp  string `json:"timestamp"`
			} `json:"Git"`
		} `json:"Data"`
	} `json:"SourceMetadata"`
}

type hit struct {
	Detector string
	Verified bool
	Redacted string
	Repo     string
	Commit   string
	File     string
	Line     int
	Author   string
}

func (c *collector) Run(ctx context.Context, cctx scan.Context) error {
	binary := strings.TrimSpace(toString(cctx.Parameters()["binary"]))
	if binary == "" {
		binary = defaultBinary
	}
	timeout := parseTimeout(cctx.Parameters()["timeout_seconds"])
	maxRepos := parsePositiveInt(cctx.Parameters()["max_repos"], defaultMaxRepos)
	onlyVerified, _ := cctx.Parameters()["only_verified"].(bool)
	extraArgs := parseStringList(cctx.Parameters()["extra_args"])

	repos, err := c.resolveRepos(cctx)
	if err != nil {
		return err
	}
	var allowed []string
	for _, r := range repos {
		if cctx.IsInScope(r) {
			allowed = append(allowed, r)
		}
	}
	if len(allowed) > maxRepos {
		allowed = allowed[:maxRepos]
	}
	if len(allowed) == 0 {
		return nil
	}

	run := c.runner
	if run == nil {
		run = subprocess.Run
	}

	seen := map[string]struct{}{}
	for _, repo := range allowed {
		args := []string{"git", repo, "--json", "--no-update"}
		if onlyVerified {
			args = append(args, "--only-verified")
		}
		args = append(args, extraArgs...)
		result, err := run(ctx, subprocess.Spec{
			Binary:  binary,
			Args:    args,
			Timeout: timeout,
		})
		if err != nil {
			_ = cctx.EmitEvidence(fact.EvidenceFact{
				SourceTool:     Name,
				SourceCategory: finding.SourcePublicOSINT,
				Confidence:     finding.ConfidenceLow,
				Payload:        map[string]any{"repo": repo, "error": err.Error()},
			})
			continue
		}
		if _, err := cctx.EmitEntity(fact.EntityFact{
			Kind:           entity.KindRepository,
			Value:          repo,
			Confidence:     finding.ConfidenceHigh,
			SourceCategory: finding.SourcePublicOSINT,
		}); err != nil {
			return err
		}
		for _, h := range parseJSONL(result.Stdout, repo) {
			key := fmt.Sprintf("%s|%s|%s|%d", h.Repo, h.Detector, h.File, h.Line)
			if _, dup := seen[key]; dup {
				continue
			}
			seen[key] = struct{}{}
			sev := finding.SeverityMedium
			conf := finding.ConfidenceMedium
			verifiedNote := " (unverified — may be expired or revoked)"
			if h.Verified {
				sev = finding.SeverityHigh
				conf = finding.ConfidenceHigh
				verifiedNote = " (verified live by the upstream service)"
			}
			loc := h.Repo
			if h.File != "" {
				loc = fmt.Sprintf("%s at %s:%d", h.Repo, h.File, h.Line)
			}
			desc := fmt.Sprintf("trufflehog detected a %s credential in %s%s. Redacted form: %s.",
				h.Detector, loc, verifiedNote, h.Redacted)
			if _, err := cctx.EmitFinding(fact.FindingFact{
				Title:      fmt.Sprintf("Leaked %s credential in %s", h.Detector, h.Repo),
				Severity:   sev,
				Confidence: conf,
				Category:   "leaked-credential",
				Description: desc,
				Attributes: map[string]any{
					"detector":  h.Detector,
					"verified":  h.Verified,
					"redacted":  h.Redacted,
					"repository": h.Repo,
					"commit":     h.Commit,
					"file":       h.File,
					"line":       h.Line,
					"author":     h.Author,
				},
				SupportingEntities: []fact.EntityRef{{Kind: entity.KindRepository, Value: h.Repo}},
			}); err != nil {
				return err
			}
		}
	}
	return nil
}

func parseJSONL(blob []byte, fallbackRepo string) []hit {
	var out []hit
	for _, raw := range strings.Split(string(blob), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		var rec trufflehogJSON
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			continue
		}
		if rec.DetectorName == "" {
			continue
		}
		repo := rec.SourceMeta.Data.Git.Repository
		if repo == "" {
			repo = fallbackRepo
		}
		lineNum := 0
		switch n := rec.SourceMeta.Data.Git.Line.(type) {
		case float64:
			lineNum = int(n)
		case string:
			if v, err := parseInt(n); err == nil {
				lineNum = v
			}
		}
		out = append(out, hit{
			Detector: rec.DetectorName,
			Verified: rec.Verified,
			Redacted: rec.Redacted,
			Repo:     repo,
			Commit:   rec.SourceMeta.Data.Git.Commit,
			File:     rec.SourceMeta.Data.Git.File,
			Line:     lineNum,
			Author:   rec.SourceMeta.Data.Git.Email,
		})
	}
	return out
}

func parseInt(s string) (int, error) {
	v := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, errors.New("non-digit")
		}
		v = v*10 + int(r-'0')
	}
	return v, nil
}

func (c *collector) resolveRepos(cctx scan.Context) ([]string, error) {
	explicit := parseStringList(cctx.Parameters()["repos"])
	if len(explicit) > 0 {
		out := make([]string, 0, len(explicit))
		for _, r := range explicit {
			if r = strings.TrimSpace(r); r != "" {
				out = append(out, r)
			}
		}
		if len(out) > 0 {
			return out, nil
		}
	}
	values, err := cctx.ListEntityValues(entity.KindRepository)
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
		return nil, errors.New("trufflehog: no repos; pass parameters[\"repos\"] or seed REPOSITORY entities")
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
