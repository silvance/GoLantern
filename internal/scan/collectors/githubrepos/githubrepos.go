// Package githubrepos enumerates an organization's public repositories
// via the GitHub REST API. Passive asset-discovery: queries
// api.github.com only, never the target.
//
// Ported from lantern/tools/github_repos.py.
//
// Auth: optional. Parameter `token` wins over the GITHUB_TOKEN env var
// (Python uses LANTERN_GITHUB_TOKEN; we accept either to match
// developer ergonomics on machines that already have GITHUB_TOKEN set).
// Without a token GitHub allows 60 requests/hour per IP — fine for a
// one-off small org, trivial to exhaust at scale.
package githubrepos

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/silvance/golantern/internal/entity"
	"github.com/silvance/golantern/internal/fact"
	"github.com/silvance/golantern/internal/finding"
	"github.com/silvance/golantern/internal/scan"
	"github.com/silvance/golantern/internal/scope"
	"github.com/silvance/golantern/internal/workflow"
)

const (
	Name             = "github_repos"
	defaultBaseURL   = "https://api.github.com"
	defaultTimeout   = 30 * time.Second
	defaultMaxPages  = 10
	pageSize         = 100
	maxRetriesPage   = 3
	maxRetryAfterSec = 60.0
)

// New returns a collector using http.DefaultClient and the public
// GitHub API base.
func New() scan.Collector { return NewWithClient(nil, "") }

// NewWithClient lets tests inject a custom HTTP client + base URL.
func NewWithClient(client *http.Client, baseURL string) scan.Collector {
	if client == nil {
		client = http.DefaultClient
	}
	if baseURL == "" {
		baseURL = defaultBaseURL
	}
	return &collector{client: client, baseURL: strings.TrimRight(baseURL, "/")}
}

type collector struct {
	client  *http.Client
	baseURL string
}

func (collector) Metadata() scan.Meta {
	return scan.Meta{
		Name:           Name,
		Phase:          workflow.PhaseAssetDiscovery,
		RequiredScope:  scope.KindPassive,
		Description:    "Enumerate an organization's public repositories via the GitHub REST API.",
		Consumes:       []entity.Kind{entity.KindOrganization},
		Produces:       []entity.Kind{entity.KindRepository},
		SourceCategory: finding.SourcePublicOSINT,
		Parameters: []scan.ParameterSpec{
			{Name: "orgs", Type: "string_list",
				Description: "Org slugs (comma-separated). Empty falls back to existing ORGANIZATION entities."},
			{Name: "token", Type: "string",
				Description: "GitHub PAT. Falls back to $GITHUB_TOKEN. Optional but strongly recommended (60/hr unauth limit)."},
			{Name: "timeout_seconds", Type: "float", Default: 30.0,
				Description: "HTTP timeout per request."},
			{Name: "max_pages", Type: "int", Default: 10,
				Description: "Maximum 100-repo pages per org (caps per-org count at max_pages * 100)."},
			{Name: "include_forks", Type: "bool", Default: false,
				Description: "Include forked repositories."},
			{Name: "include_archived", Type: "bool", Default: false,
				Description: "Include archived repositories."},
		},
		InstallHint: "Uses the GitHub REST API directly; set GITHUB_TOKEN to lift the unauth rate limit.",
	}
}

// repoBody is the subset of /orgs/{org}/repos fields we care about.
type repoBody struct {
	HTMLURL        string `json:"html_url"`
	FullName       string `json:"full_name"`
	DefaultBranch  string `json:"default_branch"`
	Language       string `json:"language"`
	Visibility     string `json:"visibility"`
	Fork           bool   `json:"fork"`
	Archived       bool   `json:"archived"`
	StargazersCount int   `json:"stargazers_count"`
	PushedAt       string `json:"pushed_at"`
}

func (c *collector) Run(ctx context.Context, cctx scan.Context) error {
	token, _ := cctx.Parameters()["token"].(string)
	token = strings.TrimSpace(token)
	if token == "" {
		// Accept either env-var name. Python uses LANTERN_GITHUB_TOKEN;
		// developer machines often already have GITHUB_TOKEN set.
		token = strings.TrimSpace(os.Getenv("LANTERN_GITHUB_TOKEN"))
		if token == "" {
			token = strings.TrimSpace(os.Getenv("GITHUB_TOKEN"))
		}
	}
	timeout := parseTimeout(cctx.Parameters()["timeout_seconds"])
	maxPages := parsePositiveInt(cctx.Parameters()["max_pages"], defaultMaxPages)
	includeForks := parseBool(cctx.Parameters()["include_forks"])
	includeArchived := parseBool(cctx.Parameters()["include_archived"])

	orgs, err := c.resolveOrgs(cctx)
	if err != nil {
		return err
	}

	// Per-org scope. Operators can DENY a specific org without
	// disabling the collector.
	var inScope []string
	for _, o := range orgs {
		if cctx.IsInScope(o) {
			inScope = append(inScope, o)
		}
	}
	skipped := len(orgs) - len(inScope)

	reposEmitted := 0
	for _, org := range inScope {
		repos, err := c.listOrgRepos(ctx, token, org, timeout, maxPages, includeForks, includeArchived)
		if err != nil {
			return fmt.Errorf("github_repos: org %q: %w", org, err)
		}
		if _, err := cctx.EmitEntity(fact.EntityFact{
			Kind:           entity.KindOrganization,
			Value:          org,
			Confidence:     finding.ConfidenceHigh,
			SourceCategory: finding.SourcePublicOSINT,
		}); err != nil {
			return err
		}
		for _, repo := range repos {
			if repo.HTMLURL == "" {
				continue
			}
			if _, err := cctx.EmitEntity(fact.EntityFact{
				Kind:           entity.KindRepository,
				Value:          repo.HTMLURL,
				SourceCategory: finding.SourcePublicOSINT,
				Confidence:     finding.ConfidenceHigh,
				Attributes: map[string]any{
					"full_name":      repo.FullName,
					"default_branch": repo.DefaultBranch,
					"language":       repo.Language,
					"visibility":     repo.Visibility,
					"fork":           repo.Fork,
					"archived":       repo.Archived,
					"stargazers":     repo.StargazersCount,
					"pushed_at":      repo.PushedAt,
				},
			}); err != nil {
				return err
			}
			if err := cctx.EmitRelation(fact.RelationFact{
				Src:  fact.EntityRef{Kind: entity.KindRepository, Value: repo.HTMLURL},
				Dst:  fact.EntityRef{Kind: entity.KindOrganization, Value: org},
				Kind: entity.RelBelongsTo,
			}); err != nil {
				return err
			}
			reposEmitted++
		}
	}

	return cctx.EmitEvidence(fact.EvidenceFact{
		SourceTool:     Name,
		SourceCategory: finding.SourcePublicOSINT,
		Confidence:     finding.ConfidenceHigh,
		Payload: map[string]any{
			"orgs_input":                len(orgs),
			"orgs_skipped_out_of_scope": skipped,
			"orgs_queried":              len(inScope),
			"repos_emitted":             reposEmitted,
			"authenticated":             token != "",
		},
	})
}

// resolveOrgs picks the org list from parameters["orgs"] (if any) or
// falls back to existing ORGANIZATION entities the project already knows.
func (c *collector) resolveOrgs(cctx scan.Context) ([]string, error) {
	explicit := parseStringList(cctx.Parameters()["orgs"])
	if len(explicit) > 0 {
		out := make([]string, 0, len(explicit))
		for _, o := range explicit {
			o = strings.TrimSpace(o)
			if o != "" {
				out = append(out, o)
			}
		}
		if len(out) > 0 {
			return out, nil
		}
	}
	values, err := cctx.ListEntityValues(entity.KindOrganization)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v != "" {
			out = append(out, v)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("github_repos: no organizations to query; pass parameters[\"orgs\"] or seed an ORGANIZATION entity")
	}
	return out, nil
}

func (c *collector) listOrgRepos(
	ctx context.Context, token, org string,
	timeout time.Duration, maxPages int, includeForks, includeArchived bool,
) ([]repoBody, error) {
	var out []repoBody
	for page := 1; page <= maxPages; page++ {
		body, err := c.fetchPage(ctx, token, org, page, timeout)
		if err != nil {
			return nil, err
		}
		for _, r := range body {
			if !includeForks && r.Fork {
				continue
			}
			if !includeArchived && r.Archived {
				continue
			}
			out = append(out, r)
		}
		if len(body) < pageSize {
			break // last page
		}
	}
	return out, nil
}

// fetchPage runs one GET against /orgs/{org}/repos, riding out 429s
// with the server's Retry-After up to maxRetriesPage attempts.
func (c *collector) fetchPage(
	ctx context.Context, token, org string, page int, timeout time.Duration,
) ([]repoBody, error) {
	url := fmt.Sprintf("%s/orgs/%s/repos?per_page=%d&page=%d&type=all",
		c.baseURL, org, pageSize, page)

	for attempt := 0; attempt < maxRetriesPage; attempt++ {
		qctx, cancel := context.WithTimeout(ctx, timeout)
		req, err := http.NewRequestWithContext(qctx, http.MethodGet, url, nil)
		if err != nil {
			cancel()
			return nil, fmt.Errorf("build request: %w", err)
		}
		req.Header.Set("Accept", "application/vnd.github+json")
		req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
		req.Header.Set("User-Agent", "GoLantern/0.1")
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := c.client.Do(req)
		if err != nil {
			cancel()
			return nil, err
		}
		switch resp.StatusCode {
		case http.StatusTooManyRequests:
			// 429 with Retry-After. Wait and retry, up to the cap.
			wait := parseRetryAfter(resp.Header.Get("Retry-After"))
			resp.Body.Close()
			cancel()
			if wait <= 0 || attempt == maxRetriesPage-1 {
				return nil, fmt.Errorf("github rate-limited (HTTP 429) after %d attempts; supply a GITHUB_TOKEN to raise the per-IP cap", attempt+1)
			}
			select {
			case <-time.After(wait):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
			continue
		case http.StatusUnauthorized, http.StatusForbidden:
			snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
			resp.Body.Close()
			cancel()
			return nil, fmt.Errorf("github rejected request (HTTP %d); supply GITHUB_TOKEN to raise the unauth rate limit. Body: %s",
				resp.StatusCode, string(snippet))
		case http.StatusNotFound:
			resp.Body.Close()
			cancel()
			return nil, fmt.Errorf("github org %q not found (404)", org)
		}
		if resp.StatusCode >= 400 {
			snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
			resp.Body.Close()
			cancel()
			return nil, fmt.Errorf("github HTTP %d: %s", resp.StatusCode, string(snippet))
		}
		var body []repoBody
		decErr := json.NewDecoder(resp.Body).Decode(&body)
		resp.Body.Close()
		cancel()
		if decErr != nil {
			return nil, fmt.Errorf("decode: %w", decErr)
		}
		return body, nil
	}
	// Loop exits via return / error inside; this is unreachable.
	return nil, errors.New("github_repos: exhausted retries")
}

// parseRetryAfter honors the Retry-After header in its "seconds" form.
// HTTP-date Retry-After is rare from GitHub; non-numeric values fall
// through to 0 and the caller's own cap takes over.
func parseRetryAfter(v string) time.Duration {
	if v == "" {
		return 0
	}
	secs, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
	if err != nil || secs <= 0 {
		return 0
	}
	if secs > maxRetryAfterSec {
		secs = maxRetryAfterSec
	}
	return time.Duration(secs * float64(time.Second))
}

// ---- parameter coercion helpers --------------------------------------

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

func parseBool(v any) bool {
	b, _ := v.(bool)
	return b
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
