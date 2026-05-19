package githubrepos_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/silvance/golantern/internal/entity"
	"github.com/silvance/golantern/internal/project"
	"github.com/silvance/golantern/internal/run"
	"github.com/silvance/golantern/internal/scan"
	"github.com/silvance/golantern/internal/scan/collectors/githubrepos"
	"github.com/silvance/golantern/internal/scope"
	"github.com/silvance/golantern/internal/store/memory"
	"github.com/silvance/golantern/internal/workflow"
)

// repoStub describes a fake repo as the GitHub API would serialize it.
// Tests pass these; the test server marshals them on the fly so we
// don't drag JSON literals through the file.
type repoStub struct {
	HTMLURL  string `json:"html_url"`
	FullName string `json:"full_name"`
	Fork     bool   `json:"fork"`
	Archived bool   `json:"archived"`
}

// fakeGitHub serves /orgs/{org}/repos with the configured pages. Each
// element of pages is the response for page=N (1-indexed). Beyond
// len(pages) it returns 200 [].
func fakeGitHub(t *testing.T, pages map[string][][]repoStub) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	hits := &atomic.Int32{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		// URL: /orgs/{org}/repos
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		if len(parts) < 3 || parts[0] != "orgs" || parts[2] != "repos" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		org := parts[1]
		all, ok := pages[org]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		pageStr := r.URL.Query().Get("page")
		page, _ := strconv.Atoi(pageStr)
		if page < 1 {
			page = 1
		}
		w.Header().Set("Content-Type", "application/json")
		if page > len(all) {
			_, _ = w.Write([]byte("[]"))
			return
		}
		_ = json.NewEncoder(w).Encode(all[page-1])
	}))
	t.Cleanup(srv.Close)
	return srv, hits
}

func setup(t *testing.T, rules []scope.Rule, defaultScope scope.RuleKind) (*memory.Store, *project.Project, *run.Run, *scan.Runner) {
	t.Helper()
	st := memory.New()
	ctx := context.Background()
	p := &project.Project{Name: "P", DefaultScope: defaultScope, Mode: project.ModeAssessment}
	if err := st.Projects.Save(ctx, p); err != nil {
		t.Fatal(err)
	}
	for _, r := range rules {
		_ = st.Scopes.Add(ctx, &scope.StoredRule{ProjectID: p.ID, Rule: r})
	}
	pol, _ := scope.Compile(p.ID, p.DefaultScope, rules)
	ru := &run.Run{ProjectID: p.ID, Phase: workflow.PhaseAssetDiscovery, Status: run.StatusRunning}
	_ = st.Runs.Save(ctx, ru)
	runner, err := scan.NewRunner(scan.Deps{
		Runs: st.Runs, Entities: st.Entities, Findings: st.Findings, Scope: pol,
	}, nil, st.Audit)
	if err != nil {
		t.Fatal(err)
	}
	return st, p, ru, runner
}

// fullPage returns pageSize+padding repos so the paginator decides
// "more pages exist" (the collector stops when a page is short of 100).
func fullPage(prefix string, n int) []repoStub {
	out := make([]repoStub, n)
	for i := 0; i < n; i++ {
		full := fmt.Sprintf("%s/repo%d", prefix, i)
		out[i] = repoStub{
			HTMLURL:  "https://github.com/" + full,
			FullName: full,
		}
	}
	return out
}

func TestGitHubReposHappyPath(t *testing.T) {
	srv, hits := fakeGitHub(t, map[string][][]repoStub{
		"acme": {
			fullPage("acme", 100), // page 1: full
			{                       // page 2: short -> last page
				{HTMLURL: "https://github.com/acme/last", FullName: "acme/last"},
			},
		},
	})
	st, p, ru, runner := setup(t,
		[]scope.Rule{{Pattern: "acme", Kind: scope.KindPassive}},
		scope.KindPassive,
	)
	c := githubrepos.NewWithClient(srv.Client(), srv.URL)
	tx, err := runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{
		"orgs": []any{"acme"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if tx.Status != run.ToolStatusCompleted {
		t.Fatalf("status=%s err=%q", tx.Status, tx.ErrorSummary)
	}
	// 1 ORG entity + 101 REPO entities = 102 emissions
	if tx.EntitiesEmitted != 102 {
		t.Fatalf("entities_emitted=%d, want 102", tx.EntitiesEmitted)
	}
	// Persisted dedup: 1 ORG + 101 REPO = 102 distinct entities.
	allEnt, _ := st.Entities.ListByProject(context.Background(), p.ID)
	if len(allEnt) != 102 {
		t.Fatalf("persisted=%d, want 102", len(allEnt))
	}
	// Relations: one BELONGS_TO per repo.
	rels, _ := st.Entities.ListRelationsByProject(context.Background(), p.ID)
	if len(rels) != 101 {
		t.Fatalf("relations=%d, want 101", len(rels))
	}
	for _, r := range rels {
		if r.Kind != entity.RelBelongsTo {
			t.Fatalf("relation kind=%s, want belongs_to", r.Kind)
		}
	}
	// Two paged requests.
	if hits.Load() != 2 {
		t.Fatalf("HTTP hits=%d, want 2", hits.Load())
	}
}

func TestGitHubReposFallsBackToOrgEntities(t *testing.T) {
	srv, _ := fakeGitHub(t, map[string][][]repoStub{
		"seeded": {{}}, // empty page
	})
	st, p, ru, runner := setup(t,
		[]scope.Rule{{Pattern: "seeded", Kind: scope.KindPassive}},
		scope.KindPassive,
	)
	// Seed an ORGANIZATION entity; no `orgs` param.
	_, _ = st.Entities.Upsert(context.Background(), p.ID, entity.KindOrganization, "seeded", nil)
	c := githubrepos.NewWithClient(srv.Client(), srv.URL)
	tx, err := runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	if tx.Status != run.ToolStatusCompleted {
		t.Fatalf("status=%s err=%q", tx.Status, tx.ErrorSummary)
	}
}

func TestGitHubReposNoOrgsFails(t *testing.T) {
	srv, _ := fakeGitHub(t, map[string][][]repoStub{})
	_, p, ru, runner := setup(t, nil, scope.KindPassive)
	c := githubrepos.NewWithClient(srv.Client(), srv.URL)
	tx, _ := runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{})
	if tx.Status != run.ToolStatusFailed {
		t.Fatalf("status=%s, want failed", tx.Status)
	}
	if !strings.Contains(tx.ErrorSummary, "no organizations") {
		t.Fatalf("error_summary missing helpful hint: %q", tx.ErrorSummary)
	}
}

func TestGitHubReposForkAndArchivedFiltering(t *testing.T) {
	srv, _ := fakeGitHub(t, map[string][][]repoStub{
		"acme": {{
			{HTMLURL: "https://github.com/acme/normal", FullName: "acme/normal"},
			{HTMLURL: "https://github.com/acme/forked", FullName: "acme/forked", Fork: true},
			{HTMLURL: "https://github.com/acme/old", FullName: "acme/old", Archived: true},
		}},
	})
	st, p, ru, runner := setup(t,
		[]scope.Rule{{Pattern: "acme", Kind: scope.KindPassive}},
		scope.KindPassive,
	)
	c := githubrepos.NewWithClient(srv.Client(), srv.URL)
	tx, _ := runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{
		"orgs": []any{"acme"},
	})
	if tx.Status != run.ToolStatusCompleted {
		t.Fatalf("status=%s err=%q", tx.Status, tx.ErrorSummary)
	}
	// Only the non-fork, non-archived repo plus the ORG entity.
	all, _ := st.Entities.ListByProject(context.Background(), p.ID)
	if len(all) != 2 {
		t.Fatalf("entities=%d, want 2 (1 ORG + 1 REPO)", len(all))
	}

	// Now opt-in to forks and archives — all three repos land.
	st2, p2, ru2, runner2 := setup(t,
		[]scope.Rule{{Pattern: "acme", Kind: scope.KindPassive}},
		scope.KindPassive,
	)
	c2 := githubrepos.NewWithClient(srv.Client(), srv.URL)
	tx2, _ := runner2.Execute(context.Background(), p2.ID, ru2.ID, c2, map[string]any{
		"orgs":             []any{"acme"},
		"include_forks":    true,
		"include_archived": true,
	})
	if tx2.Status != run.ToolStatusCompleted {
		t.Fatalf("status=%s err=%q", tx2.Status, tx2.ErrorSummary)
	}
	all2, _ := st2.Entities.ListByProject(context.Background(), p2.ID)
	if len(all2) != 4 {
		t.Fatalf("entities=%d, want 4 (1 ORG + 3 REPO)", len(all2))
	}
}

func TestGitHubReposOutOfScopeOrgSkipped(t *testing.T) {
	srv, hits := fakeGitHub(t, map[string][][]repoStub{
		"good": {{}}, "bad": {{}},
	})
	_, p, ru, runner := setup(t,
		[]scope.Rule{
			{Pattern: "good", Kind: scope.KindPassive},
			{Pattern: "bad", Kind: scope.KindDeny},
		},
		scope.KindPassive,
	)
	c := githubrepos.NewWithClient(srv.Client(), srv.URL)
	tx, _ := runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{
		"orgs": []any{"good", "bad"},
	})
	if tx.Status != run.ToolStatusCompleted {
		t.Fatalf("status=%s err=%q", tx.Status, tx.ErrorSummary)
	}
	// Only 'good' was queried.
	if hits.Load() != 1 {
		t.Fatalf("hits=%d, want 1 (bad should be skipped)", hits.Load())
	}
}

func TestGitHubRepos404OrgFails(t *testing.T) {
	srv, _ := fakeGitHub(t, map[string][][]repoStub{
		// no entries -> handler returns 404
	})
	_, p, ru, runner := setup(t,
		[]scope.Rule{{Pattern: "ghost", Kind: scope.KindPassive}},
		scope.KindPassive,
	)
	c := githubrepos.NewWithClient(srv.Client(), srv.URL)
	tx, _ := runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{
		"orgs": []any{"ghost"},
	})
	if tx.Status != run.ToolStatusFailed {
		t.Fatalf("status=%s, want failed", tx.Status)
	}
	if !strings.Contains(tx.ErrorSummary, "not found") {
		t.Fatalf("error_summary missing 404 hint: %q", tx.ErrorSummary)
	}
}

func TestGitHubRepos401HasGITHUBTokenHint(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(srv.Close)
	_, p, ru, runner := setup(t,
		[]scope.Rule{{Pattern: "acme", Kind: scope.KindPassive}},
		scope.KindPassive,
	)
	c := githubrepos.NewWithClient(srv.Client(), srv.URL)
	tx, _ := runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{
		"orgs": []any{"acme"},
	})
	if tx.Status != run.ToolStatusFailed {
		t.Fatalf("status=%s, want failed", tx.Status)
	}
	if !strings.Contains(tx.ErrorSummary, "GITHUB_TOKEN") {
		t.Fatalf("error_summary missing token hint: %q", tx.ErrorSummary)
	}
}

func TestGitHubRepos429RetriesThenSucceeds(t *testing.T) {
	attempts := &atomic.Int32{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := attempts.Add(1)
		if n < 2 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"html_url":"https://github.com/acme/r","full_name":"acme/r"}]`))
	}))
	t.Cleanup(srv.Close)
	_, p, ru, runner := setup(t,
		[]scope.Rule{{Pattern: "acme", Kind: scope.KindPassive}},
		scope.KindPassive,
	)
	c := githubrepos.NewWithClient(srv.Client(), srv.URL)
	tx, _ := runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{
		"orgs": []any{"acme"},
	})
	if tx.Status != run.ToolStatusCompleted {
		t.Fatalf("status=%s err=%q (attempts=%d)", tx.Status, tx.ErrorSummary, attempts.Load())
	}
	if attempts.Load() != 2 {
		t.Fatalf("attempts=%d, want 2", attempts.Load())
	}
}

func TestGitHubRepos429ExhaustedFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Retry-After", "0")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	t.Cleanup(srv.Close)
	_, p, ru, runner := setup(t,
		[]scope.Rule{{Pattern: "acme", Kind: scope.KindPassive}},
		scope.KindPassive,
	)
	c := githubrepos.NewWithClient(srv.Client(), srv.URL)
	tx, _ := runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{
		"orgs": []any{"acme"},
	})
	if tx.Status != run.ToolStatusFailed {
		t.Fatalf("status=%s, want failed", tx.Status)
	}
	if !strings.Contains(tx.ErrorSummary, "rate-limited") {
		t.Fatalf("error_summary missing rate-limit hint: %q", tx.ErrorSummary)
	}
}

func TestGitHubReposAuthorizationHeaderSent(t *testing.T) {
	gotAuth := ""
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("[]"))
	}))
	t.Cleanup(srv.Close)
	_, p, ru, runner := setup(t,
		[]scope.Rule{{Pattern: "acme", Kind: scope.KindPassive}},
		scope.KindPassive,
	)
	c := githubrepos.NewWithClient(srv.Client(), srv.URL)
	_, _ = runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{
		"orgs":  []any{"acme"},
		"token": "ghp_secret",
	})
	if gotAuth != "Bearer ghp_secret" {
		t.Fatalf("Authorization header=%q", gotAuth)
	}
}

func TestGitHubReposRepositoryValueCanonicalized(t *testing.T) {
	// Confirm REPOSITORY value gets normalized: the GitHub html_url
	// arrives as "https://github.com/Acme/Repo" but the persisted
	// entity should be "https://github.com/acme/repo" — entity.Canonicalize
	// for KindRepository lowercases path segments.
	srv, _ := fakeGitHub(t, map[string][][]repoStub{
		"acme": {{
			{HTMLURL: "https://github.com/Acme/Repo.git", FullName: "Acme/Repo"},
		}},
	})
	st, p, ru, runner := setup(t,
		[]scope.Rule{{Pattern: "acme", Kind: scope.KindPassive}},
		scope.KindPassive,
	)
	c := githubrepos.NewWithClient(srv.Client(), srv.URL)
	_, _ = runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{
		"orgs": []any{"acme"},
	})
	values, _ := st.Entities.ListValuesByKind(context.Background(), p.ID, entity.KindRepository)
	if len(values) != 1 || values[0] != "https://github.com/acme/repo" {
		t.Fatalf("canonicalization wrong: %v", values)
	}
}
