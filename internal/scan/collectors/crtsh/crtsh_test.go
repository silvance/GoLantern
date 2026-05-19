package crtsh_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/silvance/golantern/internal/entity"
	"github.com/silvance/golantern/internal/project"
	"github.com/silvance/golantern/internal/run"
	"github.com/silvance/golantern/internal/scan"
	"github.com/silvance/golantern/internal/scan/collectors/crtsh"
	"github.com/silvance/golantern/internal/scope"
	"github.com/silvance/golantern/internal/store/memory"
	"github.com/silvance/golantern/internal/workflow"
)

// crtshTestSetup builds an in-memory store with a project + scope
// rule, a PENDING run, and a runner wired to the in-memory repos.
// rules controls the project's scope; returns the store, project, run,
// runner so the test can drive Execute directly.
func crtshTestSetup(t *testing.T, rules []scope.Rule, defaultScope scope.RuleKind) (*memory.Store, *project.Project, *run.Run, *scan.Runner) {
	t.Helper()
	st := memory.New()
	ctx := context.Background()
	p := &project.Project{Name: "P", DefaultScope: defaultScope, Mode: project.ModeAssessment}
	if err := st.Projects.Save(ctx, p); err != nil {
		t.Fatal(err)
	}
	for _, r := range rules {
		if err := st.Scopes.Add(ctx, &scope.StoredRule{ProjectID: p.ID, Rule: r}); err != nil {
			t.Fatal(err)
		}
	}
	pol, err := scope.Compile(p.ID, p.DefaultScope, rules)
	if err != nil {
		t.Fatal(err)
	}
	ru := &run.Run{ProjectID: p.ID, Phase: workflow.PhaseAssetDiscovery, Status: run.StatusRunning}
	if err := st.Runs.Save(ctx, ru); err != nil {
		t.Fatal(err)
	}
	runner, err := scan.NewRunner(scan.Deps{
		Runs: st.Runs, Entities: st.Entities, Findings: st.Findings, Scope: pol,
	}, nil, st.Audit)
	if err != nil {
		t.Fatal(err)
	}
	return st, p, ru, runner
}

// newCrtshServer returns an httptest server that responds with the
// supplied entries (JSON-marshalled). Counts each request via reqs.
func newCrtshServer(t *testing.T, entries []map[string]any) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	reqs := &atomic.Int32{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reqs.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(entries)
	}))
	t.Cleanup(srv.Close)
	return srv, reqs
}

func TestCrtshHappyPath(t *testing.T) {
	srv, _ := newCrtshServer(t, []map[string]any{
		{"name_value": "a.example.com\nb.example.com\n*.example.com\nexample.com\nadmin.example.com"},
		{"name_value": "b.example.com\nc.example.com"},
		// Out-of-scope name: should not produce an entity even though
		// it's in the upstream payload. The collector's parser filters
		// on the suffix; out-of-scope filtering for the apex is done
		// via IsInScope on the input domain.
		{"name_value": "stray.other.test"},
	})

	st, p, ru, runner := crtshTestSetup(t,
		[]scope.Rule{{Pattern: "*.example.com", Kind: scope.KindLightActive}, {Pattern: "example.com", Kind: scope.KindLightActive}},
		scope.KindPassive,
	)
	c := crtsh.NewWithClient(srv.Client(), srv.URL)
	tx, err := runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{"domain": "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if tx.Status != run.ToolStatusCompleted {
		t.Fatalf("status=%s err=%q", tx.Status, tx.ErrorSummary)
	}
	// 1 apex domain + 4 subdomains (a, b, c, admin) = 5 emissions
	if tx.EntitiesEmitted != 5 {
		t.Fatalf("entities emitted=%d, want 5", tx.EntitiesEmitted)
	}
	// Persisted dedup: a/b/c/admin = 4 subdomains, plus the apex = 5 entities.
	allEntities, _ := st.Entities.ListByProject(context.Background(), p.ID)
	if len(allEntities) != 5 {
		t.Fatalf("persisted entities=%d, want 5: %+v", len(allEntities), allEntities)
	}
	// Relations: one CHILD_OF per subdomain.
	rels, _ := st.Entities.ListRelationsByProject(context.Background(), p.ID)
	if len(rels) != 4 {
		t.Fatalf("relations=%d, want 4", len(rels))
	}
	for _, r := range rels {
		if r.Kind != entity.RelChildOf {
			t.Fatalf("unexpected kind: %s", r.Kind)
		}
	}
	// Summary evidence row exists (in addition to the per-entity
	// evidence each EmitEntity creates).
	ev, _ := st.Findings.ListEvidence(context.Background(), p.ID)
	var sawSummary bool
	for _, e := range ev {
		if v, _ := e.Payload["subdomain_count"]; v != nil {
			sawSummary = true
			break
		}
	}
	if !sawSummary {
		t.Fatalf("summary evidence row missing: %+v", ev)
	}
}

func TestCrtshRetriesOn503(t *testing.T) {
	attempts := &atomic.Int32{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := attempts.Add(1)
		if n < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]map[string]any{{"name_value": "a.example.com"}})
	}))
	t.Cleanup(srv.Close)

	st, p, ru, runner := crtshTestSetup(t,
		[]scope.Rule{{Pattern: "example.com", Kind: scope.KindLightActive}, {Pattern: "*.example.com", Kind: scope.KindLightActive}},
		scope.KindPassive,
	)
	c := crtsh.NewWithClient(srv.Client(), srv.URL)
	// Short timeout via parameter to keep the test snappy (the
	// backoff timer takes longer than the HTTP RTT inside httptest).
	// We override the package's initialBackoff via the timeout knob
	// indirectly: the request context fires at timeout_seconds and
	// would cancel the backoff sleep early — but we want the retry
	// loop to actually run, so allow generous time.
	tx, err := runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{
		"domain":          "example.com",
		"timeout_seconds": 30.0,
	})
	if err != nil {
		t.Fatal(err)
	}
	if tx.Status != run.ToolStatusCompleted {
		t.Fatalf("status=%s err=%q (attempts=%d)", tx.Status, tx.ErrorSummary, attempts.Load())
	}
	if attempts.Load() != 3 {
		t.Fatalf("attempts=%d, want 3", attempts.Load())
	}
	if tx.EntitiesEmitted != 2 {
		t.Fatalf("entities=%d, want 2", tx.EntitiesEmitted)
	}
	_ = st
}

func TestCrtshExhaustsRetriesAnd5xxLandsAsFailed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	t.Cleanup(srv.Close)

	_, p, ru, runner := crtshTestSetup(t,
		[]scope.Rule{{Pattern: "example.com", Kind: scope.KindLightActive}},
		scope.KindPassive,
	)
	c := crtsh.NewWithClient(srv.Client(), srv.URL)
	// Override the package's initial backoff to keep the test fast
	// via the timeout parameter — the per-request context fires
	// before backoff completes, but the collector's backoff sleep
	// would still take ~14s total without help. Use a 4s budget so
	// the loop's outer context cancels after the first short sleep
	// and the function returns context.DeadlineExceeded which lands
	// the tx as FAILED rather than Completed.
	start := time.Now()
	tx, err := runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{
		"domain":          "example.com",
		"timeout_seconds": 1.0,
	})
	if err != nil {
		t.Fatal(err)
	}
	if tx.Status != run.ToolStatusFailed {
		t.Fatalf("status=%s, want failed", tx.Status)
	}
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Fatalf("test took too long: %v", elapsed)
	}
	_ = p
}

func TestCrtshRequiresDomainParameter(t *testing.T) {
	_, p, ru, runner := crtshTestSetup(t,
		[]scope.Rule{{Pattern: "example.com", Kind: scope.KindLightActive}},
		scope.KindPassive,
	)
	c := crtsh.NewWithClient(http.DefaultClient, "http://unused.test")
	tx, err := runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	if tx.Status != run.ToolStatusFailed {
		t.Fatalf("status=%s, want failed (missing param)", tx.Status)
	}
}

func TestCrtshOutOfScopeDomainSkipsSilently(t *testing.T) {
	// Server returns nothing; we never reach it because IsInScope
	// rejects before fetching.
	called := &atomic.Int32{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called.Add(1)
		_, _ = fmt.Fprint(w, "[]")
	}))
	t.Cleanup(srv.Close)
	_, p, ru, runner := crtshTestSetup(t,
		[]scope.Rule{{Pattern: "only.example.com", Kind: scope.KindLightActive}},
		scope.KindDeny,
	)
	c := crtsh.NewWithClient(srv.Client(), srv.URL)
	tx, err := runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{"domain": "out-of-scope.test"})
	if err != nil {
		t.Fatal(err)
	}
	// Completed (the collector returned nil), but emissions = 0 and
	// the upstream wasn't called.
	if tx.Status != run.ToolStatusCompleted {
		t.Fatalf("status=%s", tx.Status)
	}
	if tx.EntitiesEmitted != 0 {
		t.Fatalf("entities=%d, want 0", tx.EntitiesEmitted)
	}
	if called.Load() != 0 {
		t.Fatalf("upstream called %d times, want 0", called.Load())
	}
}

func TestCrtshIdempotentDomainEmission(t *testing.T) {
	// Two runs over the same data produce the same dedup'd entity
	// graph — the second run is a no-op at the persistence layer.
	srv, _ := newCrtshServer(t, []map[string]any{
		{"name_value": "a.example.com\nb.example.com"},
	})
	st, p, ru, runner := crtshTestSetup(t,
		[]scope.Rule{{Pattern: "example.com", Kind: scope.KindLightActive}, {Pattern: "*.example.com", Kind: scope.KindLightActive}},
		scope.KindPassive,
	)
	c := crtsh.NewWithClient(srv.Client(), srv.URL)
	_, _ = runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{"domain": "example.com"})
	_, _ = runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{"domain": "example.com"})
	got, _ := st.Entities.ListByProject(context.Background(), p.ID)
	if len(got) != 3 { // example.com + a + b
		t.Fatalf("persisted=%d, want 3", len(got))
	}
	rels, _ := st.Entities.ListRelationsByProject(context.Background(), p.ID)
	if len(rels) != 2 {
		t.Fatalf("relations=%d, want 2", len(rels))
	}
}
