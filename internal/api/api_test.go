package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/silvance/golantern/internal/audit"
	"github.com/silvance/golantern/internal/project"
	"github.com/silvance/golantern/internal/run"
	"github.com/silvance/golantern/internal/scope"
	"github.com/silvance/golantern/internal/store/memory"
	"github.com/silvance/golantern/internal/workflow"
)

func newTestServer(t *testing.T) (*httptest.Server, *memory.Store) {
	t.Helper()
	st := memory.New()
	srv := httptest.NewServer(New(st.Projects, st.Scopes, st.Runs, st.Audit).Handler())
	t.Cleanup(srv.Close)
	return srv, st
}

func getJSON(t *testing.T, url string, dst any) (int, []byte) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if dst != nil && resp.StatusCode < 300 {
		if err := json.Unmarshal(body, dst); err != nil {
			t.Fatalf("decode %s body=%q: %v", url, string(body), err)
		}
	}
	return resp.StatusCode, body
}

func seedProject(t *testing.T, st *memory.Store) *project.Project {
	t.Helper()
	p := &project.Project{Name: "Acme", DefaultScope: scope.KindPassive, Mode: project.ModeAssessment}
	if err := st.Projects.Save(context.Background(), p); err != nil {
		t.Fatalf("seed project: %v", err)
	}
	return p
}

func TestHealthEndpoint(t *testing.T) {
	srv, _ := newTestServer(t)
	var got map[string]string
	status, _ := getJSON(t, srv.URL+"/healthz", &got)
	if status != 200 || got["status"] != "ok" {
		t.Fatalf("healthz: status=%d body=%v", status, got)
	}
}

func TestListAndGetProject(t *testing.T) {
	srv, st := newTestServer(t)
	p := seedProject(t, st)

	var list []projectDTO
	status, _ := getJSON(t, srv.URL+"/api/v1/projects", &list)
	if status != 200 || len(list) != 1 || list[0].ID != p.ID {
		t.Fatalf("list: status=%d list=%+v", status, list)
	}

	var got projectDTO
	status, _ = getJSON(t, srv.URL+"/api/v1/projects/"+p.ID, &got)
	if status != 200 || got.Name != "Acme" || got.DefaultScope != "passive" {
		t.Fatalf("get: status=%d got=%+v", status, got)
	}
}

func TestGetProjectMissingIs404(t *testing.T) {
	srv, _ := newTestServer(t)
	status, body := getJSON(t, srv.URL+"/api/v1/projects/ghost", nil)
	if status != 404 {
		t.Fatalf("missing project: status=%d body=%s", status, body)
	}
}

func TestListScopeRules(t *testing.T) {
	srv, st := newTestServer(t)
	p := seedProject(t, st)
	for _, pat := range []string{"*.example.com", "api.example.com"} {
		if err := st.Scopes.Add(context.Background(), &scope.StoredRule{
			ProjectID: p.ID, Rule: scope.Rule{Pattern: pat, Kind: scope.KindLightActive},
		}); err != nil {
			t.Fatalf("seed scope: %v", err)
		}
	}
	var rules []scopeRuleDTO
	status, _ := getJSON(t, srv.URL+"/api/v1/projects/"+p.ID+"/scope-rules", &rules)
	if status != 200 || len(rules) != 2 {
		t.Fatalf("status=%d rules=%+v", status, rules)
	}
}

func TestScopeTestEndpoint(t *testing.T) {
	srv, st := newTestServer(t)
	p := seedProject(t, st)
	if err := st.Scopes.Add(context.Background(), &scope.StoredRule{
		ProjectID: p.ID, Rule: scope.Rule{Pattern: "*.example.com", Kind: scope.KindFullActive},
	}); err != nil {
		t.Fatal(err)
	}
	var got map[string]string
	url := srv.URL + "/api/v1/projects/" + p.ID + "/scope/test?target=api.example.com"
	status, _ := getJSON(t, url, &got)
	if status != 200 || got["matched"] != "full_active" {
		t.Fatalf("scope test: status=%d got=%+v", status, got)
	}
}

func TestScopeTestMissingTargetIs400(t *testing.T) {
	srv, st := newTestServer(t)
	p := seedProject(t, st)
	status, _ := getJSON(t, srv.URL+"/api/v1/projects/"+p.ID+"/scope/test", nil)
	if status != 400 {
		t.Fatalf("status=%d, want 400", status)
	}
}

func TestListRunsNewestFirst(t *testing.T) {
	srv, st := newTestServer(t)
	p := seedProject(t, st)
	first := &run.Run{ProjectID: p.ID, Phase: workflow.PhaseOSINT, Status: run.StatusCompleted}
	second := &run.Run{ProjectID: p.ID, Phase: workflow.PhaseAssetDiscovery, Status: run.StatusPending}
	_ = st.Runs.Save(context.Background(), first)
	_ = st.Runs.Save(context.Background(), second)
	var got []runDTO
	status, _ := getJSON(t, srv.URL+"/api/v1/projects/"+p.ID+"/runs", &got)
	if status != 200 || len(got) != 2 {
		t.Fatalf("status=%d got=%+v", status, got)
	}
	if got[0].ID != second.ID {
		t.Fatalf("expected newest first; got[0]=%s want %s", got[0].ID, second.ID)
	}
}

// ----- write-side: scope rules CRUD -----------------------------------

func postJSON(t *testing.T, url string, body any) (int, []byte) {
	t.Helper()
	buf, _ := json.Marshal(body)
	resp, err := http.Post(url, "application/json", bytes.NewReader(buf))
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, out
}

func deleteReq(t *testing.T, url string) int {
	t.Helper()
	req, _ := http.NewRequest(http.MethodDelete, url, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("DELETE %s: %v", url, err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}

func TestCreateScopeRuleExplicitKind(t *testing.T) {
	srv, st := newTestServer(t)
	p := seedProject(t, st)
	status, body := postJSON(t, srv.URL+"/api/v1/projects/"+p.ID+"/scope-rules", map[string]any{
		"pattern": "*.acme.example",
		"kind":    "light_active",
		"note":    "wildcard rule",
	})
	if status != 201 {
		t.Fatalf("status=%d body=%s", status, body)
	}
	var got scopeRuleDTO
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	if got.Pattern != "*.acme.example" || got.Kind != "light_active" {
		t.Fatalf("response wrong: %+v", got)
	}
	// Audit row should exist.
	rows, _ := st.Audit.ListByProject(context.Background(), p.ID)
	if len(rows) != 1 || rows[0].Action != audit.ActionScopeRuleCreated {
		t.Fatalf("audit row missing or wrong: %+v", rows)
	}
	if rows[0].Detail["kind_source"] != "explicit" {
		t.Fatalf("kind_source should be 'explicit', got %v", rows[0].Detail["kind_source"])
	}
}

func TestCreateScopeRuleInfersKindFromMode(t *testing.T) {
	srv, st := newTestServer(t)
	p := &project.Project{Name: "P", DefaultScope: scope.KindPassive, Mode: project.ModeBugBounty}
	if err := st.Projects.Save(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	status, body := postJSON(t, srv.URL+"/api/v1/projects/"+p.ID+"/scope-rules", map[string]any{
		"pattern": "*.example.com",
	})
	if status != 201 {
		t.Fatalf("status=%d body=%s", status, body)
	}
	var got scopeRuleDTO
	json.Unmarshal(body, &got)
	// bug_bounty preset suggests full_active.
	if got.Kind != "full_active" {
		t.Fatalf("mode preset not applied; got kind=%s", got.Kind)
	}
	rows, _ := st.Audit.ListByProject(context.Background(), p.ID)
	if rows[0].Detail["kind_source"] != "mode_preset" {
		t.Fatalf("kind_source should be 'mode_preset'")
	}
}

func TestCreateScopeRuleValidation(t *testing.T) {
	srv, st := newTestServer(t)
	p := seedProject(t, st)
	cases := []struct {
		name string
		body any
		want int
	}{
		{"missing pattern", map[string]any{"kind": "passive"}, 400},
		{"blank pattern", map[string]any{"pattern": "   "}, 400},
		{"bogus kind", map[string]any{"pattern": "x.test", "kind": "bogus"}, 400},
		{"unknown field rejected", map[string]any{"pattern": "x.test", "foo": "bar"}, 400},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			status, _ := postJSON(t, srv.URL+"/api/v1/projects/"+p.ID+"/scope-rules", c.body)
			if status != c.want {
				t.Fatalf("status=%d, want %d", status, c.want)
			}
		})
	}
}

func TestCreateScopeRuleDuplicateIs409(t *testing.T) {
	srv, st := newTestServer(t)
	p := seedProject(t, st)
	url := srv.URL + "/api/v1/projects/" + p.ID + "/scope-rules"
	body := map[string]any{"pattern": "host.example.com", "kind": "light_active"}
	if status, _ := postJSON(t, url, body); status != 201 {
		t.Fatalf("first POST status=%d", status)
	}
	if status, _ := postJSON(t, url, body); status != 409 {
		t.Fatalf("duplicate status=%d, want 409", status)
	}
}

func TestCreateScopeRuleMissingProjectIs404(t *testing.T) {
	srv, _ := newTestServer(t)
	status, _ := postJSON(t, srv.URL+"/api/v1/projects/ghost/scope-rules", map[string]any{
		"pattern": "x.test", "kind": "passive",
	})
	if status != 404 {
		t.Fatalf("status=%d, want 404", status)
	}
}

func TestDeleteScopeRule(t *testing.T) {
	srv, st := newTestServer(t)
	p := seedProject(t, st)
	sr := &scope.StoredRule{ProjectID: p.ID, Rule: scope.Rule{Pattern: "x.test", Kind: scope.KindLightActive}}
	if err := st.Scopes.Add(context.Background(), sr); err != nil {
		t.Fatal(err)
	}
	url := srv.URL + "/api/v1/projects/" + p.ID + "/scope-rules/" + sr.ID
	if got := deleteReq(t, url); got != 204 {
		t.Fatalf("status=%d, want 204", got)
	}
	// Gone.
	rules, _ := st.Scopes.ListByProject(context.Background(), p.ID)
	if len(rules) != 0 {
		t.Fatalf("rule not deleted: %+v", rules)
	}
	// Audit row recorded the deletion.
	rows, _ := st.Audit.ListByProject(context.Background(), p.ID)
	if len(rows) != 1 || rows[0].Action != audit.ActionScopeRuleDeleted {
		t.Fatalf("audit row missing or wrong: %+v", rows)
	}
}

func TestDeleteScopeRuleMissingIs404(t *testing.T) {
	srv, st := newTestServer(t)
	p := seedProject(t, st)
	url := srv.URL + "/api/v1/projects/" + p.ID + "/scope-rules/ghost"
	if got := deleteReq(t, url); got != 404 {
		t.Fatalf("status=%d, want 404", got)
	}
}

func TestDeleteScopeRuleCrossProjectBoundary(t *testing.T) {
	// Rule belongs to project A; DELETE on project B with rule A's id must 404,
	// not silently succeed. This is the cross-project authorization guard.
	srv, st := newTestServer(t)
	a := &project.Project{Name: "A", DefaultScope: scope.KindPassive, Mode: project.ModeCTF}
	b := &project.Project{Name: "B", DefaultScope: scope.KindPassive, Mode: project.ModeCTF}
	for _, p := range []*project.Project{a, b} {
		if err := st.Projects.Save(context.Background(), p); err != nil {
			t.Fatal(err)
		}
	}
	sr := &scope.StoredRule{ProjectID: a.ID, Rule: scope.Rule{Pattern: "x.test", Kind: scope.KindLightActive}}
	_ = st.Scopes.Add(context.Background(), sr)

	url := srv.URL + "/api/v1/projects/" + b.ID + "/scope-rules/" + sr.ID
	if got := deleteReq(t, url); got != 404 {
		t.Fatalf("status=%d, want 404 (cross-project leak!)", got)
	}
	// Ensure the rule still exists under project A.
	rules, _ := st.Scopes.ListByProject(context.Background(), a.ID)
	if len(rules) != 1 {
		t.Fatal("cross-project DELETE was allowed to remove the rule")
	}
}

func TestAuditLogsEndpointReturnsNewestFirst(t *testing.T) {
	srv, st := newTestServer(t)
	p := seedProject(t, st)
	for _, pat := range []string{"a.test", "b.test", "c.test"} {
		if status, body := postJSON(t, srv.URL+"/api/v1/projects/"+p.ID+"/scope-rules",
			map[string]any{"pattern": pat, "kind": "passive"}); status != 201 {
			t.Fatalf("POST %s: %d %s", pat, status, body)
		}
	}
	var rows []auditLogDTO
	status, _ := getJSON(t, srv.URL+"/api/v1/projects/"+p.ID+"/audit-logs", &rows)
	if status != 200 || len(rows) != 3 {
		t.Fatalf("status=%d rows=%+v", status, rows)
	}
	if rows[0].Target != "c.test" {
		t.Fatalf("newest-first violated: %+v", rows)
	}
}

func TestGetRunAndToolExecutions(t *testing.T) {
	srv, st := newTestServer(t)
	p := seedProject(t, st)
	ru := &run.Run{ProjectID: p.ID, Phase: workflow.PhaseOSINT, Status: run.StatusRunning}
	_ = st.Runs.Save(context.Background(), ru)
	tx := &run.ToolExecution{RunID: ru.ID, Tool: "crtsh", Status: run.ToolStatusCompleted, EntitiesEmitted: 3}
	_ = st.Runs.SaveToolExecution(context.Background(), tx)

	var got runDTO
	status, _ := getJSON(t, srv.URL+"/api/v1/runs/"+ru.ID, &got)
	if status != 200 || got.Phase != "osint" {
		t.Fatalf("status=%d got=%+v", status, got)
	}

	var txs []toolExecDTO
	status, _ = getJSON(t, srv.URL+"/api/v1/runs/"+ru.ID+"/tool-executions", &txs)
	if status != 200 || len(txs) != 1 || txs[0].EntitiesEmitted != 3 {
		t.Fatalf("status=%d txs=%+v", status, txs)
	}
}
