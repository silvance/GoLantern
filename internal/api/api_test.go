package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/silvance/golantern/internal/project"
	"github.com/silvance/golantern/internal/run"
	"github.com/silvance/golantern/internal/scope"
	"github.com/silvance/golantern/internal/store/memory"
	"github.com/silvance/golantern/internal/workflow"
)

func newTestServer(t *testing.T) (*httptest.Server, *memory.Store) {
	t.Helper()
	st := memory.New()
	srv := httptest.NewServer(New(st.Projects, st.Scopes, st.Runs).Handler())
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
