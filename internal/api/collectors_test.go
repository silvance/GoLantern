package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/silvance/golantern/internal/project"
	"github.com/silvance/golantern/internal/scan"
	"github.com/silvance/golantern/internal/scan/collectors/fixture"
	"github.com/silvance/golantern/internal/scope"
	"github.com/silvance/golantern/internal/store/memory"
)

func newCollectorsServer(t *testing.T) (*httptest.Server, *memory.Store) {
	t.Helper()
	st := memory.New()
	s := New(st.Projects, st.Scopes, st.Runs, st.Audit)
	reg := scan.NewRegistry()
	reg.Register(fixture.Name, fixture.New)
	s.Registry = reg
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)
	return srv, st
}

func TestListCollectors(t *testing.T) {
	srv, _ := newCollectorsServer(t)
	resp, err := http.Get(srv.URL + "/api/v1/collectors")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status=%d", resp.StatusCode)
	}
	var out []map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 || out[0]["name"] != fixture.Name {
		t.Fatalf("unexpected payload: %+v", out)
	}
	// Sanity: the DTO carries the fields the SPA needs.
	for _, key := range []string{"phase", "required_scope", "description", "parameters"} {
		if _, ok := out[0][key]; !ok {
			t.Errorf("collector DTO missing %q: %+v", key, out[0])
		}
	}
}

func TestListCollectorsUnconfigured(t *testing.T) {
	st := memory.New()
	s := New(st.Projects, st.Scopes, st.Runs, st.Audit)
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/api/v1/collectors")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotImplemented {
		t.Fatalf("status=%d, want 501", resp.StatusCode)
	}
}

func TestRecommendedTools(t *testing.T) {
	srv, st := newCollectorsServer(t)
	p := &project.Project{
		Name:         "P",
		DefaultScope: scope.KindPassive,
		Mode:         project.ModeAssessment,
	}
	if err := st.Projects.Save(context.Background(), p); err != nil {
		t.Fatal(err)
	}

	resp, err := http.Get(srv.URL + "/api/v1/projects/" + p.ID + "/recommended-tools?phase=osint")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status=%d", resp.StatusCode)
	}
	var body struct {
		Phase string   `json:"phase"`
		Mode  string   `json:"mode"`
		Tools []string `json:"tools"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&body)
	if body.Phase != "osint" || body.Mode != "assessment" {
		t.Fatalf("metadata wrong: %+v", body)
	}
	if len(body.Tools) == 0 {
		t.Fatal("expected non-empty tool list for assessment osint")
	}
}

func TestDoctorReportsRegisteredCollectors(t *testing.T) {
	srv, _ := newCollectorsServer(t)
	resp, err := http.Get(srv.URL + "/api/v1/doctor")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status=%d", resp.StatusCode)
	}
	var entries []map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		t.Fatal(err)
	}
	// Fixture has no external binary, so its status should be "no_binary".
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0]["status"] != "no_binary" {
		t.Errorf("fixture collector should be no_binary, got %v", entries[0]["status"])
	}
}

func TestDoctorUnconfigured(t *testing.T) {
	st := memory.New()
	s := New(st.Projects, st.Scopes, st.Runs, st.Audit)
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/api/v1/doctor")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotImplemented {
		t.Fatalf("status=%d, want 501", resp.StatusCode)
	}
}

func TestRecommendedToolsRejectsBadPhase(t *testing.T) {
	srv, st := newCollectorsServer(t)
	p := &project.Project{Name: "P", DefaultScope: scope.KindPassive, Mode: project.ModeAssessment}
	_ = st.Projects.Save(context.Background(), p)

	resp, err := http.Get(srv.URL + "/api/v1/projects/" + p.ID + "/recommended-tools?phase=bogus")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d, want 400", resp.StatusCode)
	}
}
