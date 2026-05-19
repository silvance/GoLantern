package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/silvance/golantern/internal/project"
	"github.com/silvance/golantern/internal/run"
	"github.com/silvance/golantern/internal/scope"
	"github.com/silvance/golantern/internal/store/memory"
	"github.com/silvance/golantern/internal/workflow"
)

func setupCancelTest(t *testing.T) (*httptest.Server, *memory.Store, *run.Run) {
	t.Helper()
	st := memory.New()
	p := &project.Project{Name: "P", DefaultScope: scope.KindPassive, Mode: project.ModeAssessment}
	_ = st.Projects.Save(context.Background(), p)
	ru := &run.Run{ProjectID: p.ID, Phase: workflow.PhaseOSINT, Status: run.StatusRunning}
	_ = st.Runs.Save(context.Background(), ru)

	s := New(st.Projects, st.Scopes, st.Runs, st.Audit)
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)
	return srv, st, ru
}

func TestCancelRunningRun(t *testing.T) {
	srv, st, ru := setupCancelTest(t)
	resp, err := http.Post(srv.URL+"/api/v1/runs/"+ru.ID+"/cancel", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status=%d", resp.StatusCode)
	}
	got, _ := st.Runs.Get(context.Background(), ru.ID)
	if got.Status != run.StatusCancelled {
		t.Fatalf("status=%s, want cancelled", got.Status)
	}
	if got.FinishedAt == nil {
		t.Fatal("finished_at should be set")
	}
	// Audit entry written.
	logs, _ := st.Audit.ListByProject(context.Background(), got.ProjectID)
	if len(logs) == 0 || logs[0].Action != "run.cancel_requested" {
		t.Fatalf("audit log not written: %+v", logs)
	}
}

func TestCancelTerminalRunIs409(t *testing.T) {
	srv, _, ru := setupCancelTest(t)
	// First cancel succeeds, second yields 409.
	r1, _ := http.Post(srv.URL+"/api/v1/runs/"+ru.ID+"/cancel", "", nil)
	r1.Body.Close()
	r2, _ := http.Post(srv.URL+"/api/v1/runs/"+ru.ID+"/cancel", "", nil)
	r2.Body.Close()
	if r2.StatusCode != http.StatusConflict {
		t.Fatalf("second cancel status=%d, want 409", r2.StatusCode)
	}
}

func TestCancelMissingRunIs404(t *testing.T) {
	srv, _, _ := setupCancelTest(t)
	resp, _ := http.Post(srv.URL+"/api/v1/runs/ghost/cancel", "", nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status=%d, want 404", resp.StatusCode)
	}
}
