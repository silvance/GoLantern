package shodan_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/silvance/golantern/internal/entity"
	"github.com/silvance/golantern/internal/project"
	"github.com/silvance/golantern/internal/run"
	"github.com/silvance/golantern/internal/scan"
	"github.com/silvance/golantern/internal/scan/collectors/shodan"
	"github.com/silvance/golantern/internal/scope"
	"github.com/silvance/golantern/internal/store/memory"
	"github.com/silvance/golantern/internal/workflow"
)

const sampleHost = `{
  "org":"Acme Co","asn":"AS12345","isp":"Acme ISP","country_code":"US",
  "hostnames":["www.example.com"],
  "data":[
    {"port":80,"transport":"tcp","product":"nginx","version":"1.25"},
    {"port":443,"transport":"tcp","product":"nginx","version":"1.25"}
  ]
}`

func setup(t *testing.T) (*memory.Store, *project.Project, *run.Run, *scan.Runner) {
	t.Helper()
	st := memory.New()
	ctx := context.Background()
	p := &project.Project{Name: "P", DefaultScope: scope.KindPassive, Mode: project.ModeAssessment}
	_ = st.Projects.Save(ctx, p)
	rules := []scope.Rule{{Pattern: "10.0.0.0/8", Kind: scope.KindPassive}}
	_ = st.Scopes.Add(ctx, &scope.StoredRule{ProjectID: p.ID, Rule: rules[0]})
	pol, _ := scope.Compile(p.ID, p.DefaultScope, rules)
	ru := &run.Run{ProjectID: p.ID, Phase: workflow.PhaseEnrichment, Status: run.StatusRunning}
	_ = st.Runs.Save(ctx, ru)
	runner, _ := scan.NewRunner(scan.Deps{
		Runs: st.Runs, Entities: st.Entities, Findings: st.Findings, Scope: pol,
	}, nil, st.Audit)
	return st, p, ru, runner
}

func TestShodanHappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/shodan/host/10.0.0.5") {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(sampleHost))
	}))
	t.Cleanup(srv.Close)
	c := shodan.NewWithClient(srv.Client(), srv.URL)
	st, p, ru, runner := setup(t)
	tx, err := runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{
		"ips":     []any{"10.0.0.5"},
		"api_key": "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	if tx.Status != run.ToolStatusCompleted {
		t.Fatalf("status=%s err=%q", tx.Status, tx.ErrorSummary)
	}
	services, _ := st.Entities.ListValuesByKind(context.Background(), p.ID, entity.KindService)
	if len(services) != 2 {
		t.Fatalf("services=%v, want 2", services)
	}
	techs, _ := st.Entities.ListValuesByKind(context.Background(), p.ID, entity.KindTechnology)
	if len(techs) != 1 || techs[0] != "nginx" {
		t.Fatalf("techs=%v, want [nginx]", techs)
	}
}

func TestShodan404IsNoDataEvidence(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)
	c := shodan.NewWithClient(srv.Client(), srv.URL)
	st, p, ru, runner := setup(t)
	tx, _ := runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{
		"ips":     []any{"10.0.0.5"},
		"api_key": "test",
	})
	if tx.Status != run.ToolStatusCompleted {
		t.Fatalf("status=%s", tx.Status)
	}
	// No services were emitted.
	services, _ := st.Entities.ListValuesByKind(context.Background(), p.ID, entity.KindService)
	if len(services) != 0 {
		t.Fatalf("services=%v, want empty", services)
	}
}

func TestShodanMissingKeyFails(t *testing.T) {
	c := shodan.NewWithClient(http.DefaultClient, "http://unused.test")
	_, p, ru, runner := setup(t)
	// Make sure SHODAN_API_KEY env doesn't bleed through.
	t.Setenv("SHODAN_API_KEY", "")
	tx, _ := runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{
		"ips": []any{"10.0.0.5"},
	})
	if tx.Status != run.ToolStatusFailed {
		t.Fatalf("status=%s", tx.Status)
	}
	if !strings.Contains(tx.ErrorSummary, "api_key") {
		t.Fatalf("error_summary missing hint: %q", tx.ErrorSummary)
	}
}
