package censys_test

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
	"github.com/silvance/golantern/internal/scan/collectors/censys"
	"github.com/silvance/golantern/internal/scope"
	"github.com/silvance/golantern/internal/store/memory"
	"github.com/silvance/golantern/internal/workflow"
)

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

const sampleHost = `{"result":{
  "location":{"country":"US"},
  "autonomous_system":{"asn":12345,"name":"Acme"},
  "dns":{"names":["www.example.com"]},
  "services":[
    {"port":80,"transport_protocol":"tcp","service_name":"HTTP","software":[{"product":"nginx"}]},
    {"port":443,"transport_protocol":"tcp","service_name":"HTTPS","software":[{"product":"nginx"}]}
  ]
}}`

func TestCensysHappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/api/v2/hosts/10.0.0.5") {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(sampleHost))
	}))
	t.Cleanup(srv.Close)
	c := censys.NewWithClient(srv.Client(), srv.URL)
	st, p, ru, runner := setup(t)
	_, _ = runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{
		"ips":        []any{"10.0.0.5"},
		"api_id":     "id",
		"api_secret": "secret",
	})
	services, _ := st.Entities.ListValuesByKind(context.Background(), p.ID, entity.KindService)
	if len(services) != 2 {
		t.Fatalf("services=%v", services)
	}
}

func TestCensysMissingCredsFails(t *testing.T) {
	c := censys.NewWithClient(http.DefaultClient, "http://unused.test")
	_, p, ru, runner := setup(t)
	t.Setenv("CENSYS_API_ID", "")
	t.Setenv("CENSYS_API_SECRET", "")
	tx, _ := runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{
		"ips": []any{"10.0.0.5"},
	})
	if tx.Status != run.ToolStatusFailed {
		t.Fatalf("status=%s", tx.Status)
	}
}
