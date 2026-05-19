package hibp_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/silvance/golantern/internal/finding"
	"github.com/silvance/golantern/internal/project"
	"github.com/silvance/golantern/internal/run"
	"github.com/silvance/golantern/internal/scan"
	"github.com/silvance/golantern/internal/scan/collectors/hibp"
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
	rules := []scope.Rule{{Pattern: "example.com", Kind: scope.KindPassive}}
	_ = st.Scopes.Add(ctx, &scope.StoredRule{ProjectID: p.ID, Rule: rules[0]})
	pol, _ := scope.Compile(p.ID, p.DefaultScope, rules)
	ru := &run.Run{ProjectID: p.ID, Phase: workflow.PhaseEnrichment, Status: run.StatusRunning}
	_ = st.Runs.Save(ctx, ru)
	runner, _ := scan.NewRunner(scan.Deps{
		Runs: st.Runs, Entities: st.Entities, Findings: st.Findings, Scope: pol,
	}, nil, st.Audit)
	return st, p, ru, runner
}

func TestHIBPEmitsBreachFindingRecent(t *testing.T) {
	// "Recent" breach within last 365 days -> MEDIUM severity.
	recent := time.Now().AddDate(0, -1, 0).Format("2006-01-02")
	body := fmt.Sprintf(`[{"Name":"FooBreach","Title":"Foo Breach","BreachDate":%q,"IsVerified":true,"IsSensitive":false}]`, recent)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	c := hibp.NewWithClient(srv.Client(), srv.URL)
	st, p, ru, runner := setup(t)
	_, err := runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{
		"emails":           []any{"alice@example.com"},
		"api_key":          "test-key",
		"request_delay_ms": 0,
	})
	if err != nil {
		t.Fatal(err)
	}
	findings, _ := st.Findings.ListFindings(context.Background(), p.ID)
	if len(findings) != 1 || findings[0].Severity != finding.SeverityMedium {
		t.Fatalf("findings=%+v, want 1 MEDIUM", findings)
	}
}

func TestHIBPSensitiveIsMedium(t *testing.T) {
	// Old breach but sensitive -> MEDIUM (sensitive flips severity).
	body := `[{"Name":"X","Title":"X","BreachDate":"2010-01-01","IsSensitive":true}]`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	c := hibp.NewWithClient(srv.Client(), srv.URL)
	st, p, ru, runner := setup(t)
	_, _ = runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{
		"emails":           []any{"alice@example.com"},
		"api_key":          "k",
		"request_delay_ms": 0,
	})
	findings, _ := st.Findings.ListFindings(context.Background(), p.ID)
	if findings[0].Severity != finding.SeverityMedium {
		t.Fatalf("sensitive should -> MEDIUM; got %s", findings[0].Severity)
	}
}

func TestHIBPOldNonSensitiveIsLow(t *testing.T) {
	body := `[{"Name":"X","Title":"X","BreachDate":"2010-01-01","IsSensitive":false}]`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	c := hibp.NewWithClient(srv.Client(), srv.URL)
	st, p, ru, runner := setup(t)
	_, _ = runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{
		"emails":           []any{"alice@example.com"},
		"api_key":          "k",
		"request_delay_ms": 0,
	})
	findings, _ := st.Findings.ListFindings(context.Background(), p.ID)
	if findings[0].Severity != finding.SeverityLow {
		t.Fatalf("old+non-sensitive should -> LOW; got %s", findings[0].Severity)
	}
}

func TestHIBP404IsCleanEvidence(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)
	c := hibp.NewWithClient(srv.Client(), srv.URL)
	st, p, ru, runner := setup(t)
	_, _ = runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{
		"emails":           []any{"alice@example.com"},
		"api_key":          "k",
		"request_delay_ms": 0,
	})
	findings, _ := st.Findings.ListFindings(context.Background(), p.ID)
	if len(findings) != 0 {
		t.Fatalf("404 should produce 0 findings; got %+v", findings)
	}
}

func TestHIBPMissingKeyFails(t *testing.T) {
	c := hibp.NewWithClient(http.DefaultClient, "http://unused.test")
	_, p, ru, runner := setup(t)
	t.Setenv("HIBP_API_KEY", "")
	tx, _ := runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{
		"emails": []any{"alice@example.com"},
	})
	if tx.Status != run.ToolStatusFailed {
		t.Fatalf("status=%s", tx.Status)
	}
}
