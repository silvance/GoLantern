package dnsrecon

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/silvance/golantern/internal/entity"
	"github.com/silvance/golantern/internal/project"
	"github.com/silvance/golantern/internal/run"
	"github.com/silvance/golantern/internal/scan"
	"github.com/silvance/golantern/internal/scope"
	"github.com/silvance/golantern/internal/store/memory"
	"github.com/silvance/golantern/internal/subprocess"
	"github.com/silvance/golantern/internal/workflow"
)

func setup(t *testing.T) (*memory.Store, *project.Project, *run.Run, *scan.Runner) {
	t.Helper()
	st := memory.New()
	ctx := context.Background()
	p := &project.Project{Name: "P", DefaultScope: scope.KindPassive, Mode: project.ModeAssessment}
	_ = st.Projects.Save(ctx, p)
	rules := []scope.Rule{
		{Pattern: "example.com", Kind: scope.KindPassive},
		{Pattern: "*.example.com", Kind: scope.KindPassive},
		{Pattern: "*", Kind: scope.KindPassive}, // allow IPs
	}
	for _, r := range rules {
		_ = st.Scopes.Add(ctx, &scope.StoredRule{ProjectID: p.ID, Rule: r})
	}
	pol, _ := scope.Compile(p.ID, p.DefaultScope, rules)
	ru := &run.Run{ProjectID: p.ID, Phase: workflow.PhaseAssetDiscovery, Status: run.StatusRunning}
	_ = st.Runs.Save(ctx, ru)
	runner, _ := scan.NewRunner(scan.Deps{
		Runs: st.Runs, Entities: st.Entities, Findings: st.Findings, Scope: pol,
	}, nil, st.Audit)
	return st, p, ru, runner
}

// stubRunner emulates dnsrecon by writing the JSON output file the
// real binary would have produced into the -j path.
type stubRunner struct {
	json string
}

func (s *stubRunner) run(_ context.Context, spec subprocess.Spec) (subprocess.Result, error) {
	var jsonPath string
	for i, a := range spec.Args {
		if a == "-j" && i+1 < len(spec.Args) {
			jsonPath = spec.Args[i+1]
		}
	}
	if jsonPath != "" {
		_ = os.MkdirAll(filepath.Dir(jsonPath), 0o755)
		_ = os.WriteFile(jsonPath, []byte(s.json), 0o600)
	}
	return subprocess.Result{}, nil
}

func TestDnsreconParsesRecords(t *testing.T) {
	stub := &stubRunner{json: `[
		{"type": "A", "name": "www.example.com", "address": "1.2.3.4"},
		{"type": "AAAA", "name": "www.example.com", "address": "2001:db8::1"},
		{"type": "MX", "name": "example.com", "exchange": "mail.example.com"},
		{"type": "NS", "name": "example.com", "target": "ns1.example.com"},
		{"type": "A", "name": "out-of-scope.test", "address": "9.9.9.9"}
	]`}
	c := newWithRunner(stub.run)
	st, p, ru, runner := setup(t)
	tx, err := runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{
		"domains": []any{"example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if tx.Status != run.ToolStatusCompleted {
		t.Fatalf("status=%s err=%q", tx.Status, tx.ErrorSummary)
	}
	subs, _ := st.Entities.ListValuesByKind(context.Background(), p.ID, entity.KindSubdomain)
	have := map[string]bool{}
	for _, v := range subs {
		have[v] = true
	}
	for _, want := range []string{"www.example.com", "mail.example.com", "ns1.example.com"} {
		if !have[want] {
			t.Errorf("missing subdomain %q: %v", want, subs)
		}
	}
	ips, _ := st.Entities.ListValuesByKind(context.Background(), p.ID, entity.KindIP)
	haveIP := map[string]bool{}
	for _, v := range ips {
		haveIP[v] = true
	}
	if !haveIP["1.2.3.4"] {
		t.Errorf("missing IP 1.2.3.4: %v", ips)
	}
}

func TestDnsreconAXFRRaisesFinding(t *testing.T) {
	stub := &stubRunner{json: `[
		{"type": "info", "zone_transfer": "success", "name": "example.com"},
		{"type": "A", "name": "internal.example.com", "address": "10.0.0.5"}
	]`}
	c := newWithRunner(stub.run)
	st, p, ru, runner := setup(t)
	_, _ = runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{
		"domains": []any{"example.com"},
	})
	fs, _ := st.Findings.ListFindings(context.Background(), p.ID)
	if len(fs) != 1 {
		t.Fatalf("expected 1 finding for AXFR; got %d", len(fs))
	}
	if fs[0].Category != "dns.zone_transfer" {
		t.Fatalf("wrong category: %s", fs[0].Category)
	}
}

func TestDnsreconNoDomainsFails(t *testing.T) {
	c := newWithRunner((&stubRunner{}).run)
	_, p, ru, runner := setup(t)
	tx, _ := runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{})
	if tx.Status != run.ToolStatusFailed {
		t.Fatalf("status=%s", tx.Status)
	}
}
