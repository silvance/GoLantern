package whois

import (
	"context"
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
	rules := []scope.Rule{{Pattern: "example.com", Kind: scope.KindPassive}}
	for _, r := range rules {
		_ = st.Scopes.Add(ctx, &scope.StoredRule{ProjectID: p.ID, Rule: r})
	}
	pol, _ := scope.Compile(p.ID, p.DefaultScope, rules)
	ru := &run.Run{ProjectID: p.ID, Phase: workflow.PhaseEnrichment, Status: run.StatusRunning}
	_ = st.Runs.Save(ctx, ru)
	runner, _ := scan.NewRunner(scan.Deps{
		Runs: st.Runs, Entities: st.Entities, Findings: st.Findings, Scope: pol,
	}, nil, st.Audit)
	return st, p, ru, runner
}

type stubRunner struct {
	stdout string
}

func (s *stubRunner) run(_ context.Context, spec subprocess.Spec) (subprocess.Result, error) {
	_ = spec
	return subprocess.Result{Stdout: []byte(s.stdout)}, nil
}

const sampleWhois = `% IANA WHOIS server

Domain Name: EXAMPLE.COM
Registry Domain ID: 2336799_DOMAIN_COM-VRSN
Registrar WHOIS Server: whois.iana.org
Registrar URL: http://res-dom.iana.org
Updated Date: 2024-08-14T07:01:34Z
Creation Date: 1995-08-14T04:00:00Z
Registry Expiry Date: 2025-08-13T04:00:00Z
Registrar: RESERVED-Internet Assigned Numbers Authority
Registrar Abuse Contact Email: abuse@iana.org
Domain Status: clientDeleteProhibited
Domain Status: clientTransferProhibited
Registrant Organization: Internet Assigned Numbers Authority
Name Server: A.IANA-SERVERS.NET
Name Server: B.IANA-SERVERS.NET
`

func TestWhoisHappyPath(t *testing.T) {
	stub := &stubRunner{stdout: sampleWhois}
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
	// Domain entity should land with registrar/creation/expiry attributes.
	domains, _ := st.Entities.ListByProject(context.Background(), p.ID)
	var d *entity.Entity
	for _, e := range domains {
		if e.Kind == entity.KindDomain && e.Value == "example.com" {
			d = e
			break
		}
	}
	if d == nil {
		t.Fatal("domain entity not emitted")
	}
	if d.Attributes["registrar"] == nil {
		t.Errorf("registrar not parsed; attrs=%v", d.Attributes)
	}
	if d.Attributes["creation_date"] == nil {
		t.Errorf("creation_date not parsed; attrs=%v", d.Attributes)
	}
	if d.Attributes["registrant_org"] == nil {
		t.Errorf("registrant_org not parsed; attrs=%v", d.Attributes)
	}
	ns, _ := d.Attributes["nameservers"].([]string)
	if len(ns) != 2 {
		t.Errorf("expected 2 nameservers; got %v", ns)
	}
	// Registrant org should also land as its own entity.
	orgs, _ := st.Entities.ListValuesByKind(context.Background(), p.ID, entity.KindOrganization)
	if len(orgs) != 1 {
		t.Fatalf("expected 1 org entity; got %v", orgs)
	}
}

func TestWhoisIgnoresCommentLines(t *testing.T) {
	got := parseWhois("% comment\n# also comment\nRegistrar: Acme\n")
	if got.Registrar != "Acme" {
		t.Fatalf("registrar=%q", got.Registrar)
	}
}

func TestWhoisNoDomainsFails(t *testing.T) {
	c := newWithRunner((&stubRunner{}).run)
	_, p, ru, runner := setup(t)
	tx, _ := runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{})
	if tx.Status != run.ToolStatusFailed {
		t.Fatalf("status=%s", tx.Status)
	}
}
