package emailsec_test

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/silvance/golantern/internal/finding"
	"github.com/silvance/golantern/internal/project"
	"github.com/silvance/golantern/internal/run"
	"github.com/silvance/golantern/internal/scan"
	"github.com/silvance/golantern/internal/scan/collectors/emailsec"
	"github.com/silvance/golantern/internal/scope"
	"github.com/silvance/golantern/internal/store/memory"
	"github.com/silvance/golantern/internal/workflow"
)

// fakeResolver routes lookups via per-name maps. Missing keys return
// a DNS NXDOMAIN-shaped error, mirroring net.Resolver behaviour.
type fakeResolver struct {
	txt map[string][]string
	mx  map[string][]*net.MX
}

func nxdomain(name string) error {
	return &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}

func (f *fakeResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	if v, ok := f.txt[name]; ok {
		return v, nil
	}
	return nil, nxdomain(name)
}

func (f *fakeResolver) LookupMX(_ context.Context, name string) ([]*net.MX, error) {
	if v, ok := f.mx[name]; ok {
		return v, nil
	}
	return nil, nxdomain(name)
}

func setup(t *testing.T) (*memory.Store, *project.Project, *run.Run, *scan.Runner) {
	t.Helper()
	st := memory.New()
	ctx := context.Background()
	p := &project.Project{Name: "P", DefaultScope: scope.KindPassive, Mode: project.ModeAssessment}
	if err := st.Projects.Save(ctx, p); err != nil {
		t.Fatal(err)
	}
	rules := []scope.Rule{{Pattern: "example.com", Kind: scope.KindPassive}}
	for _, r := range rules {
		if err := st.Scopes.Add(ctx, &scope.StoredRule{ProjectID: p.ID, Rule: r}); err != nil {
			t.Fatal(err)
		}
	}
	pol, _ := scope.Compile(p.ID, p.DefaultScope, rules)
	ru := &run.Run{ProjectID: p.ID, Phase: workflow.PhaseExposure, Status: run.StatusRunning}
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

// findFindings returns the titles of all findings persisted for p.
func findingTitles(t *testing.T, st *memory.Store, p *project.Project) []string {
	t.Helper()
	rows, _ := st.Findings.ListFindings(context.Background(), p.ID)
	out := make([]string, 0, len(rows))
	for _, f := range rows {
		out = append(out, f.Title)
	}
	return out
}

// findingByCategory returns the first finding with the given category.
func findingByCategory(t *testing.T, st *memory.Store, p *project.Project, cat string) *finding.Finding {
	t.Helper()
	rows, _ := st.Findings.ListFindings(context.Background(), p.ID)
	for _, f := range rows {
		if f.Category == cat {
			return f
		}
	}
	return nil
}

func TestEmailSecHardPassPosture(t *testing.T) {
	// SPF -all, DMARC reject. No findings expected.
	st, p, ru, runner := setup(t)
	r := &fakeResolver{
		txt: map[string][]string{
			"example.com":        {"v=spf1 include:_spf.google.com -all"},
			"_dmarc.example.com": {"v=DMARC1; p=reject; pct=100"},
		},
		mx: map[string][]*net.MX{
			"example.com": {{Host: "mx.example.com.", Pref: 10}},
		},
	}
	c := emailsec.NewWithResolver(r)
	tx, err := runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{"domain": "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if tx.Status != run.ToolStatusCompleted {
		t.Fatalf("status=%s err=%q", tx.Status, tx.ErrorSummary)
	}
	if titles := findingTitles(t, st, p); len(titles) != 0 {
		t.Fatalf("hard-pass posture should have no findings; got %v", titles)
	}
}

func TestEmailSecMissingSPF(t *testing.T) {
	st, p, ru, runner := setup(t)
	r := &fakeResolver{
		txt: map[string][]string{
			"_dmarc.example.com": {"v=DMARC1; p=reject"},
		},
	}
	c := emailsec.NewWithResolver(r)
	_, _ = runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{"domain": "example.com"})
	f := findingByCategory(t, st, p, "email_spf")
	if f == nil || f.Severity != finding.SeverityHigh {
		t.Fatalf("expected HIGH email_spf finding; got %+v", f)
	}
}

func TestEmailSecPlusAllIsCritical(t *testing.T) {
	st, p, ru, runner := setup(t)
	r := &fakeResolver{
		txt: map[string][]string{
			"example.com":        {"v=spf1 +all"},
			"_dmarc.example.com": {"v=DMARC1; p=reject"},
		},
	}
	c := emailsec.NewWithResolver(r)
	_, _ = runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{"domain": "example.com"})
	f := findingByCategory(t, st, p, "email_spf")
	if f == nil || f.Severity != finding.SeverityCritical {
		t.Fatalf("expected CRITICAL for +all; got %+v", f)
	}
}

func TestEmailSecPermissiveQualMissingOrQuestion(t *testing.T) {
	for _, spf := range []string{
		"v=spf1 include:_spf.test.com", // no `all` mechanism
		"v=spf1 ?all",
	} {
		t.Run(spf, func(t *testing.T) {
			st, p, ru, runner := setup(t)
			r := &fakeResolver{
				txt: map[string][]string{
					"example.com":        {spf},
					"_dmarc.example.com": {"v=DMARC1; p=reject"},
				},
			}
			c := emailsec.NewWithResolver(r)
			_, _ = runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{"domain": "example.com"})
			f := findingByCategory(t, st, p, "email_spf")
			if f == nil || f.Severity != finding.SeverityMedium {
				t.Fatalf("expected MEDIUM permissive finding; got %+v", f)
			}
		})
	}
}

func TestEmailSecSoftFailIsLow(t *testing.T) {
	st, p, ru, runner := setup(t)
	r := &fakeResolver{
		txt: map[string][]string{
			"example.com":        {"v=spf1 ~all"},
			"_dmarc.example.com": {"v=DMARC1; p=reject"},
		},
	}
	c := emailsec.NewWithResolver(r)
	_, _ = runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{"domain": "example.com"})
	f := findingByCategory(t, st, p, "email_spf")
	if f == nil || f.Severity != finding.SeverityLow {
		t.Fatalf("expected LOW for softfail; got %+v", f)
	}
}

func TestEmailSecDMARCMonitorOnly(t *testing.T) {
	st, p, ru, runner := setup(t)
	r := &fakeResolver{
		txt: map[string][]string{
			"example.com":        {"v=spf1 -all"},
			"_dmarc.example.com": {"v=DMARC1; p=none; pct=100"},
		},
	}
	c := emailsec.NewWithResolver(r)
	_, _ = runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{"domain": "example.com"})
	f := findingByCategory(t, st, p, "email_dmarc")
	if f == nil || f.Severity != finding.SeverityMedium {
		t.Fatalf("expected MEDIUM for p=none; got %+v", f)
	}
}

func TestEmailSecDMARCAbsent(t *testing.T) {
	st, p, ru, runner := setup(t)
	r := &fakeResolver{
		txt: map[string][]string{"example.com": {"v=spf1 -all"}},
	}
	c := emailsec.NewWithResolver(r)
	_, _ = runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{"domain": "example.com"})
	f := findingByCategory(t, st, p, "email_dmarc")
	if f == nil || f.Severity != finding.SeverityHigh {
		t.Fatalf("expected HIGH for absent DMARC; got %+v", f)
	}
}

func TestEmailSecDMARCInvalidPolicy(t *testing.T) {
	st, p, ru, runner := setup(t)
	r := &fakeResolver{
		txt: map[string][]string{
			"example.com":        {"v=spf1 -all"},
			"_dmarc.example.com": {"v=DMARC1; pct=100"}, // missing p=
		},
	}
	c := emailsec.NewWithResolver(r)
	_, _ = runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{"domain": "example.com"})
	f := findingByCategory(t, st, p, "email_dmarc")
	if f == nil || f.Severity != finding.SeverityMedium {
		t.Fatalf("expected MEDIUM for missing p=; got %+v", f)
	}
}

func TestEmailSecDKIMSelectorMiss(t *testing.T) {
	st, p, ru, runner := setup(t)
	r := &fakeResolver{
		txt: map[string][]string{
			"example.com":                          {"v=spf1 -all"},
			"_dmarc.example.com":                   {"v=DMARC1; p=reject"},
			"google._domainkey.example.com":        {"v=DKIM1; k=rsa; p=PUBKEY"},
			// "selector1._domainkey.example.com" missing → finding
		},
	}
	c := emailsec.NewWithResolver(r)
	_, _ = runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{
		"domain":         "example.com",
		"dkim_selectors": []any{"google", "selector1"},
	})
	dkimFindings := []string{}
	rows, _ := st.Findings.ListFindings(context.Background(), p.ID)
	for _, f := range rows {
		if f.Category == "email_dkim" {
			dkimFindings = append(dkimFindings, f.Title)
		}
	}
	if len(dkimFindings) != 1 {
		t.Fatalf("expected 1 DKIM miss finding; got %d: %v", len(dkimFindings), dkimFindings)
	}
	// "google" selector should emit an evidence row but not a finding.
	ev, _ := st.Findings.ListEvidence(context.Background(), p.ID)
	var sawGoogleEvidence bool
	for _, e := range ev {
		if sel, _ := e.Payload["selector"].(string); sel == "google" {
			if present, _ := e.Payload["present"].(bool); present {
				sawGoogleEvidence = true
			}
		}
	}
	if !sawGoogleEvidence {
		t.Fatal("google selector hit should produce a `present:true` evidence row")
	}
}

func TestEmailSecOutOfScopeSkipsLookups(t *testing.T) {
	// Project scope excludes the queried domain. The collector must
	// short-circuit before any lookup so no entity / finding / evidence
	// is persisted.
	st := memory.New()
	ctx := context.Background()
	p := &project.Project{Name: "P", DefaultScope: scope.KindDeny, Mode: project.ModeAssessment}
	_ = st.Projects.Save(ctx, p)
	pol, _ := scope.Compile(p.ID, p.DefaultScope, nil)
	// Reachable at default: add a passive rule so the runner's
	// allows_at_default precheck passes, but for a different domain.
	rule := scope.Rule{Pattern: "ok.example", Kind: scope.KindPassive}
	_ = st.Scopes.Add(ctx, &scope.StoredRule{ProjectID: p.ID, Rule: rule})
	pol, _ = scope.Compile(p.ID, p.DefaultScope, []scope.Rule{rule})
	ru := &run.Run{ProjectID: p.ID, Phase: workflow.PhaseExposure, Status: run.StatusRunning}
	_ = st.Runs.Save(ctx, ru)

	runner, _ := scan.NewRunner(scan.Deps{
		Runs: st.Runs, Entities: st.Entities, Findings: st.Findings, Scope: pol,
	}, nil, st.Audit)

	called := false
	r := &fakeResolver{
		txt: map[string][]string{},
	}
	// Wrap with a counting resolver so we can assert no call.
	rw := &countingResolver{inner: r, calls: &called}
	c := emailsec.NewWithResolver(rw)

	tx, err := runner.Execute(ctx, p.ID, ru.ID, c, map[string]any{"domain": "out-of-scope.test"})
	if err != nil {
		t.Fatal(err)
	}
	if tx.Status != run.ToolStatusCompleted {
		t.Fatalf("status=%s", tx.Status)
	}
	if called {
		t.Fatal("resolver should not be called for out-of-scope domain")
	}
	if tx.EntitiesEmitted != 0 {
		t.Fatal("no entity emissions expected")
	}
}

func TestEmailSecRequiresDomainParam(t *testing.T) {
	_, p, ru, runner := setup(t)
	c := emailsec.NewWithResolver(&fakeResolver{})
	tx, _ := runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{})
	if tx.Status != run.ToolStatusFailed {
		t.Fatalf("status=%s, want failed", tx.Status)
	}
}

func TestEmailSecDNSExceptionsTreatedAsAbsent(t *testing.T) {
	// A SERVFAIL-like error on the SPF lookup must be treated as
	// "no record" so the collector still produces the missing-SPF
	// finding rather than crashing the whole run.
	st, p, ru, runner := setup(t)
	r := &errorResolver{err: errors.New("servfail")}
	c := emailsec.NewWithResolver(r)
	tx, _ := runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{"domain": "example.com"})
	if tx.Status != run.ToolStatusCompleted {
		t.Fatalf("status=%s err=%q", tx.Status, tx.ErrorSummary)
	}
	titles := findingTitles(t, st, p)
	if len(titles) < 2 {
		t.Fatalf("expected SPF + DMARC missing findings; got %v", titles)
	}
}

// countingResolver wraps inner and flips called when any method runs.
type countingResolver struct {
	inner Resolver2
	calls *bool
}

// Resolver2 mirrors emailsec.Resolver locally so we don't need to
// re-export it from the package. The methods are identical.
type Resolver2 interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
	LookupMX(ctx context.Context, name string) ([]*net.MX, error)
}

func (c *countingResolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	*c.calls = true
	return c.inner.LookupTXT(ctx, name)
}
func (c *countingResolver) LookupMX(ctx context.Context, name string) ([]*net.MX, error) {
	*c.calls = true
	return c.inner.LookupMX(ctx, name)
}

// errorResolver returns the configured error on every lookup. Used to
// confirm the collector treats DNS failures as "no record" rather than
// crashing.
type errorResolver struct{ err error }

func (e *errorResolver) LookupTXT(context.Context, string) ([]string, error) {
	return nil, e.err
}
func (e *errorResolver) LookupMX(context.Context, string) ([]*net.MX, error) {
	return nil, e.err
}
