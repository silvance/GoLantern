package cloudbucket

import (
	"context"
	"testing"

	"github.com/silvance/golantern/internal/entity"
	"github.com/silvance/golantern/internal/finding"
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
	pol, _ := scope.Compile(p.ID, p.DefaultScope, nil)
	ru := &run.Run{ProjectID: p.ID, Phase: workflow.PhaseEnrichment, Status: run.StatusRunning}
	_ = st.Runs.Save(ctx, ru)
	runner, _ := scan.NewRunner(scan.Deps{
		Runs: st.Runs, Entities: st.Entities, Findings: st.Findings, Scope: pol,
	}, nil, st.Audit)
	return st, p, ru, runner
}

type stubRunner struct {
	stdout string
	stdin  []byte
}

func (s *stubRunner) run(_ context.Context, spec subprocess.Spec) (subprocess.Result, error) {
	s.stdin = append([]byte(nil), spec.Stdin...)
	return subprocess.Result{Stdout: []byte(s.stdout)}, nil
}

func TestCloudBucketPublicReadCritical(t *testing.T) {
	stub := &stubRunner{stdout: `
{"name":"acme-prod","exists":true,"region":"us-east-1","provider":"aws","permissions":{"all_users":{"read":true}}}
{"name":"acme-private","exists":true,"provider":"aws","permissions":{}}
{"name":"acme-write","exists":true,"provider":"aws","permissions":{"all_users":{"read":true,"write":true}}}
{"name":"does-not-exist","exists":false}
`}
	c := newWithRunner(stub.run)
	st, p, ru, runner := setup(t)
	tx, err := runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{
		"candidates": []any{"acme-prod", "acme-private", "acme-write", "does-not-exist"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if tx.Status != run.ToolStatusCompleted {
		t.Fatalf("status=%s err=%q", tx.Status, tx.ErrorSummary)
	}
	// Three buckets exist; one rejected.
	buckets, _ := st.Entities.ListValuesByKind(context.Background(), p.ID, entity.KindCloudBucket)
	if len(buckets) != 3 {
		t.Fatalf("expected 3 cloud bucket entities; got %d (%v)", len(buckets), buckets)
	}
	// Findings: acme-prod (READ, Critical for public), acme-write (Critical for WRITE).
	// acme-private has no permissions, no finding.
	fs, _ := st.Findings.ListFindings(context.Background(), p.ID)
	if len(fs) != 2 {
		t.Fatalf("expected 2 findings; got %d: %+v", len(fs), fs)
	}
	for _, f := range fs {
		if f.Severity != finding.SeverityCritical {
			t.Fatalf("expected critical for public bucket exposure; got %s on %q", f.Severity, f.Title)
		}
	}
}

func TestCloudBucketSeedsFromOrgEntities(t *testing.T) {
	stub := &stubRunner{stdout: ""}
	c := newWithRunner(stub.run)
	st, p, ru, runner := setup(t)
	_, _ = st.Entities.Upsert(context.Background(), p.ID, entity.KindOrganization, "acme corp", nil)
	_, _ = runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{})
	got := string(stub.stdin)
	if got == "" {
		t.Fatal("expected stdin to receive candidate names; got empty")
	}
	// "Acme Corp" -> "acme-corp" + derived variants.
	for _, want := range []string{"acme-corp", "acme-corp-prod", "acme-corp-backup"} {
		if !contains(got, want) {
			t.Fatalf("expected %q in candidates; got %q", want, got)
		}
	}
}

func TestCloudBucketAuthUsersHigh(t *testing.T) {
	stub := &stubRunner{stdout: `
{"name":"acme-auth","exists":true,"provider":"aws","permissions":{"auth_users":{"read":true}}}
`}
	c := newWithRunner(stub.run)
	st, p, ru, runner := setup(t)
	_, _ = runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{
		"candidates": []any{"acme-auth"},
	})
	fs, _ := st.Findings.ListFindings(context.Background(), p.ID)
	if len(fs) != 1 {
		t.Fatalf("expected 1 finding; got %d", len(fs))
	}
	if fs[0].Severity != finding.SeverityHigh {
		t.Fatalf("AuthUsers READ-only should be High; got %s", fs[0].Severity)
	}
}

func TestCloudBucketNoCandidatesFails(t *testing.T) {
	c := newWithRunner((&stubRunner{}).run)
	_, p, ru, runner := setup(t)
	tx, _ := runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{})
	if tx.Status != run.ToolStatusFailed {
		t.Fatalf("status=%s", tx.Status)
	}
}

func TestSanitizeName(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"Acme Corp", "acme-corp"},
		{"acme_prod", "acme-prod"},
		{"ACME.com", "acme-com"},
		{"a", ""},  // too short
		{"-acme-", "acme"},
		{"a!b@c#", "abc"}, // special chars stripped, "abc" hits the 3-char minimum
		{"x!", ""},        // becomes "x", too short
	}
	for _, c := range cases {
		got := sanitizeName(c.in)
		if got != c.want {
			t.Errorf("sanitizeName(%q) = %q; want %q", c.in, got, c.want)
		}
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (haystack == needle ||
		(len(haystack) > len(needle) && indexOf(haystack, needle) >= 0))
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
