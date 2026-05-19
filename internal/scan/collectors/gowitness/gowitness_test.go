package gowitness

// Tests live in the gowitness package itself so they can use the
// unexported newWithRunner test seam.

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/silvance/golantern/internal/artifact"
	"github.com/silvance/golantern/internal/entity"
	"github.com/silvance/golantern/internal/fact"
	"github.com/silvance/golantern/internal/finding"
	"github.com/silvance/golantern/internal/project"
	"github.com/silvance/golantern/internal/run"
	"github.com/silvance/golantern/internal/scan"
	"github.com/silvance/golantern/internal/scope"
	"github.com/silvance/golantern/internal/store/memory"
	"github.com/silvance/golantern/internal/workflow"
)

// fakePNG is a minimal PNG signature; just enough to round-trip through
// the artifact store and assert the bytes survive intact. The runner
// doesn't decode images, so a valid PNG header followed by junk is fine.
var fakePNG = []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 'p', 'n', 'g'}

// runnerFixture mints a memory store, project, run, filesystem
// artifact store, and a scan.Runner wired with all artifact deps.
func runnerFixture(t *testing.T) (*memory.Store, *project.Project, *run.Run, *scan.Runner) {
	t.Helper()
	st := memory.New()
	ctx := context.Background()
	p := &project.Project{Name: "P", DefaultScope: scope.KindPassive, Mode: project.ModeAssessment}
	if err := st.Projects.Save(ctx, p); err != nil {
		t.Fatal(err)
	}
	if err := st.Scopes.Add(ctx, &scope.StoredRule{
		ProjectID: p.ID,
		Rule:      scope.Rule{Pattern: "*.example.com", Kind: scope.KindLightActive},
	}); err != nil {
		t.Fatal(err)
	}
	pol, _ := scope.Compile(p.ID, p.DefaultScope, []scope.Rule{
		{Pattern: "*.example.com", Kind: scope.KindLightActive},
	})
	ru := &run.Run{ProjectID: p.ID, Phase: workflow.PhaseValidation, Status: run.StatusRunning}
	_ = st.Runs.Save(ctx, ru)
	runner, err := scan.NewRunner(scan.Deps{
		Runs:          st.Runs,
		Entities:      st.Entities,
		Findings:      st.Findings,
		Scope:         pol,
		Artifacts:     st.Artifacts,
		ArtifactStore: artifact.NewFilesystemStore(t.TempDir()),
	}, nil, st.Audit)
	if err != nil {
		t.Fatal(err)
	}
	return st, p, ru, runner
}

// seedURL prefills a URL entity so the collector's "resolve URLs"
// fallback (ListEntityValues) finds it without the caller passing
// `urls` explicitly. Mirrors what httpxprobe leaves behind.
func seedURL(t *testing.T, st *memory.Store, p *project.Project, url string) {
	t.Helper()
	if _, err := st.Entities.Upsert(context.Background(), p.ID, entity.KindURL, url, nil); err != nil {
		t.Fatal(err)
	}
}

// stubRunner builds a runnerFn that writes a fakePNG into the
// screenshotDir for every URL it's given and returns matching JSONL.
// When failFor contains a URL, that URL's record is emitted as a
// failure and no PNG is written.
func stubRunner(t *testing.T, failFor map[string]string) runnerFn {
	t.Helper()
	return func(_ context.Context, _ string, screenshotDir string, urls []string, _ time.Duration, _ []string) ([]byte, error) {
		var lines []string
		for _, u := range urls {
			if reason, fail := failFor[u]; fail {
				lines = append(lines,
					`{"url":"`+u+`","final_url":"`+u+`","failed":true,"failed_reason":"`+reason+`"}`)
				continue
			}
			name := sanitizeFilename(u) + ".png"
			if err := os.WriteFile(filepath.Join(screenshotDir, name), fakePNG, 0o644); err != nil {
				t.Fatal(err)
			}
			lines = append(lines,
				`{"url":"`+u+`","final_url":"`+u+`","title":"Site","response_code":200,"file_name":"`+name+`","failed":false}`)
		}
		// One malformed line to confirm parseJSONL tolerates it.
		lines = append(lines, "not-json")
		return []byte(strings.Join(lines, "\n") + "\n"), nil
	}
}

func TestGowitnessHappyPath(t *testing.T) {
	st, p, ru, runner := runnerFixture(t)
	seedURL(t, st, p, "https://api.example.com")
	seedURL(t, st, p, "https://www.example.com")

	c := newWithRunner(stubRunner(t, nil))
	tx, err := runner.Execute(context.Background(), p.ID, ru.ID, c, nil)
	if err != nil {
		t.Fatal(err)
	}
	if tx.Status != run.ToolStatusCompleted {
		t.Fatalf("status=%s err=%q", tx.Status, tx.ErrorSummary)
	}

	rows, err := st.Artifacts.ListByProject(context.Background(), p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("expected 2 artifact rows, got %d", len(rows))
	}
	for _, a := range rows {
		if a.ContentType != "image/png" {
			t.Errorf("content_type=%q want image/png", a.ContentType)
		}
		if a.SizeBytes != len(fakePNG) {
			t.Errorf("size=%d want %d", a.SizeBytes, len(fakePNG))
		}
		if a.SHA256 != artifact.SHA256(fakePNG) {
			t.Errorf("sha256 mismatch")
		}
		if !strings.HasSuffix(a.Filename, ".png") {
			t.Errorf("filename %q not .png", a.Filename)
		}
	}

	// Evidence rows should reference the artifact URIs.
	evList, err := st.Findings.ListEvidence(context.Background(), p.ID)
	if err != nil {
		t.Fatal(err)
	}
	withURI := 0
	for _, e := range evList {
		if e.ArtifactURI != "" {
			withURI++
		}
	}
	if withURI != 2 {
		t.Fatalf("expected 2 evidence rows with artifact URI, got %d", withURI)
	}
}

func TestGowitnessHandlesFailures(t *testing.T) {
	st, p, ru, runner := runnerFixture(t)
	seedURL(t, st, p, "https://api.example.com")
	seedURL(t, st, p, "https://broken.example.com")

	c := newWithRunner(stubRunner(t, map[string]string{
		"https://broken.example.com": "connection refused",
	}))
	tx, err := runner.Execute(context.Background(), p.ID, ru.ID, c, nil)
	if err != nil {
		t.Fatal(err)
	}
	if tx.Status != run.ToolStatusCompleted {
		t.Fatalf("status=%s err=%q", tx.Status, tx.ErrorSummary)
	}

	rows, _ := st.Artifacts.ListByProject(context.Background(), p.ID)
	if len(rows) != 1 {
		t.Fatalf("expected 1 artifact (only api), got %d", len(rows))
	}
}

func TestGowitnessOutOfScopeFiltered(t *testing.T) {
	st, p, ru, runner := runnerFixture(t)
	// Out-of-scope URL — scope rule only covers *.example.com.
	seedURL(t, st, p, "https://api.notallowed.invalid")

	c := newWithRunner(stubRunner(t, nil))
	tx, err := runner.Execute(context.Background(), p.ID, ru.ID, c, nil)
	if err != nil {
		t.Fatal(err)
	}
	if tx.Status != run.ToolStatusCompleted {
		t.Fatalf("status=%s err=%q", tx.Status, tx.ErrorSummary)
	}
	// All targets out of scope -> zero-emission diagnostic.
	if !strings.Contains(tx.ErrorSummary, "out of scope") {
		t.Fatalf("expected out-of-scope diagnostic, got %q", tx.ErrorSummary)
	}
	rows, _ := st.Artifacts.ListByProject(context.Background(), p.ID)
	if len(rows) != 0 {
		t.Fatalf("expected no artifacts for out-of-scope targets, got %d", len(rows))
	}
}

func TestGowitnessNoTargetsError(t *testing.T) {
	_, p, ru, runner := runnerFixture(t)
	c := newWithRunner(stubRunner(t, nil))
	tx, err := runner.Execute(context.Background(), p.ID, ru.ID, c, nil)
	if err != nil {
		t.Fatal(err)
	}
	if tx.Status != run.ToolStatusFailed {
		t.Fatalf("status=%s, want failed (no targets)", tx.Status)
	}
	if !strings.Contains(tx.ErrorSummary, "no URLs") {
		t.Fatalf("error missing 'no URLs' hint: %q", tx.ErrorSummary)
	}
}

func TestGowitnessExplicitURLsOverrideEntities(t *testing.T) {
	st, p, ru, runner := runnerFixture(t)
	// Entity list has one URL; explicit parameter overrides with a
	// different URL, so only the explicit one should be screenshotted.
	seedURL(t, st, p, "https://entity.example.com")

	c := newWithRunner(stubRunner(t, nil))
	tx, err := runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{
		"urls": []any{"https://explicit.example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if tx.Status != run.ToolStatusCompleted {
		t.Fatalf("status=%s err=%q", tx.Status, tx.ErrorSummary)
	}
	rows, _ := st.Artifacts.ListByProject(context.Background(), p.ID)
	if len(rows) != 1 {
		t.Fatalf("expected 1 artifact, got %d", len(rows))
	}
	if !strings.Contains(rows[0].Filename, "explicit.example.com") {
		t.Fatalf("filename should reference the explicit URL, got %q", rows[0].Filename)
	}
}

func TestGowitnessUnconfiguredArtifactBackend(t *testing.T) {
	// Build a runner WITHOUT artifact deps; StoreArtifact must error.
	st := memory.New()
	ctx := context.Background()
	p := &project.Project{Name: "P", DefaultScope: scope.KindPassive, Mode: project.ModeAssessment}
	_ = st.Projects.Save(ctx, p)
	_ = st.Scopes.Add(ctx, &scope.StoredRule{
		ProjectID: p.ID,
		Rule:      scope.Rule{Pattern: "*.example.com", Kind: scope.KindLightActive},
	})
	pol, _ := scope.Compile(p.ID, p.DefaultScope, []scope.Rule{
		{Pattern: "*.example.com", Kind: scope.KindLightActive},
	})
	ru := &run.Run{ProjectID: p.ID, Phase: workflow.PhaseValidation, Status: run.StatusRunning}
	_ = st.Runs.Save(ctx, ru)
	runner, err := scan.NewRunner(scan.Deps{
		Runs: st.Runs, Entities: st.Entities, Findings: st.Findings, Scope: pol,
	}, nil, st.Audit)
	if err != nil {
		t.Fatal(err)
	}
	seedURL(t, st, p, "https://api.example.com")

	c := newWithRunner(stubRunner(t, nil))
	tx, err := runner.Execute(ctx, p.ID, ru.ID, c, nil)
	if err != nil {
		t.Fatal(err)
	}
	if tx.Status != run.ToolStatusFailed {
		t.Fatalf("status=%s, want failed (unconfigured)", tx.Status)
	}
	if !strings.Contains(tx.ErrorSummary, "artifact storage not configured") {
		t.Fatalf("expected unconfigured hint, got %q", tx.ErrorSummary)
	}
}

func TestSanitizeFilename(t *testing.T) {
	cases := map[string]string{
		"https://api.example.com":       "api.example.com",
		"http://example.com/path?x=1":   "example.com-path-x-1",
		"":                              "screenshot",
		"https://" + strings.Repeat("a", 300): strings.Repeat("a", 200),
	}
	for in, want := range cases {
		if got := sanitizeFilename(in); got != want {
			t.Errorf("sanitizeFilename(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseJSONLSkipsGarbage(t *testing.T) {
	blob := []byte(`{"url":"https://a","file_name":"a.png"}
not-json
{"url":"https://b","file_name":"b.png","failed":true}
`)
	got := parseJSONL(blob)
	if len(got) != 2 {
		t.Fatalf("parseJSONL got %d records, want 2", len(got))
	}
	if got[0].URL != "https://a" || got[1].Failed != true {
		t.Fatalf("unexpected parse: %+v", got)
	}
}

// Make sure the Meta is consistent with what the engine expects.
func TestMetadata(t *testing.T) {
	m := (collector{}).Metadata()
	if m.Name != Name {
		t.Fatalf("name=%q", m.Name)
	}
	if m.Phase != workflow.PhaseValidation {
		t.Fatalf("phase=%s", m.Phase)
	}
	if m.RequiredScope != scope.KindLightActive {
		t.Fatalf("required_scope=%s", m.RequiredScope)
	}
	if m.SourceCategory != finding.SourceLiveProbe {
		t.Fatalf("source_category=%s", m.SourceCategory)
	}
	// Sanity that the entity kind references compile-link with the
	// fact package — keeps a future refactor of fact.EntityRef from
	// silently breaking the metadata.
	_ = fact.EntityRef{Kind: entity.KindURL, Value: "x"}
}
