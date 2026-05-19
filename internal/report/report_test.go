package report_test

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"strings"
	"testing"

	"github.com/silvance/golantern/internal/entity"
	"github.com/silvance/golantern/internal/finding"
	"github.com/silvance/golantern/internal/project"
	"github.com/silvance/golantern/internal/report"
	"github.com/silvance/golantern/internal/run"
	"github.com/silvance/golantern/internal/scope"
	"github.com/silvance/golantern/internal/store/memory"
	"github.com/silvance/golantern/internal/workflow"
)

// reportFixture seeds a store with a project, three findings (one of
// each interesting severity), a few entities of different kinds, two
// evidence rows attached to the critical finding, and two runs. The
// shape exercises grouping, severity sort, kind ordering, and the
// "entities present even when a kind has zero rows" invariant.
func reportFixture(t *testing.T) (*memory.Store, *project.Project) {
	t.Helper()
	st := memory.New()
	ctx := context.Background()
	p := &project.Project{Name: "RPT", DefaultScope: scope.KindLightActive, Mode: project.ModeBugBounty}
	if err := st.Projects.Save(ctx, p); err != nil {
		t.Fatal(err)
	}
	mustEntity := func(k entity.Kind, v string) string {
		id, err := st.Entities.Upsert(ctx, p.ID, k, entity.Canonicalize(k, v), nil)
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	mustEntity(entity.KindDomain, "a.example.com")
	mustEntity(entity.KindDomain, "b.example.com")
	mustEntity(entity.KindIP, "192.0.2.5")

	criticalFinding := &finding.Finding{
		ProjectID: p.ID, Title: "Critical issue", Severity: finding.SeverityCritical,
		Confidence: finding.ConfidenceHigh, Category: "auth",
		Description: "Reset endpoint accepts arbitrary tokens.",
	}
	mediumFinding := &finding.Finding{
		ProjectID: p.ID, Title: "Medium issue", Severity: finding.SeverityMedium,
		Confidence: finding.ConfidenceMedium,
	}
	infoFinding := &finding.Finding{
		ProjectID: p.ID, Title: "Informational", Severity: finding.SeverityInfo,
		Confidence: finding.ConfidenceLow,
	}
	for _, f := range []*finding.Finding{infoFinding, mediumFinding, criticalFinding} {
		if err := st.Findings.CreateFinding(ctx, f); err != nil {
			t.Fatal(err)
		}
	}

	// Two evidence rows on the critical finding to verify per-finding grouping.
	for i := 0; i < 2; i++ {
		if err := st.Findings.CreateEvidence(ctx, &finding.Evidence{
			ProjectID:      p.ID,
			FindingID:      criticalFinding.ID,
			SourceTool:     "fixture",
			SourceCategory: finding.SourceActiveScan,
			Confidence:     finding.ConfidenceHigh,
			Payload:        map[string]any{"step": i},
		}); err != nil {
			t.Fatal(err)
		}
	}

	for _, ph := range []workflow.Phase{workflow.PhaseOSINT, workflow.PhaseValidation} {
		if err := st.Runs.Save(ctx, &run.Run{
			ProjectID: p.ID, Phase: ph, Status: run.StatusCompleted,
		}); err != nil {
			t.Fatal(err)
		}
	}
	return st, p
}

func deps(st *memory.Store) report.Deps {
	return report.Deps{
		Projects: st.Projects,
		Entities: st.Entities,
		Findings: st.Findings,
		Runs:     st.Runs,
		Audit:    st.Audit,
	}
}

func TestGenerateAssemblesBundle(t *testing.T) {
	st, p := reportFixture(t)
	b, err := report.Generate(context.Background(), deps(st), p.ID, report.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if b.Project.Name != "RPT" || b.Project.ReportTemplate != "bug_bounty" {
		t.Fatalf("project view wrong: %+v", b.Project)
	}
	if b.Summary.EntitiesTotal != 3 || b.Summary.FindingsTotal != 3 || b.Summary.RunsTotal != 2 {
		t.Fatalf("summary wrong: %+v", b.Summary)
	}
	// Severity sort: critical first, info last.
	if b.Findings[0].Severity != "critical" || b.Findings[len(b.Findings)-1].Severity != "info" {
		var got []string
		for _, f := range b.Findings {
			got = append(got, f.Severity)
		}
		t.Fatalf("severity sort wrong: %v", got)
	}
	// Evidence grouped per finding; critical has 2, the others have 0.
	if len(b.Findings[0].Evidence) != 2 {
		t.Fatalf("critical evidence = %d, want 2", len(b.Findings[0].Evidence))
	}
	for _, f := range b.Findings[1:] {
		if len(f.Evidence) != 0 {
			t.Fatalf("non-critical finding has unexpected evidence: %+v", f)
		}
	}
	// All known entity kinds present (empty slice when nothing landed).
	for _, kind := range []string{"domain", "ip", "url", "email", "subdomain", "person"} {
		if _, ok := b.EntitiesByKind[kind]; !ok {
			t.Fatalf("EntitiesByKind missing %q", kind)
		}
	}
	if len(b.EntitiesByKind["domain"]) != 2 {
		t.Fatalf("domain entities = %d, want 2", len(b.EntitiesByKind["domain"]))
	}
}

func TestGenerateMissingProject(t *testing.T) {
	st := memory.New()
	if _, err := report.Generate(context.Background(), deps(st), "ghost", report.Options{}); err == nil {
		t.Fatal("expected error for missing project")
	}
}

func TestRenderHTMLEscapesAndIncludesData(t *testing.T) {
	// Inject an unsafe-looking title and confirm it's escaped.
	st, p := reportFixture(t)
	if err := st.Findings.CreateFinding(context.Background(), &finding.Finding{
		ProjectID:  p.ID,
		Title:      "<script>alert(1)</script>",
		Severity:   finding.SeverityHigh,
		Confidence: finding.ConfidenceMedium,
	}); err != nil {
		t.Fatal(err)
	}
	b, _ := report.Generate(context.Background(), deps(st), p.ID, report.Options{})
	out, err := report.RenderHTML(b)
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if !strings.Contains(s, "&lt;script&gt;") {
		t.Fatalf("HTML escaping missing; output:\n%s", s)
	}
	if strings.Contains(s, "<script>alert(1)</script>") {
		t.Fatal("raw script tag leaked into HTML")
	}
	if !strings.Contains(s, b.Project.Name) {
		t.Fatal("project name missing from HTML")
	}
	if !strings.Contains(s, "sev-critical") {
		t.Fatal("severity CSS class missing from HTML")
	}
}

func TestRenderCSVSectionedOutput(t *testing.T) {
	st, p := reportFixture(t)
	b, _ := report.Generate(context.Background(), deps(st), p.ID, report.Options{})
	out, err := report.RenderCSV(b)
	if err != nil {
		t.Fatal(err)
	}
	// Parse the CSV and confirm at least one row per expected section.
	r := csv.NewReader(strings.NewReader(string(out)))
	r.FieldsPerRecord = -1
	rows, err := r.ReadAll()
	if err != nil {
		t.Fatalf("CSV parse: %v", err)
	}
	sections := map[string]int{}
	for _, row := range rows {
		if len(row) >= 2 && row[0] == "section" {
			sections[row[1]]++
		}
	}
	for _, name := range []string{"project", "findings", "entities", "runs"} {
		if sections[name] == 0 {
			t.Fatalf("CSV missing %q section header", name)
		}
	}
	// Critical-finding ID present in the findings section.
	if !strings.Contains(string(out), b.Findings[0].ID) {
		t.Fatalf("critical finding ID missing from CSV")
	}
}

func TestBundleJSONShape(t *testing.T) {
	// Pin the API-facing JSON keys so SPA consumers don't break on a
	// silent rename.
	st, p := reportFixture(t)
	b, _ := report.Generate(context.Background(), deps(st), p.ID, report.Options{})
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	for _, key := range []string{
		`"project"`, `"summary"`, `"entities_by_kind"`, `"findings"`, `"runs"`,
		`"entities_total"`, `"findings_total"`, `"runs_total"`,
		`"report_template"`,
	} {
		if !strings.Contains(s, key) {
			t.Fatalf("JSON missing key %s", key)
		}
	}
}
