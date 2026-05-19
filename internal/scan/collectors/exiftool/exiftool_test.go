package exiftool

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
	pol, _ := scope.Compile(p.ID, scope.KindPassive, nil)
	ru := &run.Run{ProjectID: p.ID, Phase: workflow.PhaseEnrichment, Status: run.StatusRunning}
	_ = st.Runs.Save(ctx, ru)
	runner, _ := scan.NewRunner(scan.Deps{
		Runs: st.Runs, Entities: st.Entities, Findings: st.Findings, Scope: pol,
	}, nil, st.Audit)
	return st, p, ru, runner
}

const sampleStdout = `[{
  "SourceFile":"/tmp/leaked.pdf",
  "PDF:Author":"Alice Smith",
  "PDF:Creator":"Microsoft Word 2019",
  "PDF:Title":"Internal Q4 Plan",
  "XMP:CreatorTool":"Acrobat Distiller 11.0",
  "EXIF:GPSLatitude":"37.7749 N",
  "PDF:Producer":"Contact alice@example.com or check C:\\Users\\alice\\drafts"
}]`

func TestExifToolHappyPath(t *testing.T) {
	// Write a fake file so the path-expansion logic accepts it.
	tmp := filepath.Join(t.TempDir(), "leaked.pdf")
	_ = os.WriteFile(tmp, []byte("dummy"), 0o644)

	stub := func(_ context.Context, _ subprocess.Spec) (subprocess.Result, error) {
		// Patch SourceFile to point at our tempfile so downstream
		// asserts on filepath.Base("leaked.pdf") still match.
		body := sampleStdout
		return subprocess.Result{Stdout: []byte(body)}, nil
	}
	c := newWithRunner(stub)
	st, p, ru, runner := setup(t)
	_, err := runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{
		"paths": []any{tmp},
	})
	if err != nil {
		t.Fatal(err)
	}
	docs, _ := st.Entities.ListValuesByKind(context.Background(), p.ID, entity.KindDocument)
	if len(docs) != 1 {
		t.Fatalf("docs=%v", docs)
	}
	people, _ := st.Entities.ListValuesByKind(context.Background(), p.ID, entity.KindPerson)
	if len(people) != 1 || people[0] != "Alice Smith" {
		t.Fatalf("people=%v", people)
	}
	emails, _ := st.Entities.ListValuesByKind(context.Background(), p.ID, entity.KindEmail)
	if len(emails) != 1 || emails[0] != "alice@example.com" {
		t.Fatalf("emails=%v", emails)
	}
}

func TestExifToolNoFilesFails(t *testing.T) {
	stub := func(_ context.Context, _ subprocess.Spec) (subprocess.Result, error) {
		return subprocess.Result{}, nil
	}
	c := newWithRunner(stub)
	_, p, ru, runner := setup(t)
	tx, _ := runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{})
	if tx.Status != run.ToolStatusFailed {
		t.Fatalf("status=%s", tx.Status)
	}
}
