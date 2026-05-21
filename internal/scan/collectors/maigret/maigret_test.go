package maigret

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
	pol, _ := scope.Compile(p.ID, p.DefaultScope, nil)
	ru := &run.Run{ProjectID: p.ID, Phase: workflow.PhaseOSINT, Status: run.StatusRunning}
	_ = st.Runs.Save(ctx, ru)
	runner, _ := scan.NewRunner(scan.Deps{
		Runs: st.Runs, Entities: st.Entities, Findings: st.Findings, Scope: pol,
	}, nil, st.Audit)
	return st, p, ru, runner
}

// stubRunner emulates maigret by writing the JSON output file the
// real binary would have produced into the --folderoutput directory,
// then returning success. The collector's real file readers then
// pick it up — exercising the locateJSON + parseSimpleJSON paths.
type stubRunner struct {
	username string
	json     string
	gotArgs  []string
}

func (s *stubRunner) run(_ context.Context, spec subprocess.Spec) (subprocess.Result, error) {
	s.gotArgs = append([]string(nil), spec.Args...)
	var tmp string
	for i, a := range spec.Args {
		if a == "--folderoutput" && i+1 < len(spec.Args) {
			tmp = spec.Args[i+1]
		}
	}
	if tmp == "" {
		return subprocess.Result{}, nil
	}
	path := filepath.Join(tmp, "report_"+s.username+"_simple.json")
	if err := os.WriteFile(path, []byte(s.json), 0o600); err != nil {
		return subprocess.Result{}, err
	}
	return subprocess.Result{}, nil
}

func TestMaigretClaimedHits(t *testing.T) {
	stub := &stubRunner{
		username: "foo",
		json: `{
			"github": {"url_user": "https://github.com/foo", "status": "Claimed", "http_status": 200, "tags": ["dev"]},
			"twitter": {"url_user": "https://twitter.com/foo", "status": "Claimed", "http_status": 200},
			"deadsite": {"url_user": "https://nope.example/foo", "status": "Available"}
		}`,
	}
	c := newWithRunner(stub.run)
	st, p, ru, runner := setup(t)
	tx, err := runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{
		"username": "foo",
	})
	if err != nil {
		t.Fatal(err)
	}
	if tx.Status != run.ToolStatusCompleted {
		t.Fatalf("status=%s err=%q", tx.Status, tx.ErrorSummary)
	}
	persons, _ := st.Entities.ListValuesByKind(context.Background(), p.ID, entity.KindPerson)
	if len(persons) != 1 || persons[0] != "foo" {
		t.Fatalf("person entity missing: %v", persons)
	}
	urls, _ := st.Entities.ListValuesByKind(context.Background(), p.ID, entity.KindURL)
	have := map[string]bool{}
	for _, v := range urls {
		have[v] = true
	}
	if !have["https://github.com/foo"] || !have["https://twitter.com/foo"] {
		t.Fatalf("expected GH+Twitter URLs; got %v", urls)
	}
	if have["https://nope.example/foo"] {
		t.Fatalf("available status leaked: %v", urls)
	}
}

func TestMaigretArrayJSONShape(t *testing.T) {
	// Older maigret versions emit an array, not an object.
	stub := &stubRunner{
		username: "foo",
		json: `[
			{"sitename": "github", "url_user": "https://github.com/foo", "status": "Claimed"}
		]`,
	}
	c := newWithRunner(stub.run)
	st, p, ru, runner := setup(t)
	_, _ = runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{
		"username": "foo",
	})
	urls, _ := st.Entities.ListValuesByKind(context.Background(), p.ID, entity.KindURL)
	if len(urls) != 1 || urls[0] != "https://github.com/foo" {
		t.Fatalf("array shape not parsed: %v", urls)
	}
}

func TestMaigretMissingUsername(t *testing.T) {
	c := newWithRunner((&stubRunner{}).run)
	_, p, ru, runner := setup(t)
	tx, _ := runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{})
	if tx.Status != run.ToolStatusFailed {
		t.Fatalf("status=%s", tx.Status)
	}
}

func TestMaigretRejectsBadUsername(t *testing.T) {
	c := newWithRunner((&stubRunner{}).run)
	_, p, ru, runner := setup(t)
	tx, _ := runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{
		"username": "foo; rm -rf /",
	})
	if tx.Status != run.ToolStatusFailed {
		t.Fatalf("status=%s; bad username should fail validation", tx.Status)
	}
}
