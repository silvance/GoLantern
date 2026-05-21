package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/silvance/golantern/internal/api"
	"github.com/silvance/golantern/internal/evidence"
	"github.com/silvance/golantern/internal/evidence/parsers/linpeas"
	"github.com/silvance/golantern/internal/evidence/parsers/winpeas"
	"github.com/silvance/golantern/internal/project"
	"github.com/silvance/golantern/internal/scope"
	"github.com/silvance/golantern/internal/store/memory"
)

func newEvidenceServer(t *testing.T) (*httptest.Server, *memory.Store, *project.Project) {
	t.Helper()
	st := memory.New()
	srv := api.New(st.Projects, st.Scopes, st.Runs, st.Audit)
	srv.Entities = st.Entities
	srv.Findings = st.Findings
	reg := evidence.NewRegistry()
	reg.Register(linpeas.New())
	reg.Register(winpeas.New())
	srv.EvidenceParsers = reg

	p := &project.Project{Name: "P", DefaultScope: scope.KindPassive, Mode: project.ModeCTF}
	if err := st.Projects.Save(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts, st, p
}

func TestEvidenceListsParsers(t *testing.T) {
	ts, _, _ := newEvidenceServer(t)
	resp, err := http.Get(ts.URL + "/api/v1/evidence/parsers")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status=%d", resp.StatusCode)
	}
	var out []struct {
		Name string `json:"name"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	names := map[string]bool{}
	for _, p := range out {
		names[p.Name] = true
	}
	if !names["linpeas"] || !names["winpeas"] {
		t.Fatalf("expected linpeas+winpeas; got %+v", out)
	}
}

func TestEvidenceIngestLinpeas(t *testing.T) {
	ts, st, p := newEvidenceServer(t)
	body := map[string]any{
		"tool":   "linpeas",
		"target": "10.0.0.5",
		"content": `
╔══════════╣ Operative system
Linux version 4.15.0-122-generic

╔══════════╣ Interesting Files - SUID
-rwsr-xr-x 1 root root 16K Jan 14 2023 /usr/bin/nmap
-rwsr-xr-x 1 root root 18K Jan 14 2023 /usr/bin/find

╔══════════╣ Sudo
    (root) NOPASSWD: /usr/bin/find
`,
		"notes": "post-foothold paste from initial recon",
	}
	buf, _ := json.Marshal(body)
	resp, err := http.Post(ts.URL+"/api/v1/projects/"+p.ID+"/evidence/ingest",
		"application/json", bytes.NewReader(buf))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 201 {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d body=%s", resp.StatusCode, raw)
	}
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if int(out["findings_emitted"].(float64)) != 2 {
		t.Fatalf("expected 2 findings (SUID+sudo); got %v", out["findings_emitted"])
	}
	// Verify findings actually landed in the store.
	fs, _ := st.Findings.ListFindings(context.Background(), p.ID)
	if len(fs) != 2 {
		t.Fatalf("store has %d findings; want 2", len(fs))
	}
	// Verify the kernel tech entity was emitted.
	techs, _ := st.Entities.ListValuesByKind(context.Background(), p.ID, "technology")
	var hasKernel bool
	for _, t := range techs {
		if t == "linux-kernel/4.15.0-122-generic" {
			hasKernel = true
		}
	}
	if !hasKernel {
		t.Fatalf("kernel tech entity missing: %v", techs)
	}
}

func TestEvidenceIngestUnknownTool(t *testing.T) {
	ts, _, p := newEvidenceServer(t)
	body, _ := json.Marshal(map[string]any{"tool": "bogus", "content": "x"})
	resp, err := http.Post(ts.URL+"/api/v1/projects/"+p.ID+"/evidence/ingest",
		"application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 400 {
		t.Fatalf("status=%d; want 400", resp.StatusCode)
	}
}

func TestEvidenceIngestMissingContent(t *testing.T) {
	ts, _, p := newEvidenceServer(t)
	body, _ := json.Marshal(map[string]any{"tool": "linpeas"})
	resp, err := http.Post(ts.URL+"/api/v1/projects/"+p.ID+"/evidence/ingest",
		"application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 400 {
		t.Fatalf("status=%d; want 400", resp.StatusCode)
	}
}

func TestEvidenceIngestUnknownProject(t *testing.T) {
	ts, _, _ := newEvidenceServer(t)
	body, _ := json.Marshal(map[string]any{"tool": "linpeas", "content": "x"})
	resp, err := http.Post(ts.URL+"/api/v1/projects/no-such-project/evidence/ingest",
		"application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Fatalf("status=%d; want 404", resp.StatusCode)
	}
}

func TestEvidenceParsersNotConfigured(t *testing.T) {
	// Server without EvidenceParsers set — list endpoint returns 501.
	st := memory.New()
	srv := api.New(st.Projects, st.Scopes, st.Runs, st.Audit)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	resp, err := http.Get(ts.URL + "/api/v1/evidence/parsers")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 501 {
		t.Fatalf("status=%d; want 501", resp.StatusCode)
	}
}
