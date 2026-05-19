package nmap

// Tests live in `package nmap` (not nmap_test) so they can substitute
// the unexported runner without exporting it.

import (
	"context"
	"strings"
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

const sampleNmapXML = `<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="10.0.0.5" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="9.3p1" extrainfo="Ubuntu">
          <cpe>cpe:/a:openbsd:openssh:9.3p1</cpe>
        </service>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="nginx" version="1.25.0"/>
      </port>
      <port protocol="tcp" portid="445">
        <state state="open"/>
        <service name="microsoft-ds"/>
      </port>
      <port protocol="tcp" portid="9999">
        <state state="closed"/>
        <service name="abyss"/>
      </port>
    </ports>
  </host>
  <host>
    <address addr="10.0.0.6" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="3389">
        <state state="open"/>
        <service name="ms-wbt-server"/>
      </port>
    </ports>
  </host>
</nmaprun>`

func setup(t *testing.T, rules []scope.Rule, defaultScope scope.RuleKind) (*memory.Store, *project.Project, *run.Run, *scan.Runner) {
	t.Helper()
	st := memory.New()
	ctx := context.Background()
	p := &project.Project{Name: "P", DefaultScope: defaultScope, Mode: project.ModeAssessment}
	if err := st.Projects.Save(ctx, p); err != nil {
		t.Fatal(err)
	}
	for _, r := range rules {
		_ = st.Scopes.Add(ctx, &scope.StoredRule{ProjectID: p.ID, Rule: r})
	}
	pol, _ := scope.Compile(p.ID, p.DefaultScope, rules)
	ru := &run.Run{ProjectID: p.ID, Phase: workflow.PhaseValidation, Status: run.StatusRunning}
	_ = st.Runs.Save(ctx, ru)
	runner, err := scan.NewRunner(scan.Deps{
		Runs: st.Runs, Entities: st.Entities, Findings: st.Findings, Scope: pol,
	}, nil, st.Audit)
	if err != nil {
		t.Fatal(err)
	}
	return st, p, ru, runner
}

// stubRunner returns canned stdout, captures the args nmap was called
// with, and signals the test whether the runner was invoked.
type stubRunner struct {
	stdout   []byte
	err      error
	rc       int
	gotArgs  []string
	called   int
}

func (s *stubRunner) run(_ context.Context, spec subprocess.Spec) (subprocess.Result, error) {
	s.called++
	s.gotArgs = append([]string(nil), spec.Args...)
	return subprocess.Result{Stdout: s.stdout, ExitCode: s.rc}, s.err
}

func TestNmapHappyPath(t *testing.T) {
	stub := &stubRunner{stdout: []byte(sampleNmapXML)}
	c := newWithRunner(stub.run)
	st, p, ru, runner := setup(t,
		[]scope.Rule{
			{Pattern: "10.0.0.5", Kind: scope.KindLightActive},
			{Pattern: "10.0.0.6", Kind: scope.KindLightActive},
		},
		scope.KindPassive,
	)
	tx, err := runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{
		"targets": []any{"10.0.0.5", "10.0.0.6"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if tx.Status != run.ToolStatusCompleted {
		t.Fatalf("status=%s err=%q", tx.Status, tx.ErrorSummary)
	}
	// 4 open ports = 4 SERVICE entities (the closed 9999 is dropped).
	if tx.EntitiesEmitted != 4 {
		t.Fatalf("entities_emitted=%d, want 4", tx.EntitiesEmitted)
	}
	// One evidence row per service + the auto-evidence from EmitEntity = 8.
	if tx.EvidenceEmitted != 8 {
		t.Fatalf("evidence_emitted=%d, want 8", tx.EvidenceEmitted)
	}

	// Persisted SERVICE values use the canonical service name.
	services, _ := st.Entities.ListValuesByKind(context.Background(), p.ID, entity.KindService)
	wantValues := map[string]bool{
		"10.0.0.5:22/ssh":   false,
		"10.0.0.5:80/http":  false,
		"10.0.0.5:445/smb":  false, // microsoft-ds -> smb
		"10.0.0.6:3389/rdp": false, // ms-wbt-server -> rdp
	}
	for _, v := range services {
		if _, ok := wantValues[v]; ok {
			wantValues[v] = true
		} else {
			t.Errorf("unexpected service value: %q", v)
		}
	}
	for v, seen := range wantValues {
		if !seen {
			t.Errorf("missing service value: %q", v)
		}
	}
}

func TestNmapArgsIncludeFlags(t *testing.T) {
	stub := &stubRunner{stdout: []byte(sampleNmapXML)}
	c := newWithRunner(stub.run)
	_, p, ru, runner := setup(t,
		[]scope.Rule{{Pattern: "10.0.0.5", Kind: scope.KindLightActive}},
		scope.KindPassive,
	)
	_, _ = runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{
		"targets":           []any{"10.0.0.5"},
		"ports":             "22,80,443",
		"timing":            "T4",
		"service_detection": true,
		"extra_args":        []any{"--script=safe"},
	})
	got := strings.Join(stub.gotArgs, " ")
	for _, want := range []string{"-oX", "-", "-T4", "-sV", "-p", "22,80,443", "--script=safe", "10.0.0.5"} {
		if !strings.Contains(got, want) {
			t.Errorf("args missing %q; got %v", want, stub.gotArgs)
		}
	}
}

func TestNmapTopPortsTokenMapped(t *testing.T) {
	stub := &stubRunner{stdout: []byte(`<nmaprun/>`)}
	c := newWithRunner(stub.run)
	_, p, ru, runner := setup(t,
		[]scope.Rule{{Pattern: "10.0.0.5", Kind: scope.KindLightActive}},
		scope.KindPassive,
	)
	_, _ = runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{
		"targets": []any{"10.0.0.5"},
		"ports":   "top-1000",
	})
	if !contains(stub.gotArgs, "--top-ports") || !contains(stub.gotArgs, "1000") {
		t.Fatalf("expected --top-ports 1000; got %v", stub.gotArgs)
	}
}

func TestNmapAllPortsToken(t *testing.T) {
	stub := &stubRunner{stdout: []byte(`<nmaprun/>`)}
	c := newWithRunner(stub.run)
	_, p, ru, runner := setup(t,
		[]scope.Rule{{Pattern: "10.0.0.5", Kind: scope.KindLightActive}},
		scope.KindPassive,
	)
	_, _ = runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{
		"targets": []any{"10.0.0.5"},
		"ports":   "-",
	})
	if !contains(stub.gotArgs, "-p-") {
		t.Fatalf("expected -p-; got %v", stub.gotArgs)
	}
}

func TestNmapTargetsFallBackToIPEntities(t *testing.T) {
	stub := &stubRunner{stdout: []byte(`<nmaprun/>`)}
	c := newWithRunner(stub.run)
	st, p, ru, runner := setup(t,
		[]scope.Rule{{Pattern: "10.0.0.5", Kind: scope.KindLightActive}},
		scope.KindPassive,
	)
	// Seed an IP entity; no `targets` param.
	_, _ = st.Entities.Upsert(context.Background(), p.ID, entity.KindIP, "10.0.0.5", nil)
	tx, _ := runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{})
	if tx.Status != run.ToolStatusCompleted {
		t.Fatalf("status=%s err=%q", tx.Status, tx.ErrorSummary)
	}
	if !contains(stub.gotArgs, "10.0.0.5") {
		t.Fatalf("expected 10.0.0.5 in args; got %v", stub.gotArgs)
	}
}

func TestNmapOutOfScopeTargetsSkippedNoSubprocess(t *testing.T) {
	stub := &stubRunner{stdout: []byte(`<nmaprun/>`)}
	c := newWithRunner(stub.run)
	_, p, ru, runner := setup(t,
		// Only the allowed rule reaches LIGHT_ACTIVE.
		[]scope.Rule{{Pattern: "10.0.0.5", Kind: scope.KindLightActive}},
		scope.KindPassive,
	)
	tx, _ := runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{
		"targets": []any{"10.0.0.99"}, // out of scope
	})
	if tx.Status != run.ToolStatusCompleted {
		t.Fatalf("status=%s", tx.Status)
	}
	if stub.called != 0 {
		t.Fatalf("subprocess called %d times; expected 0 (all out-of-scope)", stub.called)
	}
}

func TestNmapNoTargetsFails(t *testing.T) {
	stub := &stubRunner{}
	c := newWithRunner(stub.run)
	_, p, ru, runner := setup(t,
		[]scope.Rule{{Pattern: "10.0.0.5", Kind: scope.KindLightActive}},
		scope.KindPassive,
	)
	tx, _ := runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{})
	if tx.Status != run.ToolStatusFailed {
		t.Fatalf("status=%s, want failed", tx.Status)
	}
	if !strings.Contains(tx.ErrorSummary, "no targets") {
		t.Fatalf("error_summary missing hint: %q", tx.ErrorSummary)
	}
}

func TestNmapBinaryNotFoundPropagates(t *testing.T) {
	c := newWithRunner(func(_ context.Context, spec subprocess.Spec) (subprocess.Result, error) {
		return subprocess.Result{}, &subprocess.BinaryNotFoundError{Binary: spec.Binary}
	})
	_, p, ru, runner := setup(t,
		[]scope.Rule{{Pattern: "10.0.0.5", Kind: scope.KindLightActive}},
		scope.KindPassive,
	)
	tx, _ := runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{
		"targets": []any{"10.0.0.5"},
		"binary":  "no-such-nmap",
	})
	if tx.Status != run.ToolStatusFailed {
		t.Fatalf("status=%s", tx.Status)
	}
	if !strings.Contains(tx.ErrorSummary, "no-such-nmap") {
		t.Fatalf("error_summary missing missing-binary detail: %q", tx.ErrorSummary)
	}
}

func TestNmapXMLParseError(t *testing.T) {
	c := newWithRunner(func(_ context.Context, _ subprocess.Spec) (subprocess.Result, error) {
		return subprocess.Result{Stdout: []byte("this is not xml")}, nil
	})
	_, p, ru, runner := setup(t,
		[]scope.Rule{{Pattern: "10.0.0.5", Kind: scope.KindLightActive}},
		scope.KindPassive,
	)
	tx, _ := runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{
		"targets": []any{"10.0.0.5"},
	})
	if tx.Status != run.ToolStatusFailed {
		t.Fatalf("status=%s", tx.Status)
	}
	if !strings.Contains(tx.ErrorSummary, "parse XML") {
		t.Fatalf("error_summary should mention XML parse: %q", tx.ErrorSummary)
	}
}

func TestNmapServiceCanonicalization(t *testing.T) {
	cases := []struct{ raw, want string }{
		{"microsoft-ds", "smb"},
		{"ms-wbt-server", "rdp"},
		{"http-proxy", "http"},
		{"ssl/http", "https"},
		{"unknown-protocol", "unknown-protocol"},
		{"", "unknown"},
		{"  HTTP  ", "http"},
	}
	for _, c := range cases {
		if got := canonicalService(c.raw); got != c.want {
			t.Errorf("canonicalService(%q) = %q, want %q", c.raw, got, c.want)
		}
	}
}

func TestNmapConfidenceTracksVersion(t *testing.T) {
	stub := &stubRunner{stdout: []byte(sampleNmapXML)}
	c := newWithRunner(stub.run)
	st, p, ru, runner := setup(t,
		[]scope.Rule{
			{Pattern: "10.0.0.5", Kind: scope.KindLightActive},
			{Pattern: "10.0.0.6", Kind: scope.KindLightActive},
		},
		scope.KindPassive,
	)
	_, _ = runner.Execute(context.Background(), p.ID, ru.ID, c, map[string]any{
		"targets": []any{"10.0.0.5", "10.0.0.6"},
	})
	// Findings layer doesn't get touched, but evidence rows carry the
	// confidence so we can spot-check via the evidence stream.
	ev, _ := st.Findings.ListEvidence(context.Background(), p.ID)
	confByValue := map[string]string{}
	for _, e := range ev {
		val, _ := e.Payload["target"].(string)
		port, _ := e.Payload["port"].(float64)
		if val == "" {
			continue
		}
		key := val
		_ = port
		confByValue[key+":"+e.Payload["service_name"].(string)] = string(e.Confidence)
	}
	// SMB (no version) and RDP (no version) -> MEDIUM; SSH and HTTP have version -> HIGH.
	// Sanity-check at least one of each.
	for key, want := range map[string]string{
		"10.0.0.5:ssh":  "high",
		"10.0.0.5:smb":  "medium",
		"10.0.0.6:rdp":  "medium",
	} {
		if got := confByValue[key]; got != want {
			t.Errorf("confidence for %s = %q, want %q", key, got, want)
		}
	}
}

// ----- helpers --------------------------------------------------------

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}
