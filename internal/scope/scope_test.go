package scope

import (
	"errors"
	"testing"
)

// The fixture mirrors tests/test_scope.py::project_with_rules so the Go
// port's behaviour can be diffed against the Python suite case-for-case.
func newFixturePolicy(t *testing.T) *Policy {
	t.Helper()
	p, err := Compile("proj", KindPassive, []Rule{
		{Pattern: "*.example.com", Kind: KindLightActive},
		{Pattern: "api.example.com", Kind: KindFullActive},
		{Pattern: "legacy.example.com", Kind: KindDeny},
		{Pattern: "192.0.2.0/24", Kind: KindLightActive},
	})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	return p
}

func TestDefaultScopeUsedWhenNoRuleMatches(t *testing.T) {
	p := newFixturePolicy(t)
	if got := p.MatchedScope("unrelated.test"); got != KindPassive {
		t.Fatalf("MatchedScope(unrelated.test) = %v, want passive", got)
	}
}

func TestMostSpecificRuleWins(t *testing.T) {
	p := newFixturePolicy(t)
	if got := p.MatchedScope("api.example.com"); got != KindFullActive {
		t.Fatalf("MatchedScope(api.example.com) = %v, want full_active", got)
	}
	if got := p.MatchedScope("other.example.com"); got != KindLightActive {
		t.Fatalf("MatchedScope(other.example.com) = %v, want light_active", got)
	}
}

func TestDenyBlocksEvenWhenWildcardAllows(t *testing.T) {
	p := newFixturePolicy(t)
	if got := p.MatchedScope("legacy.example.com"); got != KindDeny {
		t.Fatalf("MatchedScope(legacy.example.com) = %v, want deny", got)
	}
	if p.IsAllowed("legacy.example.com", KindPassive) {
		t.Fatalf("IsAllowed should be false under deny")
	}
}

func TestCIDRMatch(t *testing.T) {
	p := newFixturePolicy(t)
	if got := p.MatchedScope("192.0.2.42"); got != KindLightActive {
		t.Fatalf("MatchedScope(192.0.2.42) = %v, want light_active", got)
	}
	if got := p.MatchedScope("192.0.3.1"); got != KindPassive {
		t.Fatalf("out-of-network IP should fall through to default, got %v", got)
	}
}

func TestRequireReturnsOutOfScope(t *testing.T) {
	p := newFixturePolicy(t)
	err := p.Require("other.example.com", KindFullActive)
	if err == nil {
		t.Fatal("expected OutOfScopeError")
	}
	if !errors.Is(err, ErrOutOfScope) {
		t.Fatalf("error does not unwrap to ErrOutOfScope: %v", err)
	}
	var oo *OutOfScopeError
	if !errors.As(err, &oo) {
		t.Fatalf("error not assignable to *OutOfScopeError: %v", err)
	}
	if oo.Required != KindFullActive || oo.Matched != KindLightActive {
		t.Fatalf("OutOfScopeError fields = %+v", oo)
	}
}

// Parity case: pyplay test_url_target_matches_ip_rule. A URL-shaped
// target like https://10.10.11.219:8443/ must match a rule written as
// the bare IP. Without normalization this silently drops to default.
func TestURLTargetMatchesIPRule(t *testing.T) {
	p, err := Compile("p", KindPassive, []Rule{
		{Pattern: "10.10.11.219", Kind: KindFullActive},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !p.IsAllowed("https://10.10.11.219:8443/", KindFullActive) {
		t.Fatalf("URL target should match bare-IP rule")
	}
}

func TestURLTargetMatchesDomainRule(t *testing.T) {
	p, err := Compile("p", KindPassive, []Rule{
		{Pattern: "admin.example.com", Kind: KindFullActive},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !p.IsAllowed("http://admin.example.com/login", KindFullActive) {
		t.Fatalf("URL target should match bare-host rule")
	}
}

func TestEmailTargetMatchesDomainRule(t *testing.T) {
	p, err := Compile("p", KindPassive, []Rule{
		{Pattern: "example.com", Kind: KindLightActive},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !p.IsAllowed("alice@example.com", KindLightActive) {
		t.Fatalf("email target should match domain rule")
	}
}

// Parity case: rule pattern written as a URL must normalize to host at
// compile time so it can match host-shaped targets.
func TestURLShapedPatternNormalizesAtCompileTime(t *testing.T) {
	p, err := Compile("p", KindPassive, []Rule{
		{Pattern: "https://admin.example.com/", Kind: KindFullActive},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !p.IsAllowed("admin.example.com", KindFullActive) {
		t.Fatalf("URL-shaped rule pattern should normalize to host")
	}
}

// Pins the Python ip_network(p, strict=False) behaviour: a rule like
// 192.0.2.5/24 must compile as the network 192.0.2.0/24, so unrelated
// IPs inside that network still match.
func TestCIDRHostBitsAreMasked(t *testing.T) {
	p, err := Compile("p", KindPassive, []Rule{
		{Pattern: "192.0.2.5/24", Kind: KindLightActive},
	})
	if err != nil {
		t.Fatalf("Compile should mask host bits, got error: %v", err)
	}
	if got := p.MatchedScope("192.0.2.42"); got != KindLightActive {
		t.Fatalf("MatchedScope(192.0.2.42) = %v, want light_active", got)
	}
}

// At equal specificity, deny must beat allow regardless of insertion
// order. The reverse would let rule order silently authorize traffic.
func TestTieBreakDenyBeatsAllow(t *testing.T) {
	for _, order := range [][]Rule{
		{
			{Pattern: "host.example.com", Kind: KindFullActive},
			{Pattern: "host.example.com", Kind: KindDeny},
		},
		{
			{Pattern: "host.example.com", Kind: KindDeny},
			{Pattern: "host.example.com", Kind: KindFullActive},
		},
	} {
		p, err := Compile("p", KindPassive, order)
		if err != nil {
			t.Fatal(err)
		}
		if got := p.MatchedScope("host.example.com"); got != KindDeny {
			t.Fatalf("tie-break failed: got %v, want deny (order=%v)", got, order)
		}
	}
}

func TestRankAndIsAllowed(t *testing.T) {
	cases := []struct {
		matched, required RuleKind
		want              bool
	}{
		{KindPassive, KindPassive, true},
		{KindPassive, KindLightActive, false},
		{KindLightActive, KindPassive, true},
		{KindFullActive, KindFullActive, true},
		{KindDeny, KindPassive, false},
		{KindDeny, KindDeny, false},
	}
	for _, c := range cases {
		// Single-rule policy that pins the matched kind.
		p, err := Compile("p", c.matched, nil)
		if err != nil {
			t.Fatal(err)
		}
		if got := p.IsAllowed("anything.test", c.required); got != c.want {
			t.Fatalf("IsAllowed matched=%s required=%s = %v, want %v",
				c.matched, c.required, got, c.want)
		}
	}
}

func TestAllowsAtDefault(t *testing.T) {
	// Default high enough → true.
	p1, _ := Compile("p", KindFullActive, nil)
	if !p1.AllowsAtDefault(KindLightActive) {
		t.Fatalf("default full_active must allow light_active")
	}
	// Default low, but a rule reaches the required level.
	p2, _ := Compile("p", KindPassive, []Rule{
		{Pattern: "*.example.com", Kind: KindFullActive},
	})
	if !p2.AllowsAtDefault(KindFullActive) {
		t.Fatalf("rule should make full_active reachable")
	}
	// No way to reach.
	p3, _ := Compile("p", KindPassive, []Rule{
		{Pattern: "*.example.com", Kind: KindLightActive},
	})
	if p3.AllowsAtDefault(KindFullActive) {
		t.Fatalf("nothing should reach full_active")
	}
	// Deny rules don't satisfy reachability.
	p4, _ := Compile("p", KindPassive, []Rule{
		{Pattern: "*.example.com", Kind: KindDeny},
	})
	if p4.AllowsAtDefault(KindLightActive) {
		t.Fatalf("deny rule should not satisfy reachability")
	}
}

// Pin path.Match's behaviour for our domain patterns against Python
// fnmatch.fnmatchcase. These are the cases callers actually rely on.
func TestFnmatchParity(t *testing.T) {
	cases := []struct {
		pattern, target string
		match           bool
	}{
		{"*.example.com", "a.example.com", true},
		{"*.example.com", "a.b.example.com", true}, // '*' crosses dots
		{"*.example.com", "example.com", false},    // '*' must consume ≥1 char
		{"api.example.com", "api.example.com", true},
		{"api.example.com", "API.EXAMPLE.COM", true}, // normalized lowercase
		{"*", "anything.test", true},
	}
	for _, c := range cases {
		p, err := Compile("p", KindDeny, []Rule{
			{Pattern: c.pattern, Kind: KindLightActive},
		})
		if err != nil {
			t.Fatal(err)
		}
		got := p.MatchedScope(c.target) == KindLightActive
		if got != c.match {
			t.Fatalf("pattern=%q target=%q matched=%v, want %v",
				c.pattern, c.target, got, c.match)
		}
	}
}

func TestCompileRejectsEmptyPattern(t *testing.T) {
	if _, err := Compile("p", KindPassive, []Rule{{Pattern: "  ", Kind: KindLightActive}}); err == nil {
		t.Fatal("expected error for empty pattern")
	}
}

func TestNormalizeTarget(t *testing.T) {
	cases := []struct{ in, want string }{
		{"  Example.COM ", "example.com"},
		{"http://admin.example.com/x", "admin.example.com"},
		{"https://10.10.11.219:8443/", "10.10.11.219"},
		{"admin.example.com:8080", "admin.example.com"},
		{"alice@example.com", "example.com"},
		{"::1", "::1"}, // bare IPv6 left alone (more than one ':')
		{"192.0.2.0/24", "192.0.2.0/24"},
	}
	for _, c := range cases {
		if got := normalizeTarget(c.in); got != c.want {
			t.Fatalf("normalizeTarget(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
