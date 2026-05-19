package entity

import "testing"

func TestKindAndRelationValid(t *testing.T) {
	for _, k := range []Kind{KindDomain, KindIP, KindURL, KindRepository} {
		if !k.Valid() {
			t.Fatalf("%q should be valid", k)
		}
	}
	if Kind("bogus").Valid() {
		t.Fatal("bogus Kind should not be valid")
	}
	for _, r := range []RelationKind{RelResolvesTo, RelHosts, RelDiscoveredFrom} {
		if !r.Valid() {
			t.Fatalf("%q should be valid", r)
		}
	}
	if RelationKind("nope").Valid() {
		t.Fatal("bogus RelationKind should not be valid")
	}
}

func TestCanonicalizeDomain(t *testing.T) {
	cases := []struct {
		kind     Kind
		in, want string
	}{
		{KindDomain, "Example.COM", "example.com"},
		{KindDomain, "  example.com.  ", "example.com"}, // strip + trailing dot
		{KindSubdomain, "API.Example.com.", "api.example.com"},
		{KindDomain, "", ""},
	}
	for _, c := range cases {
		if got := Canonicalize(c.kind, c.in); got != c.want {
			t.Fatalf("Canonicalize(%s, %q) = %q, want %q", c.kind, c.in, got, c.want)
		}
	}
}

func TestCanonicalizeEmail(t *testing.T) {
	if got := Canonicalize(KindEmail, "User@Example.COM"); got != "user@example.com" {
		t.Fatalf("email canonicalize = %q", got)
	}
}

func TestCanonicalizeIP(t *testing.T) {
	cases := []struct{ in, want string }{
		{"192.0.2.5", "192.0.2.5"},
		{"::1", "::1"},
		// IPv6 expanded form collapses to canonical compressed form.
		{"0:0:0:0:0:0:0:1", "::1"},
		// Junk passes through unchanged.
		{"not-an-ip", "not-an-ip"},
	}
	for _, c := range cases {
		if got := Canonicalize(KindIP, c.in); got != c.want {
			t.Fatalf("Canonicalize(IP, %q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestCanonicalizeURL(t *testing.T) {
	cases := []struct{ in, want string }{
		{"https://Example.com/", "https://example.com"},     // root slash dropped
		{"https://Example.com:443/", "https://example.com"}, // default port dropped
		{"http://Example.com:80/path", "http://example.com/path"},
		{"https://Example.com:8443/admin", "https://example.com:8443/admin"},
		{"https://Example.com/Path/Case?Q=1#frag", "https://example.com/Path/Case?Q=1#frag"}, // path/query case preserved
		// Junk passes through.
		{"not a url", "not a url"},
	}
	for _, c := range cases {
		if got := Canonicalize(KindURL, c.in); got != c.want {
			t.Fatalf("Canonicalize(URL, %q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestCanonicalizeRepository(t *testing.T) {
	cases := []struct{ in, want string }{
		{"https://github.com/Owner/Repo.git", "https://github.com/owner/repo"},
		{"git@github.com:Owner/Repo.git", "https://github.com/owner/repo"},
		{"github.com/Owner/Repo", "https://github.com/owner/repo"},
		{"https://gitlab.com/owner/repo/", "https://gitlab.com/owner/repo"},
		// Unparseable input returns unchanged.
		{"", ""},
	}
	for _, c := range cases {
		if got := Canonicalize(KindRepository, c.in); got != c.want {
			t.Fatalf("Canonicalize(REPOSITORY, %q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestCanonicalizePassthroughKinds(t *testing.T) {
	// Person / document / technology / etc.: just strip whitespace, case preserved.
	if got := Canonicalize(KindTechnology, "  Apache HTTPD  "); got != "Apache HTTPD" {
		t.Fatalf("technology case must be preserved, got %q", got)
	}
	if got := Canonicalize(KindPerson, "  Alice Example  "); got != "Alice Example" {
		t.Fatalf("person case must be preserved, got %q", got)
	}
}
