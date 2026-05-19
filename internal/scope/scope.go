// Package scope decides whether a collector may act on a given target,
// given a project's scope rules.
//
// Ported from lantern/workflow/scope.py. The semantics of matched_scope,
// is_allowed, require, and allows_at_default are preserved; literal-port
// hazards (fnmatch vs path.Match, ipaddress.ip_network's silent network
// coercion, urlparse host extraction) are documented at each call site.
package scope

import (
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"path"
	"strings"
)

// RuleKind is the authorization gate.
//
// Mirrors lantern.models.project.ScopeRuleKind. The string values are
// the wire format and must not change without a coordinated migration
// with the Python service while it still writes the database.
type RuleKind string

const (
	KindPassive     RuleKind = "passive"
	KindLightActive RuleKind = "light_active"
	KindFullActive  RuleKind = "full_active"
	KindDeny        RuleKind = "deny"
)

// Valid reports whether k is one of the defined kinds. Useful at
// data-ingress points where the value originated outside the type
// system (DB row, JSON request body).
func (k RuleKind) Valid() bool {
	switch k {
	case KindPassive, KindLightActive, KindFullActive, KindDeny:
		return true
	}
	return false
}

// rank orders authorization levels; higher requires stricter authorization.
// Deny is sentinel-negative — it never satisfies any required level.
func (k RuleKind) rank() int {
	switch k {
	case KindDeny:
		return -1
	case KindPassive:
		return 0
	case KindLightActive:
		return 1
	case KindFullActive:
		return 2
	}
	return -1
}

// Rule is the input shape for a single scope rule, as stored in the
// scope_rules table. We deliberately avoid coupling to a DB row type;
// the repository layer converts.
type Rule struct {
	Pattern string
	Kind    RuleKind
}

// ErrOutOfScope is returned by Policy.Require when the target is not
// authorized at the requested level. Use errors.Is at call sites.
var ErrOutOfScope = errors.New("target not authorized by scope policy")

// OutOfScopeError carries the matched scope for the caller's error
// message; the sentinel ErrOutOfScope is wrapped for errors.Is.
type OutOfScopeError struct {
	Target   string
	Required RuleKind
	Matched  RuleKind
}

func (e *OutOfScopeError) Error() string {
	return fmt.Sprintf("target=%q not authorized for %s; matched scope is %s",
		e.Target, e.Required, e.Matched)
}

func (e *OutOfScopeError) Unwrap() error { return ErrOutOfScope }

// compiledRule mirrors the Python _CompiledRule. We pre-parse the IP
// network (if any) and pre-compute a specificity score so matched_scope
// is O(n) over the rule set with no per-call allocations.
type compiledRule struct {
	pattern     string
	kind        RuleKind
	network     netip.Prefix // zero value means "not a CIDR rule"
	hasNetwork  bool
	specificity int
}

// Policy resolves whether a target is allowed at a required level. Construct
// via Compile.
type Policy struct {
	projectID    string
	defaultScope RuleKind
	rules        []compiledRule
}

// Compile builds a Policy from raw rules. The defaultScope is consulted
// when no rule matches a target.
//
// An invalid rule pattern (empty after normalization) is a programmer
// error and is returned as an error rather than silently dropped — the
// Python version compiled lazily and would have produced a non-matching
// rule. Failing fast is more idiomatic for Go and easier to test.
func Compile(projectID string, defaultScope RuleKind, rules []Rule) (*Policy, error) {
	out := make([]compiledRule, 0, len(rules))
	for i, r := range rules {
		cr, err := compileRule(r)
		if err != nil {
			return nil, fmt.Errorf("rule %d (%q): %w", i, r.Pattern, err)
		}
		out = append(out, cr)
	}
	return &Policy{projectID: projectID, defaultScope: defaultScope, rules: out}, nil
}

func compileRule(r Rule) (compiledRule, error) {
	pat := normalizeTarget(r.Pattern)
	if pat == "" {
		return compiledRule{}, errors.New("pattern empty after normalization")
	}
	cr := compiledRule{pattern: pat, kind: r.Kind}

	// CIDR / single-IP path. Python uses ip_network(p, strict=False) which
	// silently masks host bits (192.0.2.5/24 -> 192.0.2.0/24). Go's
	// netip.ParsePrefix is strict — call Masked() to match Python.
	if prefix, err := netip.ParsePrefix(pat); err == nil {
		cr.network = prefix.Masked()
		cr.hasNetwork = true
		cr.specificity = prefix.Bits()
		return cr, nil
	}
	// Bare IP (no /mask) is allowed too; we treat it as a /32 or /128.
	if addr, err := netip.ParseAddr(pat); err == nil {
		bits := addr.BitLen()
		cr.network = netip.PrefixFrom(addr, bits)
		cr.hasNetwork = true
		cr.specificity = bits
		return cr, nil
	}

	// Domain pattern. Specificity = labels*10 - 100*(labels containing '*').
	// This matches the Python heuristic so an exact rule beats a wildcard.
	labels := strings.Split(pat, ".")
	wildcardLabels := 0
	for _, l := range labels {
		if strings.ContainsAny(l, "*?[") {
			wildcardLabels++
		}
	}
	cr.specificity = len(labels)*10 - wildcardLabels*100
	return cr, nil
}

// MatchedScope returns the kind of the most-specific rule that matches
// target, or the policy's default scope when nothing matches.
func (p *Policy) MatchedScope(target string) RuleKind {
	t := normalizeTarget(target)

	// Try to interpret the target as an IP. If it parses we restrict
	// matching to CIDR rules; if it doesn't we restrict to domain rules.
	// Mixing the two arms is exactly the Python bug that motivated
	// _normalize_target — and it's why the URL/IP test case exists.
	targetIP, err := netip.ParseAddr(t)
	isIP := err == nil

	var best *compiledRule
	for i := range p.rules {
		r := &p.rules[i]
		matched := false
		switch {
		case r.hasNetwork && isIP:
			matched = r.network.Contains(targetIP)
		case !r.hasNetwork && !isIP:
			// Domain glob. path.Match's '*' matches any sequence of
			// non-separator characters; since neither pattern nor target
			// contains '/' for our use case, this is equivalent to
			// Python's fnmatch.fnmatchcase. See TestFnmatchParity for the
			// pinned cases.
			ok, err := path.Match(r.pattern, t)
			matched = err == nil && ok
		}
		if !matched {
			continue
		}
		switch {
		case best == nil:
			best = r
		case r.specificity > best.specificity:
			best = r
		case r.specificity == best.specificity && r.kind == KindDeny:
			// Tie-break: explicit DENY beats allow at equal specificity.
			// The reverse would let rule-iteration order silently
			// authorize traffic.
			best = r
		}
	}
	if best == nil {
		return p.defaultScope
	}
	return best.kind
}

// IsAllowed reports whether target is authorized at the required level.
func (p *Policy) IsAllowed(target string, required RuleKind) bool {
	matched := p.MatchedScope(target)
	if matched == KindDeny {
		return false
	}
	return matched.rank() >= required.rank()
}

// Require returns *OutOfScopeError (wrapping ErrOutOfScope) when the
// target is not authorized at the required level.
func (p *Policy) Require(target string, required RuleKind) error {
	if p.IsAllowed(target, required) {
		return nil
	}
	return &OutOfScopeError{
		Target:   target,
		Required: required,
		Matched:  p.MatchedScope(target),
	}
}

// AllowsAtDefault reports whether any path through the policy can
// authorize required actions. Useful as a cheap precheck before
// queueing a collector run — per-target IsAllowed still runs at emit
// time.
func (p *Policy) AllowsAtDefault(required RuleKind) bool {
	if p.defaultScope != KindDeny && p.defaultScope.rank() >= required.rank() {
		return true
	}
	for _, r := range p.rules {
		if r.kind == KindDeny {
			continue
		}
		if r.kind.rank() >= required.rank() {
			return true
		}
	}
	return false
}

// normalizeTarget reduces a heterogeneous target string to its host
// component. Collectors pass a mix of plain hostnames, plain IPs, URLs,
// host:port pairs, and bare emails; ScopeRule patterns are almost
// always written as the host alone. Without this reduction, e.g.
// feroxbuster running against http://10.10.11.219/ is silently filtered
// out by an otherwise-valid IP rule.
//
// Rules, in order:
//   - URL-shaped (contains "://"): take url.Parse(...).Hostname().
//   - Email-shaped (single '@'): take the domain side.
//   - "host:port" (single ':', not bracketed IPv6, not a CIDR): drop port.
//   - Otherwise pass through trimmed + lowercased.
func normalizeTarget(target string) string {
	s := strings.ToLower(strings.TrimSpace(target))
	if s == "" {
		return s
	}
	if strings.Contains(s, "://") {
		// url.Parse on "http://10.10.11.219:8443/" returns Host
		// "10.10.11.219:8443"; Hostname() strips the port and brackets.
		if u, err := url.Parse(s); err == nil && u.Hostname() != "" {
			return u.Hostname()
		}
	}
	if strings.Count(s, "@") == 1 {
		// Email-shaped. Take the domain side.
		parts := strings.SplitN(s, "@", 2)
		return parts[1]
	}
	// host:port, but: skip if it's a CIDR (contains '/'), skip bracketed
	// IPv6 literals, and skip strings with more than one ':' (bare IPv6).
	if !strings.Contains(s, "/") && !strings.HasPrefix(s, "[") && strings.Count(s, ":") == 1 {
		host, _, ok := strings.Cut(s, ":")
		if ok {
			return host
		}
	}
	return s
}
