// Package john wraps John the Ripper for offline hash cracking.
// First collector with a parameter-driven (rather than entity-
// driven) input shape: the operator supplies hashes captured from
// a foothold (LSASS dump, /etc/shadow, NTDS.dit secretsdump, etc.)
// and john grinds them against a wordlist.
//
// The collector emits one finding per cracked hash — severity is
// always High by default because cracked credentials are
// immediately usable for lateral movement. The cleartext password
// lands in the finding's attributes; downstream collectors
// (netexec authenticated mode) can pick it up via copy-paste.
//
// Required scope is Passive: john does no network I/O.
package john

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/silvance/golantern/internal/entity"
	"github.com/silvance/golantern/internal/fact"
	"github.com/silvance/golantern/internal/finding"
	"github.com/silvance/golantern/internal/scan"
	"github.com/silvance/golantern/internal/scope"
	"github.com/silvance/golantern/internal/subprocess"
	"github.com/silvance/golantern/internal/workflow"
)

const (
	Name           = "john"
	defaultBinary  = "john"
	defaultTimeout = 1800 * time.Second // 30 min default — operator can lower
)

func New() scan.Collector { return &collector{} }

type runnerFn func(ctx context.Context, spec subprocess.Spec) (subprocess.Result, error)

func newWithRunner(r runnerFn) scan.Collector { return &collector{runner: r} }

type collector struct{ runner runnerFn }

func (collector) Metadata() scan.Meta {
	return scan.Meta{
		Name:           Name,
		Phase:          workflow.PhaseExposure,
		RequiredScope:  scope.KindPassive,
		Description:    "Offline hash cracking via John the Ripper. Takes captured hashes (NTLM, sha512crypt, etc.), grinds against a wordlist, and emits one finding per cracked credential.",
		Consumes:       nil, // parameter-driven, no entity consumption
		Produces:       nil,
		SourceCategory: finding.SourceManual,
		Binary:         "john",
		InstallHint: "Fedora: sudo dnf install john\n" +
			"Debian/Ubuntu: sudo apt install john\n" +
			"For -jumbo features (most formats): sudo dnf install john-jumbo (or build from openwall/john git)",
		Parameters: []scan.ParameterSpec{
			{Name: "hashes", Type: "string_list", Required: true,
				Description: "Hashes to crack, one per line in john's input format (e.g. 'user:$NT$abcd...'). Empty = error."},
			{Name: "format", Type: "string", Default: "",
				Description: "John format flag (e.g. nt, raw-md5, sha512crypt, mscash2). Empty = let john autodetect."},
			{Name: "wordlist", Type: "string", Default: "/usr/share/wordlists/rockyou.txt",
				Description: "Path to wordlist. Stick to the operator's machine — no remote fetch."},
			{Name: "rules", Type: "string", Default: "",
				Description: "Optional --rules name (e.g. Single, Jumbo, KoreLogic)."},
			{Name: "binary", Type: "string", Default: "john"},
			{Name: "timeout_seconds", Type: "float", Default: 1800.0,
				Description: "Wall-clock crack budget. john gives up cleanly when killed."},
		},
	}
}

func (c *collector) Run(ctx context.Context, cctx scan.Context) error {
	binary := strings.TrimSpace(toString(cctx.Parameters()["binary"]))
	if binary == "" {
		binary = defaultBinary
	}
	timeout := parseTimeout(cctx.Parameters()["timeout_seconds"])
	format := strings.TrimSpace(toString(cctx.Parameters()["format"]))
	wordlist := strings.TrimSpace(toString(cctx.Parameters()["wordlist"]))
	rules := strings.TrimSpace(toString(cctx.Parameters()["rules"]))

	hashes := parseStringList(cctx.Parameters()["hashes"])
	var cleanHashes []string
	for _, h := range hashes {
		h = strings.TrimSpace(h)
		if h != "" {
			cleanHashes = append(cleanHashes, h)
		}
	}
	if len(cleanHashes) == 0 {
		return errors.New("john: parameter `hashes` is required (non-empty list of hash strings)")
	}

	tmp, err := os.MkdirTemp("", "golantern-john-")
	if err != nil {
		return fmt.Errorf("john: tempdir: %w", err)
	}
	defer os.RemoveAll(tmp)
	hashPath := filepath.Join(tmp, "hashes.txt")
	if err := os.WriteFile(hashPath, []byte(strings.Join(cleanHashes, "\n")+"\n"), 0o600); err != nil {
		return fmt.Errorf("john: write hashfile: %w", err)
	}
	// Isolated pot file so we don't pollute the operator's ~/.john/john.pot.
	potPath := filepath.Join(tmp, "session.pot")

	run := c.runner
	if run == nil {
		run = subprocess.Run
	}

	// Crack pass.
	args := []string{
		"--pot=" + potPath,
		"--wordlist=" + wordlist,
	}
	if format != "" {
		args = append(args, "--format="+format)
	}
	if rules != "" {
		args = append(args, "--rules="+rules)
	}
	args = append(args, hashPath)
	if _, err := run(ctx, subprocess.Spec{
		Binary:         binary,
		Args:           args,
		Timeout:        timeout,
		AllowPartialRC: []int{1, 2, 3},
	}); err != nil {
		_ = cctx.EmitEvidence(fact.EvidenceFact{
			SourceTool:     Name,
			SourceCategory: finding.SourceManual,
			Confidence:     finding.ConfidenceLow,
			Payload:        map[string]any{"phase": "crack", "error": err.Error()},
		})
		// Don't return — --show may still yield previously-cracked hashes from the pot.
	}

	// Show pass — extracts the cracked hash:password pairs from the
	// session pot. Always runs even if crack pass errored.
	showArgs := []string{"--show", "--pot=" + potPath}
	if format != "" {
		showArgs = append(showArgs, "--format="+format)
	}
	showArgs = append(showArgs, hashPath)
	showResult, err := run(ctx, subprocess.Spec{
		Binary:         binary,
		Args:           showArgs,
		Timeout:        60 * time.Second,
		AllowPartialRC: []int{1, 2, 3},
	})
	if err != nil {
		return fmt.Errorf("john --show: %w", err)
	}

	cracked := parseShowOutput(string(showResult.Stdout))
	for _, c := range cracked {
		// One finding per cracked password.
		if _, err := cctx.EmitFinding(fact.FindingFact{
			Title:       fmt.Sprintf("Cracked credential: %s", c.User),
			Severity:    finding.SeverityHigh,
			Confidence:  finding.ConfidenceConfirmed,
			Category:    "credential.cracked",
			Description: fmt.Sprintf("John the Ripper recovered the cleartext password for %s.", c.User),
			Attributes: map[string]any{
				"username":  c.User,
				"password":  c.Password,
				"format":    format,
				"wordlist":  wordlist,
			},
		}); err != nil {
			return err
		}
	}

	return cctx.EmitEvidence(fact.EvidenceFact{
		SourceTool:     Name,
		SourceCategory: finding.SourceManual,
		Confidence:     finding.ConfidenceHigh,
		Payload: map[string]any{
			"hashes_loaded":  len(cleanHashes),
			"hashes_cracked": len(cracked),
			"format":         format,
			"wordlist":       wordlist,
			"rules":          rules,
		},
	})
}

type crackedPair struct {
	User     string
	Password string
}

// parseShowOutput parses the output of `john --show`. The line shape
// is `user:password:...:::` (extra fields are gecos info from the
// original input file). Trailing summary lines like
// "N password hashes cracked, M left" are ignored.
func parseShowOutput(stdout string) []crackedPair {
	var out []crackedPair
	for _, line := range strings.Split(stdout, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// Skip summary lines.
		if strings.HasSuffix(line, "left") || strings.HasSuffix(line, "cracked") ||
			strings.Contains(line, "password hashes") {
			continue
		}
		parts := strings.SplitN(line, ":", 3)
		if len(parts) < 2 {
			continue
		}
		user := strings.TrimSpace(parts[0])
		pwd := parts[1]
		// john sometimes emits a no-user prefix like ":password" — keep
		// those as "(unknown)" so the operator at least sees the password.
		if user == "" {
			user = "(unknown)"
		}
		out = append(out, crackedPair{User: user, Password: pwd})
	}
	return out
}

func parseTimeout(v any) time.Duration {
	switch x := v.(type) {
	case float64:
		if x > 0 {
			return time.Duration(x * float64(time.Second))
		}
	case int:
		if x > 0 {
			return time.Duration(x) * time.Second
		}
	}
	return defaultTimeout
}

func parseStringList(v any) []string {
	switch s := v.(type) {
	case []string:
		return s
	case []any:
		out := make([]string, 0, len(s))
		for _, x := range s {
			if str, ok := x.(string); ok {
				out = append(out, str)
			}
		}
		return out
	case string:
		if s == "" {
			return nil
		}
		return []string{s}
	}
	return nil
}

func toString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

// keep entity import alive so go fmt doesn't drop it; collectors that
// declare Consumes will need it again.
var _ = entity.KindPerson
