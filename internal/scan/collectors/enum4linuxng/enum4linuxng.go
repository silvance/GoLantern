// Package enum4linuxng wraps enum4linux-ng for SMB / NetBIOS /
// Samba enumeration. The "next gen" rewrite emits structured JSON,
// which makes the parser cleaner than the original enum4linux's
// regex-the-stdout approach.
//
// Heavier than netexec's banner sweep — pulls users, groups,
// shares, RPC sessions, password policy, and OS info in one pass.
// Useful for CTF/internal engagements where a misconfigured Samba
// or unjoined Windows box leaks the whole user list anonymously.
package enum4linuxng

import (
	"context"
	"encoding/json"
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
	Name           = "enum4linux_ng"
	defaultBinary  = "enum4linux-ng"
	defaultTimeout = 600 * time.Second
)

func New() scan.Collector { return &collector{} }

type runnerFn func(ctx context.Context, spec subprocess.Spec) (subprocess.Result, error)

func newWithRunner(r runnerFn) scan.Collector { return &collector{runner: r} }

type collector struct{ runner runnerFn }

func (collector) Metadata() scan.Meta {
	return scan.Meta{
		Name:               Name,
		Phase:              workflow.PhaseValidation,
		RequiredScope:      scope.KindLightActive,
		Description:        "Deep SMB/NetBIOS/Samba enumeration via enum4linux-ng. Pulls users, groups, shares, RPC session info, and password policy in one pass; flags anonymous access.",
		Consumes:           []entity.Kind{entity.KindIP, entity.KindSubdomain},
		Produces:           []entity.Kind{entity.KindIP, entity.KindPerson},
		SourceCategory:     finding.SourceActiveScan,
		TriggersOnServices: []string{"smb", "netbios-ssn", "microsoft-ds"},
		Binary:             "enum4linux-ng",
		InstallHint:        "pipx install enum4linux-ng",
		Parameters: []scan.ParameterSpec{
			{Name: "targets", Type: "string_list", Placeholder: "10.0.0.5",
				Description: "SMB targets. Empty falls back to every IP + SUBDOMAIN entity."},
			{Name: "username", Type: "string", Default: "",
				Description: "Optional username; empty runs null-session enum."},
			{Name: "password", Type: "string", Default: ""},
			{Name: "binary", Type: "string", Default: "enum4linux-ng"},
			{Name: "timeout_seconds", Type: "float", Default: 600.0},
		},
	}
}

// e4lOutput is a permissive view of enum4linux-ng's JSON. The real
// schema is large; we only consume the sections we map to facts.
type e4lOutput struct {
	Target  string `json:"target"`
	NBTStat struct {
		Workgroup string                 `json:"workgroup"`
		Records   []map[string]any       `json:"records"`
		Raw       string                 `json:"raw"`
	} `json:"nbtstat"`
	SmbDialects map[string]any `json:"smb_dialects"`
	SessionsCheck struct {
		Anonymous map[string]any `json:"check_user_anonymous"`
	} `json:"sessions_check"`
	OSInfo  map[string]any            `json:"os_info"`
	Users   map[string]map[string]any `json:"users"`
	Groups  map[string]map[string]any `json:"groups"`
	Shares  map[string]map[string]any `json:"shares"`
	Policy  struct {
		MinPasswordLength int `json:"min_password_length"`
		PasswordComplexity bool `json:"password_complexity"`
		LockoutThreshold  int `json:"account_lockout_threshold"`
		MaxPasswordAge    string `json:"maximum_password_age"`
	} `json:"policy"`
}

func (c *collector) Run(ctx context.Context, cctx scan.Context) error {
	binary := strings.TrimSpace(toString(cctx.Parameters()["binary"]))
	if binary == "" {
		binary = defaultBinary
	}
	timeout := parseTimeout(cctx.Parameters()["timeout_seconds"])
	username := strings.TrimSpace(toString(cctx.Parameters()["username"]))
	password := toString(cctx.Parameters()["password"])

	targets, err := c.resolveTargets(cctx)
	if err != nil {
		return err
	}
	var inScope []string
	for _, t := range targets {
		if cctx.IsInScope(t) {
			inScope = append(inScope, t)
		}
	}
	if len(inScope) == 0 {
		return nil
	}

	run := c.runner
	if run == nil {
		run = subprocess.Run
	}

	totalFindings := 0
	for _, target := range inScope {
		tmp, err := os.MkdirTemp("", "golantern-e4l-")
		if err != nil {
			return fmt.Errorf("enum4linux_ng: tempdir: %w", err)
		}
		prefix := filepath.Join(tmp, "out")
		// -A = all checks, -oJ prefix writes prefix.json
		args := []string{"-A", "-oJ", prefix, target}
		if username != "" {
			args = append([]string{"-u", username, "-p", password}, args...)
		}
		_, runErr := run(ctx, subprocess.Spec{
			Binary:         binary,
			Args:           args,
			Timeout:        timeout,
			AllowPartialRC: []int{1, 2, 3},
		})
		if runErr != nil {
			os.RemoveAll(tmp)
			_ = cctx.EmitEvidence(fact.EvidenceFact{
				SourceTool:     Name,
				SourceCategory: finding.SourceActiveScan,
				Confidence:     finding.ConfidenceLow,
				Payload:        map[string]any{"target": target, "error": runErr.Error()},
				EntityKind:     entity.KindIP,
				EntityValue:    target,
			})
			continue
		}
		blob, err := os.ReadFile(prefix + ".json")
		os.RemoveAll(tmp)
		if err != nil {
			_ = cctx.EmitEvidence(fact.EvidenceFact{
				SourceTool:     Name,
				SourceCategory: finding.SourceActiveScan,
				Confidence:     finding.ConfidenceLow,
				Payload:        map[string]any{"target": target, "json_read_error": err.Error()},
				EntityKind:     entity.KindIP,
				EntityValue:    target,
			})
			continue
		}

		n, err := c.processOutput(cctx, target, blob, username == "")
		if err != nil {
			return err
		}
		totalFindings += n
	}
	return cctx.EmitEvidence(fact.EvidenceFact{
		SourceTool:     Name,
		SourceCategory: finding.SourceActiveScan,
		Confidence:     finding.ConfidenceHigh,
		Payload: map[string]any{
			"targets_scanned":  len(inScope),
			"findings_emitted": totalFindings,
		},
	})
}

func (c *collector) processOutput(cctx scan.Context, target string, blob []byte, nullSession bool) (int, error) {
	var rec e4lOutput
	if err := json.Unmarshal(blob, &rec); err != nil {
		_ = cctx.EmitEvidence(fact.EvidenceFact{
			SourceTool:     Name,
			SourceCategory: finding.SourceActiveScan,
			Confidence:     finding.ConfidenceLow,
			Payload:        map[string]any{"target": target, "parse_error": err.Error()},
			EntityKind:     entity.KindIP,
			EntityValue:    target,
		})
		return 0, nil
	}

	findings := 0

	// IP attribute enrichment.
	attrs := map[string]any{"discovered_via": Name}
	if rec.NBTStat.Workgroup != "" {
		attrs["smb_workgroup"] = rec.NBTStat.Workgroup
	}
	if len(rec.OSInfo) > 0 {
		attrs["os_info"] = rec.OSInfo
	}
	if _, err := cctx.EmitEntity(fact.EntityFact{
		Kind:           entity.KindIP,
		Value:          target,
		Attributes:     attrs,
		Confidence:     finding.ConfidenceHigh,
		SourceCategory: finding.SourceActiveScan,
	}); err != nil {
		return findings, err
	}

	// Each enumerated user becomes a PERSON entity. Doesn't make
	// sense to do this for the "Administrator/Guest" builtin set on
	// every Windows box, but the operator can post-filter; emitting
	// is cheap and dedup handles repeats across targets.
	for _, info := range rec.Users {
		name, _ := info["username"].(string)
		if name == "" {
			continue
		}
		if _, err := cctx.EmitEntity(fact.EntityFact{
			Kind:           entity.KindPerson,
			Value:          name,
			Attributes:     map[string]any{"discovered_via": Name, "source_host": target, "smb_uid": info["RID"]},
			Confidence:     finding.ConfidenceMedium,
			SourceCategory: finding.SourceActiveScan,
		}); err != nil {
			return findings, err
		}
	}

	// Findings — only fire when we actually got data anonymously
	// (or with explicit creds, which is also worth flagging if the
	// creds were "guest"-tier).
	if nullSession && len(rec.Users) > 0 {
		users := make([]string, 0, len(rec.Users))
		for _, info := range rec.Users {
			if n, _ := info["username"].(string); n != "" {
				users = append(users, n)
			}
		}
		if _, err := cctx.EmitFinding(fact.FindingFact{
			Title:       fmt.Sprintf("Anonymous SMB user enumeration on %s", target),
			Severity:    finding.SeverityMedium,
			Confidence:  finding.ConfidenceHigh,
			Category:    "smb.anonymous_user_enum",
			Description: fmt.Sprintf("Host %s leaks the local user list via anonymous SMB. %d accounts retrieved. Restrict via 'RestrictAnonymous=2' or disable SMBv1.", target, len(users)),
			Attributes:  map[string]any{"target": target, "users": users},
			SupportingEntities: []fact.EntityRef{{Kind: entity.KindIP, Value: target}},
		}); err != nil {
			return findings, err
		}
		findings++
	}

	// Writable share + sensitive share detection.
	for shareName, info := range rec.Shares {
		mapping, _ := info["mapping"].(string)
		access, _ := info["access"].(string)
		if mapping == "" {
			continue
		}
		if access == "WRITE" || access == "OK_WRITE" || strings.Contains(access, "WRITE") {
			if _, err := cctx.EmitFinding(fact.FindingFact{
				Title:       fmt.Sprintf("Writable SMB share %s on %s", shareName, target),
				Severity:    finding.SeverityHigh,
				Confidence:  finding.ConfidenceHigh,
				Category:    "smb.writable_share",
				Description: fmt.Sprintf("Share %s on %s is writable. Drop a payload, malicious .lnk, or replace executables.", shareName, target),
				Attributes:  map[string]any{"target": target, "share": shareName, "access": access},
				SupportingEntities: []fact.EntityRef{{Kind: entity.KindIP, Value: target}},
			}); err != nil {
				return findings, err
			}
			findings++
		}
	}

	// Weak password policy finding.
	if rec.Policy.MinPasswordLength > 0 && rec.Policy.MinPasswordLength < 8 {
		if _, err := cctx.EmitFinding(fact.FindingFact{
			Title:       fmt.Sprintf("Weak SMB password policy on %s (min %d chars)", target, rec.Policy.MinPasswordLength),
			Severity:    finding.SeverityMedium,
			Confidence:  finding.ConfidenceHigh,
			Category:    "smb.weak_password_policy",
			Description: fmt.Sprintf("Minimum password length on %s is %d, below the conventional 8-char floor.", target, rec.Policy.MinPasswordLength),
			Attributes: map[string]any{
				"target":             target,
				"min_password_length": rec.Policy.MinPasswordLength,
				"complexity":         rec.Policy.PasswordComplexity,
				"lockout_threshold":  rec.Policy.LockoutThreshold,
			},
			SupportingEntities: []fact.EntityRef{{Kind: entity.KindIP, Value: target}},
		}); err != nil {
			return findings, err
		}
		findings++
	}

	_ = cctx.EmitEvidence(fact.EvidenceFact{
		SourceTool:     Name,
		SourceCategory: finding.SourceActiveScan,
		Confidence:     finding.ConfidenceHigh,
		Payload: map[string]any{
			"target":      target,
			"workgroup":   rec.NBTStat.Workgroup,
			"users":       len(rec.Users),
			"groups":      len(rec.Groups),
			"shares":      len(rec.Shares),
			"null_session": nullSession,
		},
		EntityKind:  entity.KindIP,
		EntityValue: target,
	})
	return findings, nil
}

func (c *collector) resolveTargets(cctx scan.Context) ([]string, error) {
	explicit := parseStringList(cctx.Parameters()["targets"])
	if len(explicit) > 0 {
		out := make([]string, 0, len(explicit))
		for _, t := range explicit {
			if t = strings.TrimSpace(t); t != "" {
				out = append(out, t)
			}
		}
		if len(out) > 0 {
			return out, nil
		}
	}
	var out []string
	for _, kind := range []entity.Kind{entity.KindIP, entity.KindSubdomain} {
		values, err := cctx.ListEntityValues(kind)
		if err != nil {
			return nil, err
		}
		out = append(out, values...)
	}
	if len(out) == 0 {
		return nil, errors.New("enum4linux_ng: no targets; pass parameters[\"targets\"] or seed IP/SUBDOMAIN entities")
	}
	return out, nil
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
