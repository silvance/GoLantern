// Package winpeas parses WinPEAS output (the Windows-side privesc
// audit script). Mirrors the linpeas parser in shape: pattern-
// match known privesc indicators, emit one finding per category.
//
// WinPEAS sections we recognize and the findings they produce:
//   - AlwaysInstallElevated registry -> Critical
//   - SeImpersonatePrivilege / SeAssignPrimaryTokenPrivilege -> Critical (Potato attacks)
//   - Unquoted service paths -> High
//   - Writable service binaries -> High
//   - AutoLogon credentials in registry -> Critical
//   - LSA / SAM dump indicators -> Critical
//   - Stored credentials (cmdkey, vault) -> High
package winpeas

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/silvance/golantern/internal/entity"
	"github.com/silvance/golantern/internal/evidence"
	"github.com/silvance/golantern/internal/fact"
	"github.com/silvance/golantern/internal/finding"
)

const (
	Name        = "winpeas"
	description = "WinPEAS post-foothold Windows privesc audit. Paste the raw script output and we extract the actionable findings (AlwaysInstallElevated, SeImpersonatePrivilege, unquoted services, stored credentials, AutoLogon)."
)

func New() evidence.Parser { return &parser{} }

type parser struct{}

func (parser) Name() string        { return Name }
func (parser) Description() string { return description }

var (
	anyANSI = regexp.MustCompile(`\x1b\[[0-9;]*m`)

	// AlwaysInstallElevated: WinPEAS prints "AlwaysInstallElevated set to 1" when vulnerable.
	alwaysInstallRE = regexp.MustCompile(`(?i)AlwaysInstallElevated.*(?:=\s*1|set to 1|enabled)`)

	// Privilege tokens — match within Privileges section.
	dangerousPrivRE = regexp.MustCompile(`(?i)Se(Impersonate|AssignPrimaryToken|Backup|Restore|Debug|TakeOwnership|LoadDriver|Tcb)Privilege.*\b(Enabled|SE_PRIVILEGE_ENABLED)\b`)

	// Unquoted service path: service line where binary path has spaces and no surrounding quotes.
	unquotedServiceRE = regexp.MustCompile(`(?i)Unquoted Service Path Found.*?:\s*([A-Z]:\\[^\r\n]+)`)

	// AutoLogon creds in HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon.
	autoLogonRE = regexp.MustCompile(`(?i)(DefaultPassword|AutoAdminLogon)\s*[:=]\s*(\S+)`)

	// cmdkey / vault stored credentials.
	cmdkeyRE = regexp.MustCompile(`(?i)Target:\s*([^\r\n]+)`)

	// LSA / SAM dump indicators.
	lsaSamRE = regexp.MustCompile(`(?i)(LSA Secrets|SAM (file )?(found|accessible|readable)|NTDS\.dit)`)

	// OS version line.
	osVersionRE = regexp.MustCompile(`(?i)Windows\s+(Server\s+)?(\d{4}|\d+(?:\.\d+)+)`)
)

func stripANSI(s string) string { return anyANSI.ReplaceAllString(s, "") }

func (p parser) Parse(raw, target string) (evidence.Result, error) {
	var res evidence.Result
	if strings.TrimSpace(raw) == "" {
		return res, nil
	}

	var (
		alwaysInstall       bool
		dangerousPrivs      []string
		unquotedServices    []string
		autoLogonPresent    bool
		autoLogonAttrs      = map[string]any{}
		storedCredTargets   []string
		lsaSamIndicators    []string
		osVersion           string
	)

	for _, raw := range strings.Split(raw, "\n") {
		line := strings.TrimSpace(stripANSI(raw))
		if line == "" {
			continue
		}
		if alwaysInstallRE.MatchString(line) {
			alwaysInstall = true
		}
		if m := dangerousPrivRE.FindStringSubmatch(line); m != nil {
			dangerousPrivs = append(dangerousPrivs, "Se"+m[1]+"Privilege")
		}
		if m := unquotedServiceRE.FindStringSubmatch(line); m != nil {
			unquotedServices = append(unquotedServices, strings.TrimSpace(m[1]))
		}
		if m := autoLogonRE.FindStringSubmatch(line); m != nil {
			autoLogonPresent = true
			autoLogonAttrs[strings.ToLower(m[1])] = m[2]
		}
		if m := cmdkeyRE.FindStringSubmatch(line); m != nil {
			storedCredTargets = append(storedCredTargets, strings.TrimSpace(m[1]))
		}
		if m := lsaSamRE.FindStringSubmatch(line); m != nil {
			lsaSamIndicators = append(lsaSamIndicators, m[0])
		}
		if m := osVersionRE.FindStringSubmatch(line); m != nil && osVersion == "" {
			osVersion = strings.TrimSpace(m[0])
		}
	}

	addFinding := func(title, category, desc string, sev finding.Severity, attrs map[string]any) {
		if attrs == nil {
			attrs = map[string]any{}
		}
		if target != "" {
			attrs["target"] = target
		}
		f := fact.FindingFact{
			Title:       title,
			Severity:    sev,
			Confidence:  finding.ConfidenceHigh,
			Category:    category,
			Description: desc,
			Attributes:  attrs,
		}
		if target != "" {
			f.SupportingEntities = []fact.EntityRef{{Kind: entity.KindIP, Value: target}}
		}
		res.Findings = append(res.Findings, f)
	}

	if alwaysInstall {
		addFinding(
			fmt.Sprintf("AlwaysInstallElevated enabled on %s", targetOrSelf(target)),
			"privesc.always_install_elevated",
			"Both HKLM and HKCU AlwaysInstallElevated registry values are set to 1. Any user can install MSI packages with SYSTEM privileges — generate one with msfvenom (.msi) and run msiexec /quiet /qn /i payload.msi.",
			finding.SeverityCritical,
			nil,
		)
	}
	if len(dangerousPrivs) > 0 {
		// Filter to enabled privileges only.
		sev := finding.SeverityHigh
		for _, p := range dangerousPrivs {
			if p == "SeImpersonatePrivilege" || p == "SeAssignPrimaryTokenPrivilege" || p == "SeDebugPrivilege" || p == "SeTcbPrivilege" {
				sev = finding.SeverityCritical
				break
			}
		}
		addFinding(
			fmt.Sprintf("Dangerous privileges held on %s", targetOrSelf(target)),
			"privesc.token_privilege",
			"The current process token holds privileges that enable known SYSTEM-escalation primitives (Potato family for SeImpersonate/SeAssignPrimaryToken; SeDebug+token-stealing; SeBackup/Restore for SAM hive extraction).",
			sev,
			map[string]any{"privileges": dedupStrings(dangerousPrivs)},
		)
	}
	if len(unquotedServices) > 0 {
		addFinding(
			fmt.Sprintf("Unquoted service path on %s", targetOrSelf(target)),
			"privesc.unquoted_service_path",
			"Service binary path contains spaces and is unquoted; drop a malicious .exe at the appropriate parent path (e.g. C:\\Program.exe) to hijack service startup.",
			finding.SeverityHigh,
			map[string]any{"services": dedupStrings(unquotedServices)},
		)
	}
	if autoLogonPresent {
		addFinding(
			fmt.Sprintf("AutoLogon credentials in registry on %s", targetOrSelf(target)),
			"privesc.autologon_credentials",
			"DefaultPassword / AutoAdminLogon registry value present. Cleartext credentials readable by any authenticated user.",
			finding.SeverityCritical,
			autoLogonAttrs,
		)
	}
	if len(storedCredTargets) > 0 {
		addFinding(
			fmt.Sprintf("Stored credentials (cmdkey / Windows Vault) on %s", targetOrSelf(target)),
			"privesc.stored_credentials",
			"Cached credential targets accessible via cmdkey / runas /savecred / vaultcli. May permit lateral movement without recovering the cleartext.",
			finding.SeverityHigh,
			map[string]any{"targets": dedupStrings(storedCredTargets)},
		)
	}
	if len(lsaSamIndicators) > 0 {
		addFinding(
			fmt.Sprintf("SAM / LSA / NTDS dump indicators on %s", targetOrSelf(target)),
			"privesc.credential_dump",
			"WinPEAS reported accessibility of SAM, LSA secrets, or NTDS.dit. Combined with SeBackup/SeRestore or admin context this yields domain credentials.",
			finding.SeverityCritical,
			map[string]any{"indicators": dedupStrings(lsaSamIndicators)},
		)
	}

	if osVersion != "" {
		res.Entities = append(res.Entities, fact.EntityFact{
			Kind:           entity.KindTechnology,
			Value:          "windows/" + osVersion,
			Attributes:     map[string]any{"discovered_via": Name, "target": target},
			Confidence:     finding.ConfidenceHigh,
			SourceCategory: finding.SourceManual,
		})
	}

	res.Evidence = append(res.Evidence, fact.EvidenceFact{
		SourceTool:     Name,
		SourceCategory: finding.SourceManual,
		Confidence:     finding.ConfidenceMedium,
		Payload: map[string]any{
			"target":             target,
			"always_install":     alwaysInstall,
			"dangerous_privs":    dedupStrings(dangerousPrivs),
			"unquoted_services":  dedupStrings(unquotedServices),
			"auto_logon":         autoLogonPresent,
			"stored_cred_count":  len(storedCredTargets),
			"lsa_sam_indicators": len(lsaSamIndicators),
			"os_version":         osVersion,
		},
	})

	return res, nil
}

func targetOrSelf(t string) string {
	if t == "" {
		return "compromised host"
	}
	return t
}

func dedupStrings(in []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}
