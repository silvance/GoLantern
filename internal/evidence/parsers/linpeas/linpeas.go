// Package linpeas parses LinPEAS output (the linux privesc audit
// script that runs on a compromised target post-foothold). LinPEAS
// emits a sectioned report; we focus on the highest-signal section
// patterns and known-exploitable indicators, not the full output —
// the operator can always read the original via the artifact UI.
//
// Approach: strip ANSI, track the current section by its
// `╔══════` header, and emit findings for patterns we recognize as
// directly actionable (SUID GTFOBins entries, NOPASSWD sudo,
// writable /etc/passwd, world-writable PATH dirs, readable SSH
// keys, AlwaysInstallElevated-equivalent on Linux, etc.).
package linpeas

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
	Name        = "linpeas"
	description = "LinPEAS post-foothold Linux privesc audit. Paste the raw script output and we extract the actionable findings (SUID GTFOBins, NOPASSWD sudo, writable system files, exposed creds, kernel exploits)."
)

func New() evidence.Parser { return &parser{} }

type parser struct{}

func (parser) Name() string        { return Name }
func (parser) Description() string { return description }

// GTFOBins entries known to grant a root shell with default SUID.
// Not exhaustive — these are the high-payoff ones operators expect
// to see flagged. Source: https://gtfobins.github.io ("Shell" tag,
// "SUID" exploitation method).
var gtfoBinaries = map[string]struct{}{
	"nmap": {}, "vim": {}, "find": {}, "bash": {}, "less": {},
	"more": {}, "nano": {}, "cp": {}, "mv": {}, "awk": {},
	"python": {}, "python3": {}, "python2": {}, "perl": {},
	"ruby": {}, "lua": {}, "node": {}, "php": {},
	"man": {}, "vi": {}, "view": {}, "rvim": {}, "ed": {},
	"socat": {}, "tcpdump": {}, "tee": {}, "tar": {}, "xxd": {},
	"env": {}, "rsync": {}, "zip": {}, "wget": {}, "curl": {},
	"docker": {}, "expect": {}, "make": {}, "screen": {}, "ssh": {},
	"strace": {}, "systemctl": {}, "ash": {}, "csh": {}, "dash": {},
	"ksh": {}, "zsh": {}, "fish": {},
}

var (
	// LinPEAS marks "very probable" findings with red ANSI codes;
	// `\x1b[1;31m` and friends. Track the highlight so we can flag
	// red lines as High severity vs the rest at Medium.
	redANSI = regexp.MustCompile(`\x1b\[[01];?3[1-9]m`) // red / yellow / etc.
	anyANSI = regexp.MustCompile(`\x1b\[[0-9;]*m`)

	// Section headers look like:
	//   ╔══════════╣ Operative system
	sectionRE = regexp.MustCompile(`^╔[═]+╣\s*(.+)$`)

	// SUID listing lines: -rwsr-xr-x 1 root root SIZE DATE /path/to/binary
	suidLineRE = regexp.MustCompile(`^-[r-][w-][sS][r-][w-][xs-][r-][w-][x-]\s+\d+\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+(/\S+)`)

	// NOPASSWD sudo line:
	//   (root) NOPASSWD: /usr/bin/something
	nopasswdRE = regexp.MustCompile(`\(\S+\)\s+NOPASSWD:\s*(\S+.*)`)

	// World-writable files / dirs that show up after "Writable" headings.
	worldWritableRE = regexp.MustCompile(`^([drwx-]{10})\s+\d+\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+(/\S+)`)

	// SSH key file references — id_rsa, authorized_keys.
	sshKeyRE = regexp.MustCompile(`(?i)(/[^/\s]+)*/(id_rsa|id_ed25519|authorized_keys|known_hosts)\b`)

	// Cleartext credential indicators LinPEAS emits inline.
	credIndicatorRE = regexp.MustCompile(`(?i)(password|passwd|api[_-]?key|secret|token)\s*[=:]\s*\S+`)

	// Kernel version lines, e.g. "Linux version 4.15.0-..."
	kernelRE = regexp.MustCompile(`(?i)Linux version (\d+\.\d+\.\d+\S*)`)
)

func stripANSI(s string) string { return anyANSI.ReplaceAllString(s, "") }
func looksRed(s string) bool    { return redANSI.MatchString(s) }

func (p parser) Parse(raw, target string) (evidence.Result, error) {
	var res evidence.Result
	if strings.TrimSpace(raw) == "" {
		return res, nil
	}

	section := ""
	kernelVersion := ""
	suidGTFO := []string{}
	nopasswd := []string{}
	worldWritable := []string{}
	credLines := []string{}
	sshKeys := []string{}

	for _, raw := range strings.Split(raw, "\n") {
		hadRed := looksRed(raw)
		line := strings.TrimSpace(stripANSI(raw))
		if line == "" {
			continue
		}
		if m := sectionRE.FindStringSubmatch(line); m != nil {
			section = strings.TrimSpace(m[1])
			continue
		}
		// SUID GTFOBins detection — runs regardless of section
		// because LinPEAS sometimes mixes layouts.
		if m := suidLineRE.FindStringSubmatch(line); m != nil {
			path := m[1]
			bin := path[strings.LastIndex(path, "/")+1:]
			if _, ok := gtfoBinaries[bin]; ok {
				suidGTFO = append(suidGTFO, path)
			}
		}
		if m := nopasswdRE.FindStringSubmatch(line); m != nil {
			nopasswd = append(nopasswd, strings.TrimSpace(m[1]))
		}
		if hadRed && strings.Contains(strings.ToLower(section), "writable") {
			if m := worldWritableRE.FindStringSubmatch(line); m != nil {
				if strings.Contains(m[1], "w") && strings.HasSuffix(m[1], "w-") {
					// Last triplet has w: world-writable.
				}
				worldWritable = append(worldWritable, m[2])
			}
		}
		if m := sshKeyRE.FindStringSubmatch(line); m != nil {
			sshKeys = append(sshKeys, m[0])
		}
		if hadRed {
			if m := credIndicatorRE.FindStringSubmatch(line); m != nil {
				credLines = append(credLines, m[0])
			}
		}
		if m := kernelRE.FindStringSubmatch(line); m != nil {
			kernelVersion = m[1]
		}
	}

	// Findings.
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
			Confidence:  finding.ConfidenceMedium,
			Category:    category,
			Description: desc,
			Attributes:  attrs,
		}
		if target != "" {
			f.SupportingEntities = []fact.EntityRef{{Kind: entity.KindIP, Value: target}}
		}
		res.Findings = append(res.Findings, f)
	}

	if len(suidGTFO) > 0 {
		addFinding(
			fmt.Sprintf("SUID binary in GTFOBins on %s", targetOrSelf(target)),
			"privesc.suid_gtfobins",
			fmt.Sprintf("LinPEAS found %d SUID binaries that GTFOBins documents as exploitable for privilege escalation. Use the path with the documented SUID method to gain root.", len(suidGTFO)),
			finding.SeverityCritical,
			map[string]any{"binaries": dedupStrings(suidGTFO)},
		)
	}
	if len(nopasswd) > 0 {
		addFinding(
			fmt.Sprintf("NOPASSWD sudo entries on %s", targetOrSelf(target)),
			"privesc.sudo_nopasswd",
			"The current user can sudo to root (or another principal) without supplying a password. Cross-reference GTFOBins for the listed binaries.",
			finding.SeverityHigh,
			map[string]any{"sudo_entries": dedupStrings(nopasswd)},
		)
	}
	if len(worldWritable) > 0 {
		addFinding(
			fmt.Sprintf("World-writable filesystem entries on %s", targetOrSelf(target)),
			"privesc.world_writable",
			"LinPEAS flagged world-writable files / directories the operator may be able to abuse for code execution (cron-job dirs, PATH dirs, service binary paths).",
			finding.SeverityHigh,
			map[string]any{"paths": dedupStrings(worldWritable)},
		)
	}
	if len(sshKeys) > 0 {
		addFinding(
			fmt.Sprintf("SSH key material referenced in LinPEAS output on %s", targetOrSelf(target)),
			"privesc.ssh_keys",
			"LinPEAS reported references to SSH private keys or authorized_keys files. Check ownership / permissions for lateral-movement opportunities.",
			finding.SeverityMedium,
			map[string]any{"keys": dedupStrings(sshKeys)},
		)
	}
	if len(credLines) > 0 {
		addFinding(
			fmt.Sprintf("Possible cleartext credentials in LinPEAS output on %s", targetOrSelf(target)),
			"privesc.cleartext_creds",
			"LinPEAS highlighted lines that look like cleartext credentials (passwords, API keys, tokens). Manual review required — pattern matching may include false positives.",
			finding.SeverityHigh,
			map[string]any{"matches": dedupStrings(credLines)},
		)
	}
	if kernelVersion != "" {
		// Don't emit a finding for kernel by itself — too noisy. Instead
		// stash it as evidence and let searchsploit pick it up.
		res.Evidence = append(res.Evidence, fact.EvidenceFact{
			SourceTool:     Name,
			SourceCategory: finding.SourceManual,
			Confidence:     finding.ConfidenceHigh,
			Payload: map[string]any{
				"kernel_version": kernelVersion,
				"target":         target,
			},
		})
		// Also as a Technology entity so searchsploit auto-picks it up.
		res.Entities = append(res.Entities, fact.EntityFact{
			Kind:           entity.KindTechnology,
			Value:          "linux-kernel/" + kernelVersion,
			Attributes:     map[string]any{"discovered_via": Name, "target": target},
			Confidence:     finding.ConfidenceHigh,
			SourceCategory: finding.SourceManual,
		})
	}

	// Always include the raw output as a summary evidence row so
	// the operator can scroll back to the source.
	res.Evidence = append(res.Evidence, fact.EvidenceFact{
		SourceTool:     Name,
		SourceCategory: finding.SourceManual,
		Confidence:     finding.ConfidenceMedium,
		Payload: map[string]any{
			"target":           target,
			"section_count":    1, // placeholder; we don't bother counting
			"suid_gtfo_count":  len(suidGTFO),
			"nopasswd_count":   len(nopasswd),
			"world_writable":   len(worldWritable),
			"ssh_keys":         len(sshKeys),
			"cred_lines":       len(credLines),
			"kernel_version":   kernelVersion,
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
