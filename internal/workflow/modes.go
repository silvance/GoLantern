package workflow

import (
	"github.com/silvance/golantern/internal/project"
	"github.com/silvance/golantern/internal/scope"
)

// ModePreset captures the per-mode defaults the UI consults. Mirrors
// lantern.workflow.modes.ModePreset.
//
// SuggestedScopeKind is what the SPA proposes when the operator adds a
// new ScopeRule; it does NOT change Project.DefaultScope automatically.
// RecommendedTools is phase -> ordered tool names; tools missing from
// the registry at lookup time are silently skipped (in Python, anyway),
// so callers can safely add new tool names here before the collector
// exists. ReportTemplate is the logical template name; the reporting
// package branches on it.
type ModePreset struct {
	SuggestedScopeKind scope.RuleKind
	RecommendedTools   map[Phase][]string
	ReportTemplate     string
}

// presets is the master per-mode configuration. Adding a new mode means
// adding one entry here and one report-template branch in the report
// package.
var presets = map[project.Mode]ModePreset{
	project.ModeAssessment: {
		SuggestedScopeKind: scope.KindLightActive,
		RecommendedTools: map[Phase][]string{
			PhaseOSINT:          {"crtsh", "theharvester", "sherlock"},
			PhaseAssetDiscovery: {"crtsh", "subfinder", "amass", "dnsx"},
			PhaseValidation:     {"httpx_probe", "gowitness", "dnsx", "naabu", "msf_smb_version", "msf_ssh_version"},
			PhaseExposure:       {"nuclei", "testssl", "wpscan", "msf_smb_enumshares", "msf_ftp_anonymous"},
			PhaseEnrichment:     {"tlsx", "cloud_bucket", "holehe", "shodan", "censys", "hibp"},
		},
		ReportTemplate: "standard",
	},
	project.ModeBugBounty: {
		// Bounty programs authorize active testing on in-scope assets;
		// surface FULL_ACTIVE so the operator doesn't have to bump it.
		// Scope rules still gate per-target.
		SuggestedScopeKind: scope.KindFullActive,
		RecommendedTools: map[Phase][]string{
			PhaseOSINT:          {"crtsh", "github_repos", "theharvester", "sherlock", "maigret"},
			PhaseAssetDiscovery: {"crtsh", "subfinder", "amass", "dnsx", "historical_urls"},
			PhaseValidation:     {"httpx_probe", "gowitness", "naabu", "msf_smb_version", "msf_ssh_version", "msf_rdp_scanner"},
			PhaseExposure:       {"nuclei", "katana", "testssl", "wpscan", "msf_smb_enumshares", "msf_ftp_anonymous", "msf_snmp_login", "msf_vnc_none_auth"},
			PhaseEnrichment:     {"tlsx", "cloud_bucket", "holehe", "trufflehog", "shodan"},
		},
		ReportTemplate: "bug_bounty",
	},
	project.ModeCTF: {
		// HTB / lab boxes are explicitly authorized for whatever you can
		// throw at them; FULL_ACTIVE is the right floor. OSINT,
		// ASSET_DISCOVERY, and ENRICHMENT are deliberately empty: a CTF
		// box has one IP and no DNS / breach-data context.
		SuggestedScopeKind: scope.KindFullActive,
		RecommendedTools: map[Phase][]string{
			PhaseValidation: {"nmap", "naabu", "httpx_probe", "gowitness", "whatweb"},
			PhaseExposure:   {"feroxbuster", "ffuf", "gobuster", "nikto", "nuclei", "katana", "wpscan", "smbmap", "enum4linux_ng", "netexec"},
		},
		ReportTemplate: "ctf",
	},
}

// PresetFor returns the preset for mode. Panics if mode is unknown —
// callers that accept Mode from external input should validate via
// project.Mode.Valid first. This is the Go equivalent of Python's
// KeyError; we make it loud because reaching this with a bad mode is a
// type-system failure, not a runtime condition to handle.
func PresetFor(mode project.Mode) ModePreset {
	p, ok := presets[mode]
	if !ok {
		panic("workflow: unknown project mode " + string(mode))
	}
	return p
}

// RecommendedToolsForPhase returns the ordered tool hints for phase
// under mode. An empty slice is meaningful — "this mode has no opinion,
// surface the full collector list in registry order."
//
// The returned slice is a copy so callers may reorder or append without
// corrupting the preset.
func RecommendedToolsForPhase(mode project.Mode, phase Phase) []string {
	src := PresetFor(mode).RecommendedTools[phase]
	if len(src) == 0 {
		return nil
	}
	out := make([]string, len(src))
	copy(out, src)
	return out
}
