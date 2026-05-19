// Package nmap wraps the nmap CLI as a Lantern collector.
//
// Foundational active step: take the IP entities discovered earlier
// (or an explicit target list), scan for open ports, and emit one
// SERVICE entity per (host, port) with a canonical service_name. The
// canonical names drive the next-steps card on the SPA — an open
// 445 lights up SMB collectors, an open 80/443 lights up web
// collectors, etc.
//
// Output parsing uses nmap's -oX XML (stable, documented). Service
// names get normalized through canonicalService because nmap reports
// raw protocol identifiers (microsoft-ds, ms-wbt-server, http-proxy)
// that don't match the canonical names other collectors emit.
//
// Ported from lantern/tools/nmap.py.
package nmap

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"strconv"
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
	Name           = "nmap"
	defaultBinary  = "nmap"
	defaultTimeout = 600 * time.Second
	defaultTiming  = "T3"
)

// serviceAliases maps nmap's raw service identifiers to the
// canonical names other Lantern collectors emit. Anything not in
// this map falls through unchanged so the SERVICE entity still has a
// usable service_name even for protocols the SPA doesn't know about.
var serviceAliases = map[string]string{
	// SMB / NetBIOS
	"microsoft-ds": "smb",
	"netbios-ssn":  "smb",
	"smb":          "smb",
	// RDP
	"ms-wbt-server": "rdp",
	"ms-wbt":        "rdp",
	"rdp":           "rdp",
	// HTTP family
	"http":       "http",
	"http-proxy": "http",
	"http-alt":   "http",
	"https":      "https",
	"https-alt":  "https",
	"ssl/http":   "https",
	// Mail
	"smtp":       "smtp",
	"submission": "smtp",
	"smtps":      "smtp",
	"ssl/smtp":   "smtp",
	// Databases
	"mysql":      "mysql",
	"postgresql": "postgres",
	"ms-sql-s":   "mssql",
	"ms-sql-m":   "mssql",
	// AD-adjacent
	"ldap":         "ldap",
	"ldaps":        "ldap",
	"ssl/ldap":     "ldap",
	"kerberos-sec": "kerberos",
	"kerberos":     "kerberos",
	"kpasswd5":     "kerberos",
	// DNS
	"domain": "dns",
	// SNMP / VNC / FTP / SSH
	"snmp":     "snmp",
	"vnc":      "vnc",
	"vnc-1":    "vnc",
	"vnc-2":    "vnc",
	"vnc-3":    "vnc",
	"ftp":      "ftp",
	"ftps":     "ftp",
	"ftp-data": "ftp",
	"ssh":      "ssh",
}

func canonicalService(raw string) string {
	name := strings.ToLower(strings.TrimSpace(raw))
	if name == "" {
		return "unknown"
	}
	if c, ok := serviceAliases[name]; ok {
		return c
	}
	return name
}

// New returns a collector using the default nmap binary on PATH.
func New() scan.Collector { return &collector{} }

// runnerFn is the subprocess invoker the collector calls. Production
// path is subprocess.Run; tests inject a stub that returns canned XML
// so the suite doesn't need nmap installed.
type runnerFn func(ctx context.Context, spec subprocess.Spec) (subprocess.Result, error)

// newWithRunner is exported via an internal accessor for tests; the
// public API surface stays New().
func newWithRunner(r runnerFn) scan.Collector { return &collector{runner: r} }

type collector struct {
	runner runnerFn // nil falls back to subprocess.Run
}

func (collector) Metadata() scan.Meta {
	return scan.Meta{
		Name:           Name,
		Phase:          workflow.PhaseValidation,
		RequiredScope:  scope.KindLightActive,
		Description:    "TCP port + service discovery via nmap. Produces one SERVICE entity per open port.",
		Consumes:       []entity.Kind{entity.KindIP},
		Produces:       []entity.Kind{entity.KindService},
		SourceCategory: finding.SourceLiveProbe,
		TriggersOnServices: nil,
		Binary:         "nmap",
		InstallHint: "Debian/Ubuntu/Kali: apt install nmap\n" +
			"Fedora/RHEL:        dnf install nmap\n" +
			"macOS:              brew install nmap\n" +
			"Windows:            choco install nmap (or download from nmap.org)",
		Parameters: []scan.ParameterSpec{
			{Name: "targets", Type: "string_list", Placeholder: "10.0.0.5, 10.0.0.0/24",
				Description: "Hosts or CIDRs to scan. Empty falls back to every IP entity in the project."},
			{Name: "ports", Type: "string", Default: "top-1000", Placeholder: "top-1000",
				Description: "nmap port spec. Examples: 'top-1000', '1-1000', '22,80,443'. Use '-' for all 65535."},
			{Name: "service_detection", Type: "bool", Default: true,
				Description: "Run -sV to identify service+version per port. Drives the next-steps card."},
			{Name: "timing", Type: "enum", Default: "T3",
				Choices:     []string{"T0", "T1", "T2", "T3", "T4", "T5"},
				Description: "nmap timing template. T3 default, T4 aggressive, T5 insane."},
			{Name: "binary", Type: "string", Default: "nmap",
				Description: "Override the nmap binary path or name."},
			{Name: "timeout_seconds", Type: "float", Default: 600.0,
				Description: "Wall-clock timeout in seconds for the nmap subprocess."},
			{Name: "extra_args", Type: "string_list", Placeholder: "-sS, --script=safe",
				Description: "Extra nmap flags (comma-separated). Operator's responsibility to match scope."},
		},
	}
}

func (c *collector) Run(ctx context.Context, cctx scan.Context) error {
	binary, _ := cctx.Parameters()["binary"].(string)
	binary = strings.TrimSpace(binary)
	if binary == "" {
		binary = defaultBinary
	}
	timeout := parseTimeout(cctx.Parameters()["timeout_seconds"])
	ports := strings.TrimSpace(toString(cctx.Parameters()["ports"]))
	if ports == "" {
		ports = "top-1000"
	}
	serviceDetection := parseBoolDefault(cctx.Parameters()["service_detection"], true)
	timing := strings.TrimSpace(toString(cctx.Parameters()["timing"]))
	if timing == "" {
		timing = defaultTiming
	}
	extraArgs := parseStringList(cctx.Parameters()["extra_args"])

	targets, err := resolveTargets(cctx, parseStringList(cctx.Parameters()["targets"]))
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
		// No targets but no error either — the runner's zero-emission
		// diagnostic will surface the case where everything was
		// rejected. Same posture as Python.
		return nil
	}

	args := []string{"-oX", "-", "-" + timing}
	if serviceDetection {
		args = append(args, "-sV")
	}
	switch ports {
	case "top-1000":
		args = append(args, "--top-ports", "1000")
	case "-":
		args = append(args, "-p-")
	default:
		args = append(args, "-p", ports)
	}
	args = append(args, extraArgs...)
	args = append(args, inScope...)

	run := c.runner
	if run == nil {
		run = subprocess.Run
	}
	result, err := run(ctx, subprocess.Spec{
		Binary:         binary,
		Args:           args,
		Timeout:        timeout,
		AllowPartialRC: []int{1}, // rc=1 with valid XML is normal for partially-live ranges
	})
	if err != nil {
		// subprocess.BinaryNotFoundError keeps its identity; collector
		// returns the error as-is so the scan runner can downgrade it
		// to a warning without a traceback. Same for ExitError /
		// TimeoutError: they carry useful diagnostics.
		return fmt.Errorf("nmap: %w", err)
	}

	ports_, err := parseNmapXML(result.Stdout)
	if err != nil {
		return err
	}

	for _, p := range ports_ {
		attrs := map[string]any{
			"port":         p.Port,
			"protocol":     p.Protocol,
			"service_name": p.ServiceName,
			"raw_service":  p.RawService,
		}
		if p.Product != "" {
			attrs["product"] = p.Product
		}
		if p.Version != "" {
			attrs["version"] = p.Version
		}
		if p.ExtraInfo != "" {
			attrs["extrainfo"] = p.ExtraInfo
		}
		value := fmt.Sprintf("%s:%d/%s", p.Target, p.Port, p.ServiceName)
		conf := finding.ConfidenceMedium
		if p.Version != "" {
			conf = finding.ConfidenceHigh
		}
		if _, err := cctx.EmitEntity(fact.EntityFact{
			Kind:           entity.KindService,
			Value:          value,
			Attributes:     attrs,
			Confidence:     conf,
			SourceCategory: finding.SourceLiveProbe,
		}); err != nil {
			return err
		}
		if err := cctx.EmitEvidence(fact.EvidenceFact{
			SourceTool:     Name,
			SourceCategory: finding.SourceLiveProbe,
			Confidence:     conf,
			Payload: map[string]any{
				"target":       p.Target,
				"port":         p.Port,
				"protocol":     p.Protocol,
				"service_name": p.ServiceName,
				"raw_service":  p.RawService,
				"product":      p.Product,
				"version":      p.Version,
				"extrainfo":    p.ExtraInfo,
				"cpe":          p.CPE,
			},
			EntityKind:  entity.KindService,
			EntityValue: value,
		}); err != nil {
			return err
		}
	}
	return nil
}

func resolveTargets(cctx scan.Context, explicit []string) ([]string, error) {
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
	ips, err := cctx.ListEntityValues(entity.KindIP)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, ip := range ips {
		if ip = strings.TrimSpace(ip); ip != "" {
			out = append(out, ip)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("nmap: no targets to scan; pass parameters[\"targets\"] or seed IP entities")
	}
	return out, nil
}

// ----- XML parsing ----------------------------------------------------

// Stable subset of nmap's -oX output. Field names match the XML so
// the encoding/xml decoder can populate them by tag/attribute.
type nmaprun struct {
	XMLName xml.Name `xml:"nmaprun"`
	Hosts   []host   `xml:"host"`
}

type host struct {
	Addresses []address `xml:"address"`
	Ports     ports     `xml:"ports"`
}

type address struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"`
}

type ports struct {
	Ports []port `xml:"port"`
}

type port struct {
	Protocol string  `xml:"protocol,attr"`
	PortID   string  `xml:"portid,attr"`
	State    state   `xml:"state"`
	Service  service `xml:"service"`
}

type state struct {
	State string `xml:"state,attr"`
}

type service struct {
	Name      string   `xml:"name,attr"`
	Product   string   `xml:"product,attr"`
	Version   string   `xml:"version,attr"`
	ExtraInfo string   `xml:"extrainfo,attr"`
	CPEs      []string `xml:"cpe"`
}

// nmapPort is the projected shape downstream consumes.
type nmapPort struct {
	Target      string
	Port        int
	Protocol    string
	ServiceName string // canonicalized
	RawService  string
	Product     string
	Version     string
	ExtraInfo   string
	CPE         []string
}

func parseNmapXML(blob []byte) ([]nmapPort, error) {
	var doc nmaprun
	if err := xml.Unmarshal(blob, &doc); err != nil {
		return nil, fmt.Errorf("nmap: parse XML: %w", err)
	}
	var out []nmapPort
	for _, h := range doc.Hosts {
		// Prefer IPv4; fall back to IPv6 if that's all nmap saw.
		var target string
		for _, a := range h.Addresses {
			if a.AddrType == "ipv4" && a.Addr != "" {
				target = a.Addr
				break
			}
		}
		if target == "" {
			for _, a := range h.Addresses {
				if a.AddrType == "ipv6" && a.Addr != "" {
					target = a.Addr
					break
				}
			}
		}
		if target == "" {
			continue
		}
		for _, p := range h.Ports.Ports {
			if p.State.State != "open" {
				continue
			}
			portNum, err := strconv.Atoi(p.PortID)
			if err != nil || portNum <= 0 {
				continue
			}
			proto := p.Protocol
			if proto == "" {
				proto = "tcp"
			}
			out = append(out, nmapPort{
				Target:      target,
				Port:        portNum,
				Protocol:    proto,
				ServiceName: canonicalService(p.Service.Name),
				RawService:  p.Service.Name,
				Product:     p.Service.Product,
				Version:     p.Service.Version,
				ExtraInfo:   p.Service.ExtraInfo,
				CPE:         p.Service.CPEs,
			})
		}
	}
	return out, nil
}

// ----- parameter helpers ----------------------------------------------

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

func parseBoolDefault(v any, fallback bool) bool {
	if b, ok := v.(bool); ok {
		return b
	}
	return fallback
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
