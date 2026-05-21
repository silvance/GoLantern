# Collectors

GoLantern ships 39 collectors covering the LCVA workflow phases:

| Phase | Collectors |
|---|---|
| OSINT | `theharvester`, `sherlock`, `maigret`, `fixture` |
| Asset Discovery | `crtsh`, `subfinder`, `amass`, `dnsrecon`, `historical_urls`, `github_repos` |
| Validation | `dnsx`, `httpx_probe`, `gowitness`, `nmap`, `naabu`, `whatweb`, `snmpwalk`, `netexec`, `enum4linux_ng`, `ffuf`, `smbmap` |
| Exposure | `nuclei`, `katana`, `nikto`, `testssl`, `wpscan`, `ssh_audit`, `smtp_user_enum`, `john`, `email_security` |
| Enrichment | `whois`, `tlsx`, `cloud_bucket`, `holehe`, `searchsploit`, `shodan`, `censys`, `hibp`, `trufflehog`, `exiftool` |

Plus a separate **evidence-ingest** surface for post-foothold output —
see "Evidence ingestion" below.

21 of these were ported from the Python lantern codebase; 18 are new
additions that close gaps in the Python set:

- **OSINT:** `maigret` (deep pass paired with sherlock)
- **Asset discovery:** `amass`, `dnsrecon` (broader source coverage + AXFR zone transfers)
- **Validation:** `naabu` (fast port sweep), `whatweb` (rich tech fingerprint), `snmpwalk` (SNMP enumeration), `netexec`, `enum4linux_ng` (SMB / post-foothold enum for CTF mode)
- **Exposure:** `katana` (modern crawler), `wpscan`, `ssh_audit`, `smtp_user_enum`, `john` (offline hash cracking)
- **Enrichment:** `whois`, `tlsx`, `cloud_bucket`, `holehe`, `searchsploit` (offline ExploitDB lookup)

## How collectors are organized

Each collector lives in `internal/scan/collectors/<name>/` as a Go
package. The package exports:

- `Name` constant (the slug registered with the scan engine).
- `New() scan.Collector` factory.
- For CLI-wrapping collectors: an unexported `newWithRunner(runnerFn)`
  used by package-internal tests to swap out the subprocess invocation.
- For HTTP-API collectors: `NewWithClient(*http.Client, baseURL)` so
  tests can point at an `httptest.Server`.

Every collector ships unit tests that exercise its happy path plus the
two failure modes that matter most: missing-input rejection and
out-of-scope target short-circuit.

## Skipped collectors and why

Lantern's Python codebase ships ~30 collectors. We deliberately do
not port everything — some are near-duplicates of a tool that's
already ported and some require infrastructure that doesn't have a
clean Go equivalent.

### Skipped — covered by a representative

| Python collector | Why skipped | Reach the same outcome via |
|---|---|---|
| `gobuster`, `feroxbuster` | Web-content brute force; same shape as `ffuf` (wordlist + URL template + JSON-ish output). | `ffuf` (operators who need a different binary can swap it via the `binary` parameter — the wrapper accepts compatible JSON output shapes). |
| `crackmapexec` | Renamed to `netexec`; same shape. | `netexec`. |
| `gau` | Wayback / Common Crawl URL discovery. Sister tool to waybackurls with identical "domain in, URL line out" contract. | `historical_urls` with `binary=gau`. |
| `sslscan` | TLS posture; output shape is a subset of testssl's. | `testssl`. |
| `kerbrute` | Kerberos pre-auth username enumeration. | `smbmap` + `netexec` SMB enum cover most cases; Kerberos-specific brute is a niche we'd add back when an engagement needs it. |
| `whatsmyname`, `knowem`, `blackbird`, `socialscan` | Username enumeration. Same shape as `sherlock`/`maigret`; whatsmyname is primarily a site-list database that sherlock already imports, knowem is a SaaS not a CLI. | `sherlock` (fast) + `maigret` (deep) cover the surface. |

### Skipped — needs infrastructure that isn't ported

| Python collector | Why skipped |
|---|---|
| `msf_aux`, `msf_check`, `_msf.py` | Wraps Metasploit's RPC API via `pymetasploit3`. There's no clean Go equivalent of `pymetasploit3` — the Metasploit RPC client is a non-trivial dependency that would justify its own package. We treat this as a separate project. |

### Skipped — superseded

| Python collector | Why skipped |
|---|---|
| `example` | Demo collector. GoLantern's `fixture` collector is the equivalent. |

## What if I need a collector that's marked skipped?

For the "covered by a representative" group, the simplest path is to
add a `binary` parameter override on the representative collector if
the alternative has compatible output. For the "needs infrastructure"
group, opening an issue with the engagement context is the right
escalation — adding `pymetasploit3`-equivalent or the artifact
subsystem is a larger piece of work that benefits from coordination.

If you need one of the skipped collectors as its own package, copy
the most similar ported one (`ffuf` for content discovery, `nuclei`
for vuln scanners, `shodan` for HTTP-API enrichers, etc.) and adjust
the parser. The framework around each collector — subprocess
plumbing, scope gating, evidence/finding emission, JSONL parsing
helpers — stays identical.

## Evidence ingestion (post-foothold workflow)

Collectors run from the operator's machine and shell out to a binary.
That model doesn't fit tools that run **on** the compromised target —
LinPEAS, WinPEAS, mimikatz output captured via reverse shell, etc.
For those, GoLantern exposes a separate "paste evidence" surface:

- **API:** `POST /api/v1/projects/{id}/evidence/ingest` with
  `{tool, content, target?, notes?}`. Returns counts of entities /
  findings / evidence rows emitted.
- **SPA:** the project's **Ingest** tab. Pick a parser, paste the
  output, optionally set the target host, hit Ingest. Parsed
  findings show up in the **Findings** tab alongside scanner output.
- **List parsers:** `GET /api/v1/evidence/parsers`.

### Built-in parsers

| Parser | Source tool | Highlights extracted |
|---|---|---|
| `linpeas` | LinPEAS (Linux privesc audit script) | SUID GTFOBins entries (Critical), NOPASSWD sudo (High), world-writable system files (High), SSH key references (Medium), cleartext credentials (High), kernel version → Technology entity |
| `winpeas` | WinPEAS (Windows privesc audit script) | AlwaysInstallElevated (Critical), dangerous token privileges incl. Potato-family (Critical), unquoted service paths (High), AutoLogon registry creds (Critical), cmdkey / Windows Vault stored creds (High), SAM/LSA/NTDS dump indicators (Critical) |

Adding a new parser is roughly 200 lines: implement the
`evidence.Parser` interface (`Name`, `Description`, `Parse`) and
register it in `cmd/golantern/main.go` next to the existing pair.
The parser is pure — it takes raw text and returns
EntityFact/FindingFact/EvidenceFact — so the existing persistence
plumbing handles the rest.
