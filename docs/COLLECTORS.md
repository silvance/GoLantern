# Collectors

GoLantern ships 29 collectors covering the LCVA workflow phases:

| Phase | Collectors |
|---|---|
| OSINT | `theharvester`, `sherlock`, `maigret`, `fixture` |
| Asset Discovery | `crtsh`, `subfinder`, `amass`, `historical_urls`, `github_repos` |
| Validation | `dnsx`, `httpx_probe`, `gowitness`, `nmap`, `naabu`, `ffuf`, `smbmap` |
| Exposure | `nuclei`, `katana`, `nikto`, `testssl`, `wpscan`, `email_security` |
| Enrichment | `tlsx`, `cloud_bucket`, `holehe`, `shodan`, `censys`, `hibp`, `trufflehog`, `exiftool` |

21 of these were ported from the Python lantern codebase; 8 are new
additions that close gaps in the Python set (modern web crawling,
fast port discovery, cross-source subdomain correlation, TLS-cert
SAN extraction, WordPress audit, open cloud-bucket discovery,
deep username enumeration, and email-driven account discovery).

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
| `gau` | Wayback / Common Crawl URL discovery. Sister tool to waybackurls with identical "domain in, URL line out" contract. | `historical_urls` with `binary=gau`. |
| `sslscan` | TLS posture; output shape is a subset of testssl's. | `testssl`. |
| `kerbrute` | Kerberos pre-auth username enumeration. | `smbmap` covers the SMB-side enum; Kerberos-specific brute is a niche we'd add back when a real engagement needs it. |
| `enum4linux_ng` | SMB / NetBIOS enumeration. Heavy text-parsing surface that overlaps with `smbmap`. | `smbmap` (one of its design goals was being a modern enum4linux). |
| `netexec` | Multi-protocol enum/auth probe. Largest scope of any single collector — would justify its own dedicated package and CLI matrix. | `smbmap` for the SMB slice; the others (LDAP/RDP/SSH probes) are out of GoLantern's current scope. |
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
