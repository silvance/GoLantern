# Installing collectors (Fedora)

GoLantern is a single Go binary, but most collectors are wrappers
around external CLIs (`nmap`, `nuclei`, `nikto`, …). This page lists
the install commands for those external tools on Fedora.

Run `golantern doctor` after installing to confirm every binary
GoLantern looks for is on `$PATH`.

> The same set of tools works on RHEL/Alma/Rocky if you swap `dnf` for
> `dnf` + EPEL where noted; Debian/Ubuntu users want `apt install`
> equivalents (most package names are identical).

## From the Fedora repositories

These are one-command installs.

```sh
sudo dnf install nmap perl-Image-ExifTool whois net-snmp-utils whatweb exploitdb
```

| Tool | Used by |
|---|---|
| `nmap` | `nmap` collector |
| `perl-Image-ExifTool` (provides `exiftool`) | `exiftool` collector |
| `whois` | `whois` collector |
| `net-snmp-utils` (provides `snmpwalk`) | `snmpwalk` collector |
| `whatweb` | `whatweb` collector (may require EPEL on RHEL) |
| `exploitdb` (provides `searchsploit`) | `searchsploit` collector |

## Go-based tools — install with `go install`

Most ProjectDiscovery and Tomnomnom tools ship as single Go binaries.
Install Go first (`sudo dnf install golang`), then:

```sh
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest
go install -v github.com/owasp-amass/amass/v4/...@master
go install github.com/sa7mon/s3scanner@latest
go install github.com/ffuf/ffuf/v2@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/sensepost/gowitness@latest
go install github.com/trufflesecurity/trufflehog/v3@latest
```

These drop binaries into `$(go env GOPATH)/bin` — make sure that's on
your `PATH`:

```sh
export PATH="$PATH:$(go env GOPATH)/bin"
```

| Tool | Used by |
|---|---|
| `subfinder` | `subfinder` collector |
| `dnsx` | `dnsx` collector |
| `httpx` | `httpx_probe` collector |
| `nuclei` | `nuclei` collector |
| `naabu` | `naabu` collector |
| `katana` | `katana` collector |
| `tlsx` | `tlsx` collector |
| `amass` | `amass` collector |
| `s3scanner` | `cloud_bucket` collector |
| `ffuf` | `ffuf` collector |
| `waybackurls` | `historical_urls` collector (default binary) |
| `gowitness` | `gowitness` collector |
| `trufflehog` | `trufflehog` collector |

`naabu` needs raw-socket capability for SYN scanning. Either run it
as root or grant the capability once:

```sh
sudo setcap cap_net_raw,cap_net_admin=eip "$(go env GOPATH)/bin/naabu"
```

After `nuclei` is installed, update its template set once:

```sh
nuclei -update-templates
```

## Python-based tools — install with `pipx`

`theHarvester`, `sherlock`, and `smbmap` are Python projects.
`pipx` keeps each in its own venv so they don't fight over deps:

```sh
sudo dnf install pipx
pipx ensurepath
pipx install theHarvester
pipx install sherlock-project
pipx install maigret
pipx install holehe
pipx install smbmap
pipx install dnsrecon
pipx install ssh-audit
```

After `pipx ensurepath` you may need a new shell so `~/.local/bin` is
on `$PATH`.

| Tool | pipx package | Used by |
|---|---|---|
| `theHarvester` | `theHarvester` | `theharvester` collector |
| `sherlock` | `sherlock-project` | `sherlock` collector |
| `maigret` | `maigret` | `maigret` collector |
| `holehe` | `holehe` | `holehe` collector |
| `smbmap` | `smbmap` | `smbmap` collector |
| `dnsrecon` | `dnsrecon` | `dnsrecon` collector |
| `ssh-audit` | `ssh-audit` | `ssh_audit` collector |

## Ruby gem — wpscan

`wpscan` is a Ruby project, easiest via gem:

```sh
sudo dnf install ruby ruby-devel gcc-c++ patch readline readline-devel \
    zlib zlib-devel libffi-devel openssl-devel libyaml-devel make \
    libxml2-devel libxslt-devel
sudo gem install wpscan
wpscan --version
```

For enriched vulnerability data, register a free WPScan API token at
https://wpscan.com and pass it via `parameters["api_token"]` on each
run (or wire it through your env).

## Tools that aren't packaged — install from git

Fedora dropped `nikto` and never packaged `testssl.sh`; both are
self-contained scripts you clone and symlink.

### Nikto

```sh
sudo dnf install perl perl-LWP-Protocol-https perl-Net-SSLeay perl-JSON
git clone https://github.com/sullo/nikto.git ~/tools/nikto
sudo ln -s ~/tools/nikto/program/nikto.pl /usr/local/bin/nikto
nikto -Version
```

### testssl.sh

```sh
sudo dnf install bind-utils openssl
git clone --depth 1 https://github.com/drwetter/testssl.sh.git ~/tools/testssl
sudo ln -s ~/tools/testssl/testssl.sh /usr/local/bin/testssl.sh
testssl.sh --version
```

### smtp-user-enum

Fedora doesn't package smtp-user-enum; install the Perl script directly:

```sh
sudo dnf install perl perl-IO-Socket-SSL
sudo curl -L -o /usr/local/bin/smtp-user-enum \
    https://raw.githubusercontent.com/pentestmonkey/smtp-user-enum/master/smtp-user-enum.pl
sudo chmod +x /usr/local/bin/smtp-user-enum
smtp-user-enum -h
```

## Collectors with no binary dependency

These hit HTTP APIs or do their work in pure Go — nothing to install
beyond GoLantern itself. They need credentials in your config or
environment to do anything useful.

| Collector | What it talks to |
|---|---|
| `crtsh` | crt.sh public API |
| `github_repos` | GitHub API (`GITHUB_TOKEN`) |
| `shodan` | Shodan API (`SHODAN_API_KEY`) |
| `censys` | Censys API (`CENSYS_API_ID`, `CENSYS_API_SECRET`) |
| `hibp` | Have I Been Pwned API (`HIBP_API_KEY`) |
| `email_security` | DNS only — SPF/DMARC/DKIM lookups |
| `fixture` | Test fixture loader |

## Verifying

Once you've installed the tools you plan to use, start the server and
open the Doctor page in the SPA:

```sh
golantern serve
# then open http://127.0.0.1:8000/doctor
```

Doctor walks every registered collector, checks that the configured
binary is on `$PATH`, and reports the version it found. Missing
binaries are listed with an install hint.

You can also hit the API directly:

```sh
curl -s http://127.0.0.1:8000/api/v1/doctor | jq
```
