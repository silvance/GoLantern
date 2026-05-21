package linpeas

import (
	"strings"
	"testing"

	"github.com/silvance/golantern/internal/finding"
)

func TestLinpeasFindsSUIDGTFO(t *testing.T) {
	raw := `
╔══════════╣ Operative system
Linux version 5.10.0-19-amd64

╔══════════╣ Interesting Files - SUID
-rwsr-xr-x 1 root root 12K Jan 14 2023 /usr/bin/sudo
-rwsr-xr-x 1 root root 16K Jan 14 2023 /usr/bin/nmap
-rwsr-xr-x 1 root root 18K Jan 14 2023 /usr/bin/find
-rwsr-xr-x 1 root root 22K Jan 14 2023 /usr/bin/passwd
`
	res, err := New().Parse(raw, "10.0.0.5")
	if err != nil {
		t.Fatal(err)
	}
	var suidFinding bool
	for _, f := range res.Findings {
		if f.Category == "privesc.suid_gtfobins" {
			suidFinding = true
			if f.Severity != finding.SeverityCritical {
				t.Errorf("SUID GTFOBins should be Critical; got %s", f.Severity)
			}
			bins, _ := f.Attributes["binaries"].([]string)
			if len(bins) != 2 { // nmap + find
				t.Errorf("expected 2 GTFOBins; got %v", bins)
			}
		}
	}
	if !suidFinding {
		t.Fatal("no SUID GTFOBins finding emitted")
	}
}

func TestLinpeasFindsNopasswdSudo(t *testing.T) {
	raw := `
╔══════════╣ Sudo
User vagrant may run the following commands on host:
    (root) NOPASSWD: /usr/bin/find
    (ALL) ALL
`
	res, _ := New().Parse(raw, "")
	var found bool
	for _, f := range res.Findings {
		if f.Category == "privesc.sudo_nopasswd" {
			found = true
			if f.Severity != finding.SeverityHigh {
				t.Errorf("NOPASSWD should be High; got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Fatal("NOPASSWD sudo finding missing")
	}
}

func TestLinpeasKernelToTechEntity(t *testing.T) {
	raw := "Linux version 4.15.0-122-generic (something else)\n"
	res, _ := New().Parse(raw, "10.0.0.5")
	var techFound string
	for _, e := range res.Entities {
		if strings.HasPrefix(e.Value, "linux-kernel/") {
			techFound = e.Value
		}
	}
	if techFound != "linux-kernel/4.15.0-122-generic" {
		t.Fatalf("kernel entity wrong: %q", techFound)
	}
}

func TestLinpeasEmptyInput(t *testing.T) {
	res, err := New().Parse("", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 0 || len(res.Entities) != 0 {
		t.Fatalf("empty input should produce no findings; got %+v", res)
	}
}

func TestLinpeasIgnoresHardenedHost(t *testing.T) {
	// Nothing interesting — just kernel + benign SUID list.
	raw := `
Linux version 6.5.0-amd64

-rwsr-xr-x 1 root root 12K /usr/bin/sudo
-rwsr-xr-x 1 root root 22K /usr/bin/passwd
-rwsr-xr-x 1 root root 18K /usr/bin/chsh
`
	res, _ := New().Parse(raw, "")
	for _, f := range res.Findings {
		t.Errorf("hardened input emitted finding %q (%s)", f.Title, f.Category)
	}
}
