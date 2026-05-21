package winpeas

import (
	"testing"

	"github.com/silvance/golantern/internal/finding"
)

func TestWinpeasAlwaysInstallElevated(t *testing.T) {
	raw := "AlwaysInstallElevated set to 1 (HKLM and HKCU)\n"
	res, _ := New().Parse(raw, "10.0.0.5")
	var found bool
	for _, f := range res.Findings {
		if f.Category == "privesc.always_install_elevated" {
			found = true
			if f.Severity != finding.SeverityCritical {
				t.Errorf("AlwaysInstallElevated should be Critical; got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Fatal("AlwaysInstallElevated finding missing")
	}
}

func TestWinpeasImpersonatePrivilegeCritical(t *testing.T) {
	raw := "SeImpersonatePrivilege         SE_PRIVILEGE_ENABLED\n"
	res, _ := New().Parse(raw, "")
	var sev finding.Severity
	for _, f := range res.Findings {
		if f.Category == "privesc.token_privilege" {
			sev = f.Severity
		}
	}
	if sev != finding.SeverityCritical {
		t.Fatalf("SeImpersonate should escalate to Critical; got %s", sev)
	}
}

func TestWinpeasUnquotedServicePath(t *testing.T) {
	raw := `Unquoted Service Path Found: C:\Program Files\Bad Service\service.exe
`
	res, _ := New().Parse(raw, "10.0.0.5")
	var found bool
	for _, f := range res.Findings {
		if f.Category == "privesc.unquoted_service_path" {
			found = true
			svcs, _ := f.Attributes["services"].([]string)
			if len(svcs) != 1 {
				t.Errorf("expected 1 service; got %v", svcs)
			}
		}
	}
	if !found {
		t.Fatal("unquoted service finding missing")
	}
}

func TestWinpeasAutoLogonCreds(t *testing.T) {
	raw := `DefaultUserName: admin
DefaultPassword: SuperSecret123
AutoAdminLogon: 1
`
	res, _ := New().Parse(raw, "")
	var found bool
	for _, f := range res.Findings {
		if f.Category == "privesc.autologon_credentials" {
			found = true
			if f.Severity != finding.SeverityCritical {
				t.Errorf("AutoLogon creds should be Critical; got %s", f.Severity)
			}
			if f.Attributes["defaultpassword"] != "SuperSecret123" {
				t.Errorf("AutoLogon password not captured: %v", f.Attributes)
			}
		}
	}
	if !found {
		t.Fatal("AutoLogon finding missing")
	}
}

func TestWinpeasHardenedHostNoFindings(t *testing.T) {
	raw := `Windows 10 Pro
SeShutdownPrivilege   Disabled
No unquoted service paths found.
`
	res, _ := New().Parse(raw, "")
	if len(res.Findings) != 0 {
		t.Fatalf("hardened host should produce no findings; got %+v", res.Findings)
	}
}

func TestWinpeasEmptyInput(t *testing.T) {
	res, err := New().Parse("", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 0 || len(res.Entities) != 0 {
		t.Fatalf("empty input should produce nothing; got %+v", res)
	}
}
