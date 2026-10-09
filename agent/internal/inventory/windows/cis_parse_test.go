package windows

import (
	"os"
	"testing"

	"github.com/williamsouzadelima/suricatoos-infra/agent/internal/inventory"
)

func byKey(states []inventory.CISState, source string) map[string]string {
	m := map[string]string{}
	for _, s := range states {
		if s.Source == source {
			m[s.Key] = s.Value
		}
	}
	return m
}

func TestParseSeceditINF(t *testing.T) {
	raw, err := os.ReadFile("testdata/secedit-sample.inf")
	if err != nil {
		t.Fatal(err)
	}
	states := parseSeceditINF(string(raw))
	m := byKey(states, "secedit")

	// [System Access] password/lockout policy, verbatim values.
	if m["MinimumPasswordLength"] != "14" || m["MaximumPasswordAge"] != "365" || m["LockoutBadCount"] != "5" {
		t.Errorf("system access mismapped: %v", m)
	}
	// [Privilege Rights] with SIDs scrubbed, de-duped and SORTED.
	if m["SeDenyNetworkLogonRight"] != "Guests,LocalAccount" {
		t.Errorf("deny-network = %q, want Guests,LocalAccount", m["SeDenyNetworkLogonRight"])
	}
	if m["SeRemoteShutdownPrivilege"] != "Administrators" {
		t.Errorf("remote-shutdown = %q", m["SeRemoteShutdownPrivilege"])
	}
	// A custom (host-specific) SID must be reduced to "custom-sid" — never leaked.
	if m["SeBackupPrivilege"] != "Administrators,BackupOperators,custom-sid" {
		t.Errorf("backup = %q (custom SID must be scrubbed)", m["SeBackupPrivilege"])
	}
	if _, ok := m["SeTcbPrivilege"]; !ok || m["SeTcbPrivilege"] != "" {
		t.Errorf("empty privilege should be present with empty value: %q", m["SeTcbPrivilege"])
	}
	// [Version]/[Unicode]/[Registry Values] sections are ignored.
	if _, ok := m["Unicode"]; ok {
		t.Error("non-policy sections must be ignored")
	}
}

func TestParseAuditpolCSV(t *testing.T) {
	raw, err := os.ReadFile("testdata/auditpol-sample.csv")
	if err != nil {
		t.Fatal(err)
	}
	m := byKey(parseAuditpolCSV(string(raw)), "auditpol")
	if len(m) != 2 {
		t.Fatalf("want 2 subcategories (category-header row skipped), got %d: %v", len(m), m)
	}
	if m["Credential Validation"] != "Success and Failure" || m["Logon"] != "Success" {
		t.Errorf("auditpol mismapped: %v", m)
	}
}

func TestScrubSID(t *testing.T) {
	cases := map[string]string{
		"S-1-5-32-544":              "Administrators",
		"S-1-1-0":                   "Everyone",
		"S-1-5-21-111-222-333-1001": "custom-sid",
		"Administrator":             "custom-account",
		"":                          "custom-account",
	}
	for in, want := range cases {
		if got := scrubSID(in); got != want {
			t.Errorf("scrubSID(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestScrubSIDList(t *testing.T) {
	// Leading '*' stripped, well-known mapped, custom scrubbed, de-duped, SORTED.
	got := scrubSIDList("*S-1-5-32-551,*S-1-5-32-544,*S-1-5-32-544,*S-1-5-21-9-9-9-500")
	if got != "Administrators,BackupOperators,custom-sid" {
		t.Errorf("scrubSIDList = %q", got)
	}
	if scrubSIDList("   ") != "" {
		t.Error("blank list → empty")
	}
}

func TestAssembleCISFromText(t *testing.T) {
	inf, _ := os.ReadFile("testdata/secedit-sample.inf")
	csvb, _ := os.ReadFile("testdata/auditpol-sample.csv")
	all := assembleCISFromText(string(inf), string(csvb))
	var sec, aud int
	for _, s := range all {
		switch s.Source {
		case "secedit":
			sec++
		case "auditpol":
			aud++
		}
	}
	if sec == 0 || aud != 2 {
		t.Fatalf("assemble = %d secedit + %d auditpol", sec, aud)
	}
}
