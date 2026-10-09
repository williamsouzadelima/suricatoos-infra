package remediation

import "testing"

func TestAuthorize(t *testing.T) {
	// Happy path (RFC2253 DN).
	id, err := Authorize("SUCCESS", "CN=win1,OU=agent-endpoint,O=acme", nil)
	if err != nil || id.CN != "win1" || id.O != "acme" || id.OU != "agent-endpoint" {
		t.Fatalf("valid cert: id=%+v err=%v", id, err)
	}
	// Legacy OpenSSL oneline DN.
	if id, err := Authorize("SUCCESS", "/O=acme/OU=agent-endpoint/CN=win1", nil); err != nil || id.CN != "win1" {
		t.Fatalf("oneline DN: id=%+v err=%v", id, err)
	}
	cases := []struct {
		name, verify, dn string
	}{
		{"unverified", "FAILED", "CN=win1,OU=agent-endpoint,O=acme"},
		{"wrong OU", "SUCCESS", "CN=win1,OU=scanner-sensor,O=acme"},
		{"no O", "SUCCESS", "CN=win1,OU=agent-endpoint"},
		{"no CN", "SUCCESS", "OU=agent-endpoint,O=acme"},
	}
	for _, c := range cases {
		if _, err := Authorize(c.verify, c.dn, nil); err == nil {
			t.Errorf("%s: expected authz error", c.name)
		}
	}
}

func TestAuthorizeTenantKnown(t *testing.T) {
	known := func(o string) bool { return o == "acme" }
	if _, err := Authorize("SUCCESS", "CN=win1,OU=agent-endpoint,O=acme", known); err != nil {
		t.Errorf("known tenant must pass: %v", err)
	}
	if _, err := Authorize("SUCCESS", "CN=win1,OU=agent-endpoint,O=evil", known); err == nil {
		t.Error("unknown tenant must be rejected")
	}
}

func TestParseDNEscaping(t *testing.T) {
	// A comma escaped inside a value must NOT be read as an attribute separator,
	// so a crafted O cannot smuggle an OU.
	f := parseDN(`CN=win1,O=ac\,OU=agent-endpoint,OU=real`)
	if firstOf(f, "O") != "ac,OU=agent-endpoint" {
		t.Errorf("escaped comma mis-parsed: O=%q", firstOf(f, "O"))
	}
	if !hasValue(f, "OU", "real") || hasValue(f, "OU", "agent-endpoint") {
		t.Errorf("smuggled OU must not appear: %v", f["OU"])
	}
}

func TestNormalizeSerial(t *testing.T) {
	cases := map[string]string{"0A:1B": "a1b", "0x00FF": "ff", "00": "0", "1": "1"}
	for in, want := range cases {
		if got := normalizeSerial(in); got != want {
			t.Errorf("normalizeSerial(%q)=%q want %q", in, got, want)
		}
	}
}
