package scanlaunch

import "testing"

func TestNormalizeSerial(t *testing.T) {
	cases := map[string]string{
		"0A:1B:2C": "a1b2c",
		"a1b2c":    "a1b2c",
		"00A1B":    "a1b",
		"0x00FF":   "ff",
		"  0B ":    "b",
		"00":       "0",
		"0":        "0",
	}
	for in, want := range cases {
		if got := normalizeSerial(in); got != want {
			t.Errorf("normalizeSerial(%q) = %q, quer %q", in, got, want)
		}
	}
}

func TestCRLDisabledWhenNoURL(t *testing.T) {
	c := NewCRL("", true) // required is forced off when url is empty
	if err := c.Check("anything"); err != nil {
		t.Fatalf("CRL sem URL deveria permitir tudo: %v", err)
	}
}

func TestCRLFailClosed(t *testing.T) {
	c := NewCRL("http://control-plane:8080/v1/crl.der", true)
	// Not loaded yet → fail-closed: every serial is denied.
	if err := c.Check("a1b2c"); err == nil {
		t.Fatal("CRL required sem carga deveria negar (fail-closed)")
	}
	// Simulate a successful load with one revoked serial.
	c.mu.Lock()
	c.loaded = true
	c.revoked = map[string]bool{"deadbeef": true}
	c.mu.Unlock()

	if err := c.Check("0A:1B:2C"); err != nil {
		t.Errorf("serial não revogado deveria passar após carga: %v", err)
	}
	if err := c.Check("00DEADBEEF"); err == nil {
		t.Error("serial revogado deveria ser negado")
	}
}

// Revoked tells "revoked" from "could not check" — known is false until a CRL has
// loaded, or when no URL is configured — so a fail-open caller (the inventory route)
// can log the gap instead of reading it as "not revoked". It ignores required: that
// flag only shapes Check, the fail-closed answer.
func TestCRLRevokedTellsUnknownFromNotRevoked(t *testing.T) {
	for _, required := range []bool{true, false} {
		c := NewCRL("http://control-plane:8080/v1/crl.der", required)
		if revoked, known := c.Revoked("DEADBEEF"); revoked || known {
			t.Fatalf("required=%v, before any load: revoked=%v known=%v, want false/false", required, revoked, known)
		}
		c.mu.Lock()
		c.loaded = true
		c.revoked = map[string]bool{"deadbeef": true}
		c.mu.Unlock()
		if revoked, known := c.Revoked("00:DE:AD:BE:EF"); !revoked || !known {
			t.Fatalf("required=%v, revoked serial: revoked=%v known=%v, want true/true", required, revoked, known)
		}
		if revoked, known := c.Revoked("0A1B2C"); revoked || !known {
			t.Fatalf("required=%v, other serial: revoked=%v known=%v, want false/true", required, revoked, known)
		}
	}
	if revoked, known := NewCRL("", true).Revoked("DEADBEEF"); revoked || known {
		t.Fatalf("no URL: revoked=%v known=%v, want false/false (revocation not configured)", revoked, known)
	}
}

func TestCRLNotRequiredAllowsBeforeLoad(t *testing.T) {
	c := NewCRL("http://control-plane:8080/v1/crl.der", false)
	if err := c.Check("a1b2c"); err != nil {
		t.Fatalf("CRL não-required sem carga deveria permitir: %v", err)
	}
}
