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

func TestCRLNotRequiredAllowsBeforeLoad(t *testing.T) {
	c := NewCRL("http://control-plane:8080/v1/crl.der", false)
	if err := c.Check("a1b2c"); err != nil {
		t.Fatalf("CRL não-required sem carga deveria permitir: %v", err)
	}
}
