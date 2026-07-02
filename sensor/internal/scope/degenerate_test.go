package scope

import "testing"

// TestCIDROverlappingDegenerateRejected guards the low-severity hardening: a swept
// CIDR must never reach cloud metadata / link-local / loopback even if an allow
// range is mis-set too broadly (ADR-0007 self-protection invariant).
func TestCIDROverlappingDegenerateRejected(t *testing.T) {
	s, err := New("10.0.0.0/8, 169.254.0.0/16", "") // deliberately over-broad allow
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"169.254.169.0/24", "169.254.0.0/16", "127.0.0.0/24"} {
		if _, err := s.CheckHost(bad); err == nil {
			t.Errorf("CIDR %s (metadata/link-local/loopback) deveria ser rejeitado mesmo ⊆ allow", bad)
		}
	}
	// A legitimate internal sweep still passes.
	if _, err := s.CheckHost("10.20.5.0/24"); err != nil {
		t.Fatalf("CIDR interno legítimo deveria passar: %v", err)
	}
}
