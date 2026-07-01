package correlation

import "testing"

func TestCanonicalDistro_Kali(t *testing.T) {
	if got := canonicalDistro("kali"); got != "debian" {
		t.Fatalf(`canonicalDistro("kali") = %q, want "debian"`, got)
	}
}

func TestHostScope_KaliMapsToDebianRelease(t *testing.T) {
	// Kali reports its own ID/VERSION_ID but must be scoped to a fixed Debian
	// release so Debian advisories apply.
	h := hostScope(OSInfo{Family: "linux", Distro: "kali", Release: "2026.1"})
	if h.distro != "debian" || h.release != kaliDebianRelease {
		t.Fatalf("hostScope(kali) = {%q,%q}, want {debian,%q}", h.distro, h.release, kaliDebianRelease)
	}
	// A Debian advisory for the pinned release must apply to the Kali host.
	adv := advisoryScope("Debian " + kaliDebianRelease)
	if !adv.appliesTo(h) {
		t.Fatalf("Debian %s advisory should apply to a Kali host", kaliDebianRelease)
	}
	// A different Debian release must NOT apply (no cross-release fabrication).
	if advisoryScope("Debian 11").appliesTo(h) {
		t.Fatal("Debian 11 advisory must not apply to a Kali host pinned to a newer release")
	}
}
