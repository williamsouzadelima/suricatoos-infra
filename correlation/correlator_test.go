package correlation

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// testInv builds a minimal Debian 12 Inventory with the given packages.
func testInv(pkgs ...Package) Inventory {
	return testInvOS(OSInfo{Family: "linux", Distro: "debian", Release: "12"}, pkgs...)
}

// testInvOS builds a minimal Inventory with an explicit OS, for distro-scoping tests.
func testInvOS(os OSInfo, pkgs ...Package) Inventory {
	return Inventory{
		SchemaVersion: "1.0.0",
		Agent:         AgentInfo{AgentID: "test-agent-id", Hostname: "test-host"},
		CollectedAt:   time.Now().UTC(),
		OS:            os,
		Packages:      pkgs,
	}
}

// opensuseLeap156 is the host OS matching the testdata openSUSE Leap rpm fixture.
var opensuseLeap156 = OSInfo{Family: "linux", Distro: "opensuse-leap", Release: "15.6"}

// debPkg builds a dpkg-sourced Package matching the agent's fullName format.
func debPkg(name, version, arch string) Package {
	fn := name + "-" + version
	if arch != "" {
		fn += "." + arch
	}
	return Package{Name: name, Version: version, Arch: arch, Source: "dpkg", FullName: fn}
}

// rpmPkg builds an rpm-sourced Package using agent's format (version = VERSION-RELEASE).
func rpmPkg(name, versionRelease, arch string) Package {
	fn := name + "-" + versionRelease
	if arch != "" {
		fn += "." + arch
	}
	return Package{Name: name, Version: versionRelease, Arch: arch, Source: "rpm", FullName: fn}
}

func newCorrelator(t *testing.T) *NotusCorrelator {
	t.Helper()
	c, err := NewNotusCorrelator(filepath.Join("testdata"))
	if err != nil {
		t.Fatalf("NewNotusCorrelator: %v", err)
	}
	return c
}

func TestDeb_Vulnerable(t *testing.T) {
	c := newCorrelator(t)
	// chromium 113 < fixed 114.0.5735.90 → 1 finding
	inv := testInv(debPkg("chromium", "113.0.5672.126-1~deb12u1", "amd64"))
	r, err := c.Correlate(inv)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Findings) != 1 {
		t.Fatalf("want 1 finding, got %d: %+v", len(r.Findings), r.Findings)
	}
	f := r.Findings[0]
	if f.OID != "1.3.6.1.4.1.25623.1.1.1.1.2023.5418" {
		t.Errorf("oid = %q", f.OID)
	}
	if f.PackageObserved == "" {
		t.Error("package_observed must not be empty")
	}
	if f.PackageFixed == "" {
		t.Error("package_fixed must not be empty")
	}
	if f.Evidence.Source != "dpkg" {
		t.Errorf("evidence.source = %q, want dpkg", f.Evidence.Source)
	}
	if f.Evidence.MatchedAdvisory == "" {
		t.Error("evidence.matched_advisory must not be empty")
	}
	if f.DetectedAt == "" {
		t.Error("detected_at must not be empty")
	}
}

func TestDeb_Fixed(t *testing.T) {
	c := newCorrelator(t)
	// Package is AT the fixed version — not vulnerable.
	inv := testInv(debPkg("chromium", "114.0.5735.90-2~deb12u1", "amd64"))
	r, err := c.Correlate(inv)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Findings) != 0 {
		t.Fatalf("want 0 findings for fixed package, got %d", len(r.Findings))
	}
}

func TestDeb_Newer(t *testing.T) {
	c := newCorrelator(t)
	// Package is newer than the fixed version — not vulnerable.
	inv := testInv(debPkg("chromium", "115.0.5790.110-1~deb12u1", "amd64"))
	r, err := c.Correlate(inv)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Findings) != 0 {
		t.Fatalf("want 0 findings for newer package, got %d", len(r.Findings))
	}
}

func TestDeb_Epoch(t *testing.T) {
	c := newCorrelator(t)
	// openssh-client 1:8.4p1-2+deb12u2 < fixed 1:8.4p1-2+deb12u3 → 1 finding
	inv := testInv(debPkg("openssh-client", "1:8.4p1-2+deb12u2", "amd64"))
	r, err := c.Correlate(inv)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Findings) != 1 {
		t.Fatalf("want 1 finding for epoch-versioned package, got %d", len(r.Findings))
	}
}

func TestDeb_Tilde(t *testing.T) {
	c := newCorrelator(t)
	// 114.0.5735.90~rc1 < 114.0.5735.90-2~deb12u1 (tilde pre-release sorts before release)
	inv := testInv(debPkg("chromium", "114.0.5735.90~rc1-1", "amd64"))
	r, err := c.Correlate(inv)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Findings) != 1 {
		t.Fatalf("tilde pre-release should be vulnerable, got %d findings", len(r.Findings))
	}
}

func TestDeb_SourceMismatch(t *testing.T) {
	c := newCorrelator(t)
	// rpm-sourced package against a deb advisory → no findings
	inv := testInv(Package{
		Name: "chromium", Version: "113.0.5672.126-1~deb12u1", Source: "rpm",
		FullName: "chromium-113.0.5672.126-1~deb12u1.x86_64",
	})
	r, err := c.Correlate(inv)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Findings) != 0 {
		t.Fatalf("source mismatch: want 0 findings, got %d", len(r.Findings))
	}
}

func TestRPM_Vulnerable(t *testing.T) {
	c := newCorrelator(t)
	// libhtp2 0.5.40-bp156.1.1 < fixed 0.5.42-bp156.3.3.1 → 1 finding.
	// Host must be openSUSE Leap 15.6 to match the rpm fixture's product.
	inv := testInvOS(opensuseLeap156, rpmPkg("libhtp2", "0.5.40-bp156.1.1", "x86_64"))
	r, err := c.Correlate(inv)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Findings) != 1 {
		t.Fatalf("want 1 RPM finding, got %d: %+v", len(r.Findings), r.Findings)
	}
	if r.Findings[0].Evidence.Source != "rpm" {
		t.Errorf("evidence.source = %q, want rpm", r.Findings[0].Evidence.Source)
	}
}

func TestRPM_Fixed(t *testing.T) {
	c := newCorrelator(t)
	inv := testInvOS(opensuseLeap156, rpmPkg("libhtp2", "0.5.42-bp156.3.3.1", "x86_64"))
	r, err := c.Correlate(inv)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Findings) != 0 {
		t.Fatalf("want 0 findings for fixed RPM package, got %d", len(r.Findings))
	}
}

func TestNoMatch(t *testing.T) {
	c := newCorrelator(t)
	inv := testInv(debPkg("totally-unknown-package", "1.0.0-1", "amd64"))
	r, err := c.Correlate(inv)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Findings) != 0 {
		t.Fatalf("want 0 findings for unknown package, got %d", len(r.Findings))
	}
}

func TestDedup(t *testing.T) {
	c := newCorrelator(t)
	// Same vulnerable package twice in the inventory → findings must be deduplicated per OID.
	p := debPkg("chromium", "113.0.5672.126-1~deb12u1", "amd64")
	inv := testInv(p, p)
	r, err := c.Correlate(inv)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]int{}
	for _, f := range r.Findings {
		seen[f.OID+"|"+f.PackageObserved]++
	}
	for key, count := range seen {
		if count > 1 {
			t.Errorf("duplicate finding %q (count=%d)", key, count)
		}
	}
}

func TestReportFields(t *testing.T) {
	c := newCorrelator(t)
	inv := testInv(debPkg("chromium", "113.0.5672.126-1~deb12u1", "amd64"))
	r, err := c.Correlate(inv)
	if err != nil {
		t.Fatal(err)
	}
	if r.SchemaVersion != "1.0.0" {
		t.Errorf("schema_version = %q", r.SchemaVersion)
	}
	if r.AgentID != inv.Agent.AgentID {
		t.Errorf("agent_id = %q", r.AgentID)
	}
	if r.Host != inv.Agent.Hostname {
		t.Errorf("host = %q", r.Host)
	}
}

func TestJSONRoundTrip(t *testing.T) {
	c := newCorrelator(t)
	inv := testInv(debPkg("chromium", "113.0.5672.126-1~deb12u1", "amd64"))
	r, err := c.Correlate(inv)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	var r2 FindingReport
	if err := json.Unmarshal(data, &r2); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	if len(r2.Findings) != len(r.Findings) {
		t.Errorf("round-trip findings count: got %d, want %d", len(r2.Findings), len(r.Findings))
	}
}

func TestEmptyDirectory(t *testing.T) {
	dir := t.TempDir()
	c, err := NewNotusCorrelator(dir)
	if err != nil {
		t.Fatal(err)
	}
	inv := testInv(debPkg("chromium", "113.0.5672.126-1~deb12u1", "amd64"))
	r, err := c.Correlate(inv)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Findings) != 0 {
		t.Fatalf("empty directory: want 0 findings, got %d", len(r.Findings))
	}
}

func TestSplitRPMFullName(t *testing.T) {
	cases := []struct {
		input   string
		name    string
		version string
		ok      bool
	}{
		{"bash-5.1.8-6.el9.x86_64", "bash", "5.1.8-6.el9", true},
		{"libhtp-devel-0.5.42-bp156.3.3.1.x86_64", "libhtp-devel", "0.5.42-bp156.3.3.1", true},
		{"libhtp2-0.5.42-bp156.3.3.1.noarch", "libhtp2", "0.5.42-bp156.3.3.1", true},
		{"rust-hyper-rustls+default-devel-0.27.3-1.fc42.noarch", "rust-hyper-rustls+default-devel", "0.27.3-1.fc42", true},
		{"opera-109.0.5097.45-lp156.2.3.1.x86_64", "opera", "109.0.5097.45-lp156.2.3.1", true},
		{"lib32gcc-s1-12.2.0-14+deb12u1", "lib32gcc-s1", "12.2.0-14+deb12u1", true},
		{"noversion", "", "", false},
		// Regression: names with hyphen-then-digit must not mis-split (audit #1).
		// Old "first hyphen+digit" heuristic split these at "java-1"/"libpng16-1".
		{"java-1.8.0-openjdk-1.8.0.362.b08-4.el9.x86_64", "java-1.8.0-openjdk", "1.8.0.362.b08-4.el9", true},
		{"java-11-openjdk-11.0.18.0.10-3.el9.x86_64", "java-11-openjdk", "11.0.18.0.10-3.el9", true},
		{"libpng16-16-1.6.40-1.fc40.x86_64", "libpng16-16", "1.6.40-1.fc40", true},
		// Epoch in the version segment is preserved (epoch normalization is a
		// separate concern handled in the version comparator).
		{"grub2-1:2.06-70.el9_3.x86_64", "grub2", "1:2.06-70.el9_3", true},
		// Arch now in knownArches: stripped cleanly instead of gluing to release.
		{"libsndfile1-1.0.31-1.el9.riscv64", "libsndfile1", "1.0.31-1.el9", true},
		{"kernel-6.4.0-150600.23.7.loongarch64", "kernel", "6.4.0-150600.23.7", true},
		// Only a name (no version-release) cannot be split.
		{"onlyname-noarch", "", "", false},
	}
	for _, tc := range cases {
		name, ver, ok := splitRPMFullName(tc.input)
		if ok != tc.ok || name != tc.name || ver != tc.version {
			t.Errorf("splitRPMFullName(%q) = (%q, %q, %v), want (%q, %q, %v)",
				tc.input, name, ver, ok, tc.name, tc.version, tc.ok)
		}
	}
}

// TestCrossDistro_NoFalsePositive locks the audit's #2 finding: a Debian host
// must NOT be flagged by an advisory from another deb distro (Ubuntu) just
// because the package name matches and the version is lower. Without OS scoping
// this produced 1 fabricated finding; with scoping it must be 0.
func TestCrossDistro_NoFalsePositive(t *testing.T) {
	c := newCorrelator(t)
	// Debian 12 host. openssl exists only in the Ubuntu fixture (fixed
	// 3.0.13-0ubuntu3.4); the installed version is lower, so absent scoping the
	// Ubuntu advisory would match.
	inv := testInvOS(OSInfo{Family: "linux", Distro: "debian", Release: "12"},
		debPkg("openssl", "3.0.2-1", "amd64"))
	r, err := c.Correlate(inv)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Findings) != 0 {
		t.Fatalf("cross-distro false positive: Debian host matched a foreign-distro advisory; want 0 findings, got %d: %+v",
			len(r.Findings), r.Findings)
	}
}

// TestSameDistro_TruePositive is the positive counterpart: the SAME package and
// versions DO produce a finding when the host actually is the advisory's distro.
func TestSameDistro_TruePositive(t *testing.T) {
	c := newCorrelator(t)
	inv := testInvOS(OSInfo{Family: "linux", Distro: "ubuntu", Release: "22.04"},
		debPkg("openssl", "3.0.2-0ubuntu1.10", "amd64"))
	r, err := c.Correlate(inv)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Findings) != 1 {
		t.Fatalf("want 1 finding for Ubuntu host vs Ubuntu advisory, got %d", len(r.Findings))
	}
	if got := r.Findings[0].Product; got != "Ubuntu 22.04 LTS" {
		t.Errorf("finding product = %q, want %q", got, "Ubuntu 22.04 LTS")
	}
}

// TestCrossRelease_NoFalsePositive: a Debian 11 host must not be matched by a
// Debian 12 advisory (same distro, different release).
func TestCrossRelease_NoFalsePositive(t *testing.T) {
	c := newCorrelator(t)
	inv := testInvOS(OSInfo{Family: "linux", Distro: "debian", Release: "11"},
		debPkg("chromium", "113.0.5672.126-1~deb12u1", "amd64"))
	r, err := c.Correlate(inv)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Findings) != 0 {
		t.Fatalf("cross-release false positive: Debian 11 host matched a Debian 12 advisory; want 0, got %d", len(r.Findings))
	}
}

func TestScope_AppliesTo(t *testing.T) {
	cases := []struct {
		name     string
		advisory productScope
		host     productScope
		want     bool
	}{
		{"same debian", productScope{"debian", "12"}, productScope{"debian", "12"}, true},
		{"debian 11 advisory vs debian 12 host", productScope{"debian", "11"}, productScope{"debian", "12"}, false},
		{"debian vs ubuntu", productScope{"debian", "12"}, productScope{"ubuntu", "12"}, false},
		{"rhel major advisory vs minor host", productScope{"rhel", "9"}, productScope{"rhel", "9.4"}, true},
		{"rhel 8 advisory vs rhel 9 host", productScope{"rhel", "8"}, productScope{"rhel", "9.4"}, false},
		{"ubuntu exact", productScope{"ubuntu", "22.04"}, productScope{"ubuntu", "22.04"}, true},
		{"ubuntu 2 vs 22.04 (no numeric prefix bleed)", productScope{"ubuntu", "2"}, productScope{"ubuntu", "22.04"}, false},
		{"opensuse leap exact", productScope{"opensuse-leap", "15.6"}, productScope{"opensuse-leap", "15.6"}, true},
		{"unknown advisory distro", productScope{"", "12"}, productScope{"debian", "12"}, false},
		{"unknown host distro", productScope{"debian", "12"}, productScope{"", "12"}, false},
	}
	for _, tc := range cases {
		if got := tc.advisory.appliesTo(tc.host); got != tc.want {
			t.Errorf("%s: appliesTo = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestCanonicalDistro(t *testing.T) {
	cases := map[string]string{
		"debian":                              "debian",
		"ubuntu":                              "ubuntu",
		"opensuse-leap":                       "opensuse-leap",
		"rhel":                                "rhel",
		"amzn":                                "amazon",
		"ol":                                  "oracle",
		"almalinux":                           "alma",
		"Debian 12":                           "debian",
		"openSUSE Leap 15.6":                  "opensuse-leap",
		"Red Hat Enterprise Linux 9":          "rhel",
		"Ubuntu 22.04 LTS":                    "ubuntu",
		"SUSE Linux Enterprise Server 15 SP5": "sles",
		"Amazon Linux 2023":                   "amazon",
		"TempleOS 5.0":                        "", // unknown
		"":                                    "",
	}
	for in, want := range cases {
		if got := canonicalDistro(in); got != want {
			t.Errorf("canonicalDistro(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestExtractProductRelease(t *testing.T) {
	cases := map[string]string{
		"Debian 12":                  "12",
		"openSUSE Leap 15.6":         "15.6",
		"Ubuntu 22.04 LTS":           "22.04",
		"Red Hat Enterprise Linux 9": "9",
		"Amazon Linux 2023":          "2023",
		"No Numbers Here":            "",
	}
	for in, want := range cases {
		if got := extractProductRelease(in); got != want {
			t.Errorf("extractProductRelease(%q) = %q, want %q", in, got, want)
		}
	}
}

// rhel94 is a RHEL host whose VERSION_ID carries a minor (9.4); it must match the
// per-major "Red Hat Enterprise Linux 9" advisory via the release-prefix rule.
var rhel94 = OSInfo{Family: "linux", Distro: "rhel", Release: "9.4"}

// TestRPM_Epoch_NotVulnerable locks audit #3: a host AT the epoch-bearing fixed
// version (collected WITH its epoch, per the rpm collector) must NOT be flagged.
// Previously the collector dropped the epoch, so "2.06-70.el9_3" compared against
// "1:2.06-70.el9_3" read epoch 0 < 1 and produced a false positive.
func TestRPM_Epoch_NotVulnerable(t *testing.T) {
	c := newCorrelator(t)
	inv := testInvOS(rhel94, rpmPkg("grub2", "1:2.06-70.el9_3", "x86_64")) // exactly the fixed NEVRA
	r, err := c.Correlate(inv)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Findings) != 0 {
		t.Fatalf("epoch false positive: patched host flagged; want 0 findings, got %d: %+v", len(r.Findings), r.Findings)
	}
}

// TestRPM_Epoch_NewerNotVulnerable: a host NEWER than the fix (same epoch) is clean.
func TestRPM_Epoch_NewerNotVulnerable(t *testing.T) {
	c := newCorrelator(t)
	inv := testInvOS(rhel94, rpmPkg("grub2", "1:2.06-80.el9_4", "x86_64"))
	r, err := c.Correlate(inv)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Findings) != 0 {
		t.Fatalf("newer host flagged; want 0 findings, got %d", len(r.Findings))
	}
}

// TestRPM_Epoch_Vulnerable: a host genuinely behind the fix (same epoch, lower
// release) is still correctly flagged.
func TestRPM_Epoch_Vulnerable(t *testing.T) {
	c := newCorrelator(t)
	inv := testInvOS(rhel94, rpmPkg("grub2", "1:2.06-50.el9_1", "x86_64"))
	r, err := c.Correlate(inv)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Findings) != 1 {
		t.Fatalf("vulnerable host not flagged; want 1 finding, got %d", len(r.Findings))
	}
	if got := r.Findings[0].Product; got != "Red Hat Enterprise Linux 9" {
		t.Errorf("product = %q, want RHEL 9", got)
	}
}

// TestUnclassifiedProducts: all shipped fixtures use recognized products, so the
// set is empty; an advisory with an unknown product is surfaced (not silently
// dropped) so an operator can extend canonicalDistro.
func TestUnclassifiedProducts(t *testing.T) {
	c := newCorrelator(t)
	if got := c.UnclassifiedProducts(); len(got) != 0 {
		t.Fatalf("testdata products should all be classified, got unclassified: %v", got)
	}

	dir := t.TempDir()
	const f = `{"package_type":"deb","product_name":"TempleOS 5.0","advisories":[{"oid":"x","fixed_packages":[{"name":"holyc","full_version":"1.0","specifier":">="}]}]}`
	if err := os.WriteFile(filepath.Join(dir, "templeos.notus"), []byte(f), 0o644); err != nil {
		t.Fatal(err)
	}
	c2, err := NewNotusCorrelator(dir)
	if err != nil {
		t.Fatal(err)
	}
	got := c2.UnclassifiedProducts()
	if len(got) != 1 || got[0] != "TempleOS 5.0" {
		t.Fatalf("UnclassifiedProducts = %v, want [\"TempleOS 5.0\"]", got)
	}
	// And a host never matches the unclassified advisory.
	r, _ := c2.Correlate(testInvOS(OSInfo{Family: "linux", Distro: "templeos", Release: "5.0"},
		debPkg("holyc", "0.9", "amd64")))
	if len(r.Findings) != 0 {
		t.Errorf("unclassified advisory must not match; got %d findings", len(r.Findings))
	}
}
