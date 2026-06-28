package correlation

import (
	"encoding/json"
	"path/filepath"
	"testing"
	"time"
)

// testInv builds a minimal Inventory with the given packages.
func testInv(pkgs ...Package) Inventory {
	return Inventory{
		SchemaVersion: "1.0.0",
		Agent:         AgentInfo{AgentID: "test-agent-id", Hostname: "test-host"},
		CollectedAt:   time.Now().UTC(),
		OS:            OSInfo{Family: "linux", Distro: "debian", Release: "12"},
		Packages:      pkgs,
	}
}

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
	// libhtp2 0.5.40-bp156.1.1 < fixed 0.5.42-bp156.3.3.1 → 1 finding
	inv := testInv(rpmPkg("libhtp2", "0.5.40-bp156.1.1", "x86_64"))
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
	inv := testInv(rpmPkg("libhtp2", "0.5.42-bp156.3.3.1", "x86_64"))
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
	}
	for _, tc := range cases {
		name, ver, ok := splitRPMFullName(tc.input)
		if ok != tc.ok || name != tc.name || ver != tc.version {
			t.Errorf("splitRPMFullName(%q) = (%q, %q, %v), want (%q, %q, %v)",
				tc.input, name, ver, ok, tc.name, tc.version, tc.ok)
		}
	}
}
