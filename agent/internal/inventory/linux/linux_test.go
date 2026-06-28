package linux

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const dpkgFixture = `Package: openssl
Status: install ok installed
Priority: optional
Architecture: amd64
Version: 3.0.11-1~deb12u2
Description: Secure Sockets Layer toolkit
 .
 a folded continuation line must be ignored

Package: removed-pkg
Status: deinstall ok config-files
Architecture: amd64
Version: 1.0.0-1

Package: bash
Status: install ok installed
Architecture: amd64
Version: 5.2.15-2~deb12u1
`

func TestParseDpkgStatusOnlyInstalled(t *testing.T) {
	pkgs, err := parseDpkgStatus(strings.NewReader(dpkgFixture))
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 2 {
		t.Fatalf("expected 2 installed packages, got %d: %+v", len(pkgs), pkgs)
	}
	got := pkgs[0]
	if got.Name != "openssl" || got.Version != "3.0.11-1~deb12u2" || got.Arch != "amd64" {
		t.Fatalf("unexpected package: %+v", got)
	}
	if got.Source != "dpkg" {
		t.Fatalf("source = %q, want dpkg", got.Source)
	}
	if got.FullName != "openssl-3.0.11-1~deb12u2.amd64" {
		t.Fatalf("full_name = %q", got.FullName)
	}
	for _, p := range pkgs {
		if p.Name == "removed-pkg" {
			t.Fatal("config-files package must be excluded")
		}
	}
}

const osReleaseFixture = `PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"
NAME="Debian GNU/Linux"
VERSION_ID="12"
# a comment line
VERSION="12 (bookworm)"
ID=debian
`

func TestParseOSRelease(t *testing.T) {
	distro, release, err := parseOSRelease(strings.NewReader(osReleaseFixture))
	if err != nil {
		t.Fatal(err)
	}
	if distro != "debian" || release != "12" {
		t.Fatalf("distro=%q release=%q", distro, release)
	}
}

func TestCollectorWithFixtures(t *testing.T) {
	dir := t.TempDir()
	osr := filepath.Join(dir, "os-release")
	dpkg := filepath.Join(dir, "status")
	if err := os.WriteFile(osr, []byte(osReleaseFixture), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dpkg, []byte(dpkgFixture), 0o644); err != nil {
		t.Fatal(err)
	}
	c := &Collector{osReleasePath: osr, dpkgStatusPath: dpkg}
	inv, err := c.Collect()
	if err != nil {
		t.Fatal(err)
	}
	if inv.OS.Family != "linux" || inv.OS.Distro != "debian" || inv.OS.Release != "12" {
		t.Fatalf("os = %+v", inv.OS)
	}
	if len(inv.Packages) != 2 {
		t.Fatalf("packages = %d", len(inv.Packages))
	}
	if len(inv.CycleHash) != 64 {
		t.Fatalf("cycle_hash = %q", inv.CycleHash)
	}
}
