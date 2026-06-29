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

func TestParseRPMOutput(t *testing.T) {
	out := "bash\t5.1.8-1\tx86_64\n" +
		"openssl\t3.0.7-2\tx86_64\n" +
		"gpg-pubkey\tabcdef-12345678\t(none)\n" + // chave GPG, não é pacote
		"grub2\t1:2.06-70.el9_3\tx86_64\n" + // epoch presente (rpmQueryFormat condicional)
		"filesystem\t3.16-2\tnoarch\n"
	pkgs, err := parseRPMOutput(strings.NewReader(out))
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 4 {
		t.Fatalf("esperava 4 (gpg-pubkey excluído), got %d: %+v", len(pkgs), pkgs)
	}
	if pkgs[0].Name != "bash" || pkgs[0].Version != "5.1.8-1" || pkgs[0].Arch != "x86_64" || pkgs[0].Source != "rpm" {
		t.Fatalf("primeiro pacote errado: %+v", pkgs[0])
	}
	if pkgs[0].FullName != "bash-5.1.8-1.x86_64" {
		t.Fatalf("full_name = %q", pkgs[0].FullName)
	}
	// Epoch must be preserved verbatim in the version field so server-side
	// correlation can compare it against the epoch-bearing Notus advisory.
	grub2Found := false
	for i := range pkgs {
		if pkgs[i].Name == "grub2" {
			grub2Found = true
			if pkgs[i].Version != "1:2.06-70.el9_3" {
				t.Fatalf("epoch perdido: grub2.Version = %q, want %q", pkgs[i].Version, "1:2.06-70.el9_3")
			}
		}
		if pkgs[i].Name == "gpg-pubkey" {
			t.Fatal("gpg-pubkey deve ser excluído")
		}
	}
	if !grub2Found {
		t.Fatal("grub2 ausente")
	}
}

func TestCollectorFallsBackToRPMWhenNoDpkg(t *testing.T) {
	dir := t.TempDir()
	osr := filepath.Join(dir, "os-release")
	if err := os.WriteFile(osr, []byte("ID=fedora\nVERSION_ID=39\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	c := &Collector{
		osReleasePath:  osr,
		dpkgStatusPath: filepath.Join(dir, "inexistente"), // sem dpkg -> cai no rpm
		rpmList: func() ([]byte, error) {
			return []byte("bash\t5.2.15-1\tx86_64\nzlib\t1.2.13-3\tx86_64\n"), nil
		},
	}
	inv, err := c.Collect()
	if err != nil {
		t.Fatal(err)
	}
	if inv.OS.Distro != "fedora" || inv.OS.Release != "39" {
		t.Fatalf("os = %+v", inv.OS)
	}
	if len(inv.Packages) != 2 || inv.Packages[0].Source != "rpm" {
		t.Fatalf("packages = %+v", inv.Packages)
	}
}
