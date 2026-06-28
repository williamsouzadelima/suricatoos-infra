package linux

import (
	"bytes"
	"fmt"
	"os"
	"runtime"
	"time"

	"github.com/williamsouzadelima/suricatoos-infra/agent/internal/inventory"
)

const (
	defaultOSReleasePath  = "/etc/os-release"
	defaultDpkgStatusPath = "/var/lib/dpkg/status"
)

// Collector is the Linux inventory Collector. It is passive and local-only.
type Collector struct {
	osReleasePath  string
	dpkgStatusPath string
	rpmList        func() ([]byte, error) // injetável p/ testes
}

// New returns a Collector reading the standard Linux system paths.
func New() *Collector {
	return &Collector{
		osReleasePath:  defaultOSReleasePath,
		dpkgStatusPath: defaultDpkgStatusPath,
		rpmList:        defaultRPMList,
	}
}

// Collect gathers OS facts and installed packages from this Linux host and
// stamps a deterministic cycle hash.
func (c *Collector) Collect() (*inventory.Inventory, error) {
	inv := &inventory.Inventory{
		SchemaVersion: inventory.SchemaVersion,
		CollectedAt:   time.Now().UTC(),
		OS:            inventory.OS{Family: inventory.Linux, Arch: runtime.GOARCH},
	}
	if h, err := os.Hostname(); err == nil {
		inv.Agent.Hostname = h
	}
	if f, err := os.Open(c.osReleasePath); err == nil {
		distro, release, perr := parseOSRelease(f)
		f.Close()
		if perr == nil {
			inv.OS.Distro, inv.OS.Release = distro, release
		}
	}
	pkgs, err := c.collectPackages()
	if err != nil {
		return nil, err
	}
	inv.Packages = pkgs
	inv.CycleHash = inv.ComputeCycleHash()
	return inv, nil
}

// collectPackages reads the native package database: dpkg (Debian/Ubuntu/Kali)
// when present, otherwise rpm (RHEL/Fedora/SUSE) via a structured query.
func (c *Collector) collectPackages() ([]inventory.Package, error) {
	if f, err := os.Open(c.dpkgStatusPath); err == nil {
		defer f.Close()
		return parseDpkgStatus(f)
	}
	out, err := c.rpmList()
	if err != nil {
		return nil, fmt.Errorf("nenhuma base de pacotes suportada encontrada (dpkg/rpm): %w", err)
	}
	return parseRPMOutput(bytes.NewReader(out))
}

// fullName builds a normalized "name-version[.arch]" string. The exact Notus
// matching key is built by the correlation engine (Fase 2); this is a
// convenience representation carried in the inventory.
func fullName(name, version, arch string) string {
	if arch == "" {
		return name + "-" + version
	}
	return name + "-" + version + "." + arch
}
