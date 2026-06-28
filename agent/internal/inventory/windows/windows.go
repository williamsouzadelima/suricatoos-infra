//go:build windows

// Package windows implements the Windows inventory Collector.
//
// Sources (passive, local-only):
//   - HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall (64-bit apps)
//   - HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall (32-bit apps)
//
// Win32_Product (WMI) is intentionally avoided: it triggers MSI reconfiguration
// for every installed package on enumeration, which is intrusive and slow.
// The Uninstall registry key is the canonical, read-only view of installed software.
package windows

import (
	"runtime"
	"time"

	"os"

	"github.com/williamsouzadelima/suricatoos-infra/agent/internal/inventory"
)

// Collector is the Windows inventory Collector. Use New to create.
type Collector struct {
	enumKeys func() ([]winEntry, error)
	osInfo   func() (release, arch string, err error)
}

// winEntry is one raw entry read from an Uninstall registry subkey.
type winEntry struct {
	name    string
	version string
	arch    string // "x86_64" (64-bit key) or "x86" (WOW6432Node)
}

// New returns a Collector reading the Windows Uninstall registry keys.
func New() *Collector {
	return &Collector{
		enumKeys: defaultEnumKeys,
		osInfo:   defaultOSInfo,
	}
}

// Collect gathers OS facts and installed packages from this Windows host.
func (c *Collector) Collect() (*inventory.Inventory, error) {
	inv := &inventory.Inventory{
		SchemaVersion: inventory.SchemaVersion,
		CollectedAt:   time.Now().UTC(),
		OS: inventory.OS{
			Family: inventory.Windows,
			Distro: "windows",
			Arch:   runtime.GOARCH,
		},
	}
	if h, err := os.Hostname(); err == nil {
		inv.Agent.Hostname = h
	}
	if release, arch, err := c.osInfo(); err == nil {
		inv.OS.Release = release
		if arch != "" {
			inv.OS.Arch = arch
		}
	}

	entries, err := c.enumKeys()
	if err != nil {
		return nil, err
	}
	seen := make(map[string]bool, len(entries))
	for _, e := range entries {
		if e.name == "" || e.version == "" {
			continue
		}
		key := e.name + "|" + e.version
		if seen[key] {
			continue // dedup: same package in both 64- and 32-bit views
		}
		seen[key] = true
		inv.Packages = append(inv.Packages, inventory.Package{
			Name:    e.name,
			Version: e.version,
			Arch:    e.arch,
			Source:  inventory.SourceRegistry,
		})
	}
	inv.CycleHash = inv.ComputeCycleHash()
	return inv, nil
}
