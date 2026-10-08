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
	"context"
	"os"
	"runtime"
	"time"

	"github.com/williamsouzadelima/suricatoos-infra/agent/internal/inventory"
	"github.com/williamsouzadelima/suricatoos-infra/agent/internal/version"
)

// postureTimeout caps the PowerShell/WUA posture collection so a slow or stuck
// Windows Update Agent can never hang the collection loop. On timeout the
// posture is simply omitted (non-fatal); see the note in winposture.go.
const postureTimeout = 120 * time.Second

// Collector is the Windows inventory Collector. Use New to create.
type Collector struct {
	enumKeys func() ([]winEntry, error)
	osInfo   func() (release, arch string, err error)
	// osBuild returns the build number + UBR (precise patch level for MSRC).
	osBuild func() (build, ubr string)
	// management returns the central-management posture (domain/WSUS/Intune).
	management func(ctx context.Context) (*inventory.Management, error)
	// missingUpdates returns WUA applicable-but-not-installed updates; source is
	// the WUA origin label ("microsoft-update" | "wsus").
	missingUpdates func(ctx context.Context, source string) ([]inventory.MissingUpdate, error)
}

// winEntry is one raw entry read from an Uninstall registry subkey.
type winEntry struct {
	name    string
	version string
	arch    string // "x86_64" (64-bit key) or "x86" (WOW6432Node)
}

// New returns a Collector reading the Windows Uninstall registry keys, the OS
// build/UBR, and the WUA/management posture.
func New() *Collector {
	return &Collector{
		enumKeys: defaultEnumKeys,
		osInfo:   defaultOSInfo,
		osBuild:  defaultOSBuild,
		management: func(ctx context.Context) (*inventory.Management, error) {
			return collectManagement(ctx, execRunner)
		},
		missingUpdates: func(ctx context.Context, source string) ([]inventory.MissingUpdate, error) {
			return collectMissingUpdates(ctx, execRunner, source)
		},
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
	inv.Agent.AgentID = inv.Agent.Hostname
	inv.Agent.AgentVersion = version.Version
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

	// Precise patch level for MSRC correlation (ADR-0008).
	if c.osBuild != nil {
		inv.OS.Build, inv.OS.UBR = c.osBuild()
	}

	// Central-management posture + WUA missing updates. Both are best-effort and
	// NON-FATAL: a slow/unavailable WUA must never block or fail the inventory,
	// and absence of missing_updates means "not collected", NEVER "clean" — the
	// authoritative Windows detection is server-side MSRC correlation (ADR-0008).
	ctx, cancel := context.WithTimeout(context.Background(), postureTimeout)
	defer cancel()
	var mgmt *inventory.Management
	if c.management != nil {
		if m, err := c.management(ctx); err == nil {
			mgmt = m
			inv.Facts.Management = m
		}
	}
	if c.missingUpdates != nil {
		if ups, err := c.missingUpdates(ctx, sourceFor(mgmt)); err == nil {
			inv.Facts.MissingUpdates = ups
		}
	}

	inv.CycleHash = inv.ComputeCycleHash()
	return inv, nil
}
