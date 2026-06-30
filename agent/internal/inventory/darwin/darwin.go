//go:build darwin

// Package darwin implements the macOS inventory Collector.
//
// Sources (all passive and local-only):
//   - pkgutil receipts from /var/db/receipts/*.plist (XML, always present)
//   - app bundles from /Applications/*.app/Contents/Info.plist (XML or binary)
//   - Homebrew formulas via `brew list --versions --formula` (optional)
//
// The collector never contacts the network and never modifies system state.
package darwin

import (
	"context"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/williamsouzadelima/suricatoos-infra/agent/internal/inventory"
	"github.com/williamsouzadelima/suricatoos-infra/agent/internal/version"
)

// Collector is the macOS inventory Collector. Use New to create.
type Collector struct {
	receiptsDir    string
	appsDir        string
	swVers         func() (productName, productVersion string, err error)
	brewList       func() ([]byte, error)
	uname          func() (string, error)
	plistConverter func(path string) ([]byte, error)
}

// New returns a Collector reading standard macOS system paths.
func New() *Collector {
	return &Collector{
		receiptsDir:    "/var/db/receipts",
		appsDir:        "/Applications",
		swVers:         defaultSwVers,
		brewList:       defaultBrewList,
		uname:          defaultUname,
		plistConverter: defaultPlistConverter,
	}
}

// Collect gathers OS facts and installed packages from this macOS host.
func (c *Collector) Collect() (*inventory.Inventory, error) {
	inv := &inventory.Inventory{
		SchemaVersion: inventory.SchemaVersion,
		CollectedAt:   time.Now().UTC(),
		OS: inventory.OS{
			Family: inventory.Darwin,
			Distro: "macos",
			Arch:   runtime.GOARCH,
		},
	}
	if h, err := os.Hostname(); err == nil {
		inv.Agent.Hostname = h
	}
	inv.Agent.AgentID = inv.Agent.Hostname
	inv.Agent.AgentVersion = version.Version
	if _, ver, err := c.swVers(); err == nil {
		inv.OS.Release = ver
	}
	if k, err := c.uname(); err == nil {
		inv.OS.Kernel = k
	}

	var pkgs []inventory.Package
	if receipts, err := readReceipts(c.receiptsDir); err == nil {
		pkgs = append(pkgs, receipts...)
	}
	if apps, err := scanApps(c.appsDir, c.plistConverter); err == nil {
		pkgs = append(pkgs, apps...)
	}
	if raw, err := c.brewList(); err == nil && len(raw) > 0 {
		pkgs = append(pkgs, parseBrewOutput(raw)...)
	}
	inv.Packages = pkgs
	inv.CycleHash = inv.ComputeCycleHash()
	return inv, nil
}

// defaultSwVers queries sw_vers for the macOS product version.
func defaultSwVers() (productName, productVersion string, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "sw_vers", "-productVersion").Output()
	if err != nil {
		return "", "", err
	}
	return "macos", strings.TrimSpace(string(out)), nil
}

// defaultUname returns the Darwin kernel version from `uname -r`.
func defaultUname() (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "uname", "-r").Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}
