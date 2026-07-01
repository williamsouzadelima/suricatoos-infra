// Package inventory defines the normalized, OS-independent inventory and the
// Collector contract every platform collector implements.
//
// The JSON shape here is the SOURCE OF TRUTH, mirrored by
// schema/inventory.schema.json (versioned). Bump SchemaVersion and the JSON
// Schema together on any backward-incompatible change.
//
// Collectors MUST be passive and local-only: they observe the host they run on
// and never probe or scan other hosts.
package inventory

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
	"time"
)

// SchemaVersion is the semantic version of the inventory contract.
const SchemaVersion = "1.0.0"

// OSFamily enumerates the supported operating-system families.
type OSFamily string

const (
	Linux   OSFamily = "linux"
	Darwin  OSFamily = "darwin"
	Windows OSFamily = "windows"
)

// PackageSource records where a package fact was observed (evidence/traceability).
type PackageSource string

const (
	SourceDpkg      PackageSource = "dpkg"
	SourceRPM       PackageSource = "rpm"
	SourcePkgutil   PackageSource = "pkgutil"
	SourceAppBundle PackageSource = "app-bundle"
	SourceHomebrew  PackageSource = "homebrew"
	SourceRegistry  PackageSource = "registry"
	SourceWinget    PackageSource = "winget"
)

// Package is one installed software item, normalized across platforms.
type Package struct {
	Name    string        `json:"name"`
	Version string        `json:"version"`
	Arch    string        `json:"arch,omitempty"`
	Source  PackageSource `json:"source"`
	// FullName is the Notus-style "name-version-release.arch" used for Linux
	// correlation; empty on platforms without that convention.
	FullName string `json:"full_name,omitempty"`
}

// OS describes the operating system / release for product selection in correlation.
type OS struct {
	Family  OSFamily `json:"family"`
	Distro  string   `json:"distro,omitempty"`
	Release string   `json:"release"`
	Arch    string   `json:"arch"`
	Kernel  string   `json:"kernel,omitempty"`
}

// Port is a LOCAL listening port. The agent never scans remote ports.
type Port struct {
	Port    int    `json:"port"`
	Proto   string `json:"proto"`
	Process string `json:"process,omitempty"`
}

// Facts holds non-package system facts relevant to correlation.
type Facts struct {
	ListeningPortsLocal []Port   `json:"listening_ports_local,omitempty"`
	Services            []string `json:"services,omitempty"`
}

// Agent identifies the reporting agent and its enrolled scope.
type Agent struct {
	AgentID      string `json:"agent_id"`
	AgentVersion string `json:"agent_version"`
	Hostname     string `json:"hostname"`
	Scope        string `json:"scope,omitempty"`
}

// Inventory is the full normalized payload an agent emits per collection cycle.
type Inventory struct {
	SchemaVersion string    `json:"schema_version"`
	Agent         Agent     `json:"agent"`
	CollectedAt   time.Time `json:"collected_at"`
	OS            OS        `json:"os"`
	Packages      []Package `json:"packages"`
	Facts         Facts     `json:"facts"`
	CycleHash     string    `json:"cycle_hash,omitempty"`
	// Force marks an on-demand (scan_now) report so the ingest imports it even if
	// the inventory is unchanged. Dedup then only skips the periodic 15-min cycles.
	Force bool `json:"force,omitempty"`
}

// Collector gathers an Inventory locally. Each platform provides one
// implementation (build-tagged). Implementations MUST be passive/local-only.
type Collector interface {
	Collect() (*Inventory, error)
}

// ComputeCycleHash returns a deterministic SHA-256 over the inventory's
// identifying content (OS + packages), independent of the collection timestamp,
// so an unchanged host yields a stable hash for idempotent dedupe at ingest.
//
// The hash is order-independent: it sorts a canonical line per fact before
// hashing, so collector iteration order does not affect the result.
func (inv *Inventory) ComputeCycleHash() string {
	lines := make([]string, 0, len(inv.Packages)+1)
	lines = append(lines, strings.Join([]string{
		"os", string(inv.OS.Family), inv.OS.Distro, inv.OS.Release, inv.OS.Arch,
	}, "|"))
	for _, p := range inv.Packages {
		lines = append(lines, strings.Join([]string{
			"pkg", p.Name, p.Version, p.Arch, string(p.Source),
		}, "|"))
	}
	sort.Strings(lines)
	h := sha256.New()
	for _, l := range lines {
		h.Write([]byte(l))
		h.Write([]byte{'\n'})
	}
	return hex.EncodeToString(h.Sum(nil))
}
