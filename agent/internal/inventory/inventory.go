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
//
// 1.1.0 adds optional Windows posture fields (OS build/UBR, installed KBs,
// missing updates, central-management flags) used by the Windows MSRC
// correlation path (ADR-0008). 1.2.0 adds facts.cis_state (neutral
// security-configuration readings for CIS L1 hardening, ADR-0009). Every bump is
// a MINOR, backward-compatible change: every added field is optional/omitempty,
// so an older consumer ignores them and the ingest accepts any 1.x (see
// ingest.schemaCompatible). Deploy the ingest before rolling agents to a new minor.
const SchemaVersion = "1.2.0"

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
	// Build is the Windows build number, e.g. "19045"; empty on non-Windows.
	Build string `json:"build,omitempty"`
	// UBR is the Windows Update Build Revision, e.g. "4291". With Build it forms
	// the precise patch level ("19045.4291") that MSRC correlation needs to tell
	// a patched host from an unpatched one. Empty on non-Windows.
	UBR string `json:"ubr,omitempty"`
}

// Port is a LOCAL listening port. The agent never scans remote ports.
type Port struct {
	Port    int    `json:"port"`
	Proto   string `json:"proto"`
	Process string `json:"process,omitempty"`
}

// MissingUpdate is one OS update reported applicable-but-not-installed. It is
// populated ONLY from an authoritative source (the Windows Update Agent); the
// agent never judges severity itself — MSRCSeverity is carried verbatim from
// the source so correlation stays non-fabricating (ADR-0001 D1).
type MissingUpdate struct {
	KB             string   `json:"kb"`
	Title          string   `json:"title,omitempty"`
	MSRCSeverity   string   `json:"msrc_severity,omitempty"`
	RebootRequired bool     `json:"reboot_required,omitempty"`
	Categories     []string `json:"categories,omitempty"`
	UpdateID       string   `json:"update_id,omitempty"`
	// Source records where the update was offered from, e.g. "microsoft-update"
	// or "wsus"; used downstream to avoid fighting a WSUS/Intune-managed host.
	Source string `json:"source,omitempty"`
}

// Management records whether the host is centrally managed, so the cloud can
// avoid proposing a local fix that a GPO/MDM would just revert. Evidence only;
// nil when the posture is unknown or not applicable (non-Windows).
type Management struct {
	DomainJoined   bool   `json:"domain_joined,omitempty"`
	WSUSConfigured bool   `json:"wsus_configured,omitempty"`
	WSUSURL        string `json:"wsus_url,omitempty"`
	IntuneEnrolled bool   `json:"intune_enrolled,omitempty"`
}

// CISState is one measured security-configuration reading — a registry value, a
// secedit System Access / Privilege Rights entry, an auditpol subcategory, or a
// service start type. It is NEUTRAL evidence: the current value only, with NO
// pass/fail and NO CIS rule mapping. The server owns the benchmark ruleset and
// decides compliance (ADR-0009); the agent never judges. Account references in
// Privilege Rights are scrubbed to well-known SIDs so no arbitrary username or
// SID ever leaves the host (LGPD minimization).
type CISState struct {
	Source string `json:"source"` // "registry" | "secedit" | "auditpol" | "service"
	Key    string `json:"key"`
	Value  string `json:"value"`
}

// Facts holds non-package system facts relevant to correlation.
type Facts struct {
	ListeningPortsLocal []Port   `json:"listening_ports_local,omitempty"`
	Services            []string `json:"services,omitempty"`
	// InstalledKBs lists Windows update KB identifiers already present, evidence
	// for MSRC supersedence; empty on non-Windows.
	InstalledKBs []string `json:"installed_kbs,omitempty"`
	// MissingUpdates lists updates the host reports as missing (Windows/WUA).
	MissingUpdates []MissingUpdate `json:"missing_updates,omitempty"`
	// Management is the central-management posture (Windows); nil when unknown.
	Management *Management `json:"management,omitempty"`
	// CISState holds neutral security-configuration readings (Windows); the
	// server maps them to a CIS L1 ruleset (ADR-0009). Empty on non-Windows.
	CISState []CISState `json:"cis_state,omitempty"`
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
// identifying content (OS + packages + Windows missing updates), independent of
// the collection timestamp, so an unchanged host yields a stable hash for
// idempotent dedupe at ingest.
//
// The hash is order-independent: it sorts a canonical line per fact before
// hashing, so collector iteration order does not affect the result.
//
// The "os" line carries build/UBR and missing-update lines are folded in, so a
// Windows host that patches (build/UBR advances, a missing update disappears)
// produces a new hash and re-imports — otherwise a fixed host would dedupe and
// the finding would never clear. This changes the hash of EVERY host on upgrade
// to 1.1.0 (the "os" line gained two fields), causing exactly one extra import
// per host; that is benign and expected.
func (inv *Inventory) ComputeCycleHash() string {
	lines := make([]string, 0, len(inv.Packages)+len(inv.Facts.MissingUpdates)+1)
	lines = append(lines, strings.Join([]string{
		"os", string(inv.OS.Family), inv.OS.Distro, inv.OS.Release, inv.OS.Arch,
		inv.OS.Build, inv.OS.UBR,
	}, "|"))
	for _, p := range inv.Packages {
		lines = append(lines, strings.Join([]string{
			"pkg", p.Name, p.Version, p.Arch, string(p.Source),
		}, "|"))
	}
	for _, u := range inv.Facts.MissingUpdates {
		lines = append(lines, strings.Join([]string{
			"miss", u.KB, u.UpdateID,
		}, "|"))
	}
	// cis_state folds in too, so a hardening change (a setting drifts or is fixed)
	// produces a new hash and re-imports — otherwise the finding would never clear.
	for _, c := range inv.Facts.CISState {
		lines = append(lines, strings.Join([]string{
			"cis", c.Source, c.Key, c.Value,
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
