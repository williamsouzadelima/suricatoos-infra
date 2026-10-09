package correlation

import "time"

// Inventory is the minimal subset of schema/inventory.schema.json the
// correlator needs. The full contract lives in the JSON schema file.
type Inventory struct {
	SchemaVersion string    `json:"schema_version"`
	Agent         AgentInfo `json:"agent"`
	CollectedAt   time.Time `json:"collected_at"`
	OS            OSInfo    `json:"os"`
	Packages      []Package `json:"packages"`
	// CISState carries the agent's neutral security-configuration readings
	// (facts.cis_state) for the hardening correlator (ADR-0009). Empty on hosts
	// that do not collect it.
	CISState []CISStateInfo `json:"cis_state,omitempty"`
}

// CISStateInfo is one neutral security-configuration reading (registry value,
// secedit entry, auditpol subcategory, or service start type). The hardening
// correlator maps it to the server-side CIS L1 ruleset (ADR-0009); the agent
// never judges compliance and the value is already SID-scrubbed at the source.
type CISStateInfo struct {
	Source string `json:"source"`
	Key    string `json:"key"`
	Value  string `json:"value"`
}

// AgentInfo holds identifying fields from the agent section of an inventory.
type AgentInfo struct {
	AgentID  string `json:"agent_id"`
	Hostname string `json:"hostname"`
}

// OSInfo carries the OS classification needed to select the right advisory set.
type OSInfo struct {
	Family  string `json:"family"`  // "linux" | "darwin" | "windows"
	Distro  string `json:"distro"`  // e.g. "debian", "ubuntu"
	Release string `json:"release"` // e.g. "12", "22.04", "22H2"
	// Build and UBR are the Windows build number and Update Build Revision
	// (e.g. "19045" + "4291" → 10.0.19045.4291). Together they are the precise
	// patch level the MSRC correlator compares against each CSAF fixed version.
	// Empty on non-Windows.
	Build string `json:"build,omitempty"`
	UBR   string `json:"ubr,omitempty"`
}

// Package mirrors schema/inventory.schema.json#/properties/packages/items.
type Package struct {
	Name     string `json:"name"`
	Version  string `json:"version"`
	Arch     string `json:"arch,omitempty"`
	Source   string `json:"source"` // "dpkg" | "rpm" | ...
	FullName string `json:"full_name,omitempty"`
}

// Evidence records which advisory file produced the finding and via which
// package collector source.
type Evidence struct {
	Source          string `json:"source"`           // collector source ("dpkg", "rpm")
	MatchedAdvisory string `json:"matched_advisory"` // advisory file name, e.g. "debian_12.notus"
}

// Finding is one vulnerability finding, conforming to schema/finding.schema.json.
// CVE/severity are omitted here; gvmd enriches them from the OID when the report
// is imported (see gmp-bridge). If gvmd enrichment is absent, the fields remain
// empty — no severity is fabricated (ADR-0001).
type Finding struct {
	OID             string   `json:"oid"`
	CVE             []string `json:"cve,omitempty"`
	Severity        float64  `json:"severity,omitempty"`
	SeverityOrigin  string   `json:"severity_origin,omitempty"`
	PackageObserved string   `json:"package_observed"`
	PackageFixed    string   `json:"package_fixed"`
	Specifier       string   `json:"specifier"`
	Product         string   `json:"product"`
	Evidence        Evidence `json:"evidence"`
	DetectedAt      string   `json:"detected_at"` // RFC3339 UTC
}

// FindingReport is the top-level output of the correlator, conforming to
// schema/finding.schema.json.
type FindingReport struct {
	SchemaVersion string    `json:"schema_version"`
	AgentID       string    `json:"agent_id"`
	Host          string    `json:"host"`
	CollectedAt   time.Time `json:"collected_at"`
	Findings      []Finding `json:"findings"`
}

// Correlator correlates an Inventory against vulnerability advisories and
// returns a FindingReport. Implementations must be safe for concurrent use.
type Correlator interface {
	Correlate(inv Inventory) (*FindingReport, error)
}
