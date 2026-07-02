// Package sensorreport receives OpenVAS findings from an internal scanner sensor
// over mTLS (ADR-0007) and imports them into the central gvmd — but NEVER by
// trusting the sensor's XML/severity. It re-derives the tenant from the verified
// cert O, drops findings whose host is outside the tenant's authorized scope, and
// hands the survivors to gmp-bridge --mode network, which re-attests severity/CVE
// from the central feed by OID. A compromised sensor can neither forge nor
// suppress findings, nor write into another tenant's partition.
package sensorreport

import "github.com/williamsouzadelima/suricatoos-infra/ingest/scanlaunch"

// SchemaVersion is the sensor-report contract version.
const SchemaVersion = "1.0.0"

// PolicyScannerSensor is the cert OU a sensor must present.
const PolicyScannerSensor = "scanner-sensor"

// SensorReport is the POST /v1/sensor-report body. Findings reuse the scanlaunch
// Finding shape (the same normalized OpenVAS result the scan_bridge fetch emits).
type SensorReport struct {
	SchemaVersion string               `json:"schema_version"`
	CorrelationID string               `json:"correlation_id"`
	SensorID      string               `json:"sensor_id"`
	Tenant        string               `json:"tenant"` // cross-check only; the cert O is authoritative
	FeedVersion   string               `json:"feed_version,omitempty"`
	CollectedAt   string               `json:"collected_at,omitempty"`
	Findings      []scanlaunch.Finding `json:"findings"`
}

// TenantConfig is the per-tenant server-side config the report path needs: the
// scoped gvmd user (NOT admin) that owns the tenant's partition, and the tenant's
// authorized scope for host re-validation.
type TenantConfig struct {
	GmpUsername string
	GmpPassword string
	Scope       *Scope
}

// TenantResolver returns a tenant's config (ok=false = unknown tenant → deny).
type TenantResolver func(tenant string) (TenantConfig, bool)

// bridgeReport is what we hand to gmp-bridge --mode network (a temp JSON file).
type bridgeReport struct {
	Tenant   string               `json:"tenant"`
	ScanTime string               `json:"scan_time,omitempty"`
	Findings []scanlaunch.Finding `json:"findings"`
}
