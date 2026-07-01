// Package sensorjobs is the cloud-side durable dispatch queue for internal
// scanner sensors (ADR-0007). Unlike the in-memory command channel, a scan job
// carries a rich target payload, is persisted (survives a control-plane restart),
// is idempotent, and is strictly scoped to a tenant: a sensor only ever polls/acks
// jobs whose tenant equals its verified cert Organization (O). The cloud is
// authoritative — it assigns job_id/correlation_id/tenant and gates every target
// to the tenant's authorized scope before a job is ever enqueued.
package sensorjobs

import "time"

// SchemaVersion is the scan-job contract version (schema/scan-job.schema.json).
const SchemaVersion = "1.0.0"

// PolicyScannerSensor is the cert OU a sensor must present to reach these routes.
const PolicyScannerSensor = "scanner-sensor"

// JobState is a job's delivery lifecycle in the cloud queue. The scan RESULT
// lifecycle lives on the sensor + the sensor-report path; here we only track
// dispatch: PENDING → DELIVERED (polled) → ACKED (sensor accepted), or EXPIRED.
// DONE is set when the matching sensor-report is imported (by the report path).
type JobState string

const (
	StatePending   JobState = "PENDING"
	StateDelivered JobState = "DELIVERED"
	StateAcked     JobState = "ACKED"
	StateDone      JobState = "DONE"
	StateExpired   JobState = "EXPIRED"
)

func (s JobState) terminal() bool { return s == StateDone || s == StateExpired }

// Source records where a job's targets came from (both funnel into one queue).
type Source string

const (
	SourceOperator Source = "operator-scope"
	SourceScore    Source = "score-discovery"
	SourceAgent    Source = "agent-discovery"
)

// ScanJob is one dispatched scan (schema/scan-job.schema.json).
type ScanJob struct {
	SchemaVersion string    `json:"schema_version"`
	JobID         string    `json:"job_id"`
	CorrelationID string    `json:"correlation_id"`
	Tenant        string    `json:"tenant"` // = cert O; server-set
	Source        Source    `json:"source,omitempty"`
	Targets       []string  `json:"targets"`
	Ports         string    `json:"ports,omitempty"`
	ScanConfig    string    `json:"scan_config,omitempty"`
	AliveTest     string    `json:"alive_test,omitempty"`
	MaxDuration   string    `json:"max_duration,omitempty"`
	State         JobState  `json:"state"`
	NotBefore     time.Time `json:"not_before,omitempty"`
	ExpiresAt     time.Time `json:"expires_at,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
	DeliveredAt   time.Time `json:"delivered_at,omitempty"`
	AckedAt       time.Time `json:"acked_at,omitempty"`
}

// EnqueueRequest is the internal request to dispatch a job (from the admin API or
// a discovery source). The cloud assigns job_id/correlation_id and validates
// tenant + scope before persisting.
type EnqueueRequest struct {
	Tenant      string
	Source      Source
	Targets     []string
	Ports       string
	ScanConfig  string
	AliveTest   string
	MaxDuration string
	TTL         time.Duration // 0 → default
}

func (j *ScanJob) clone() *ScanJob {
	cp := *j
	cp.Targets = append([]string(nil), j.Targets...)
	return &cp
}
