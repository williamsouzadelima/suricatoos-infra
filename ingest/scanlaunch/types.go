// Package scanlaunch adds the reNgine→OpenVAS launch capability to the ingest
// binary: mTLS HTTP routes that persist a scan job, a single serialized
// reconciler that drives gvmd (via gmp-bridge/scan_bridge.py) through an
// explicit state machine, and the security controls that make launching ACTIVE
// scans from attacker-influenced recon data safe (default-deny IP allowlist,
// exact-DN authz, fail-closed CRL). It is compiled into the ingest binary but
// isolated from the passive inventory path (ADR-0006).
package scanlaunch

import (
	"strconv"
	"time"
)

// SchemaVersion is the scan-request contract version (schema/scan-request.schema.json).
const SchemaVersion = "1.0.0"

// GVM object IDs (canonical Greenbone defaults, verified on gvmd 22.7 at .97).
const (
	ConfigFullAndFast     = "daba56c8-73ec-11df-a475-002264764cea" // scan config "Full and fast"
	ScannerOpenVASDefault = "08b69003-5fc2-4037-a479-93b440211c73" // "OpenVAS Default" scanner
)

// State is a scan job's lifecycle state.
type State string

const (
	StatePending   State = "PENDING"   // persisted, not yet launched in gvmd
	StateRunning   State = "RUNNING"   // launched; OpenVAS scanning
	StateCompleted State = "COMPLETED" // gvmd Done; findings fetched + cached
	StateFailed    State = "FAILED"    // gvmd Interrupted, or a launch/fetch error
	StateStopped   State = "STOPPED"   // killed via DELETE
	StateExpired   State = "EXPIRED"   // exceeded SCAN_MAX_DURATION; auto-stopped
)

// terminal reports whether s is a final state the reconciler no longer advances.
func (s State) terminal() bool {
	switch s {
	case StateCompleted, StateFailed, StateStopped, StateExpired:
		return true
	}
	return false
}

// Host is one live host to scan: an IP literal plus its open TCP ports.
type Host struct {
	IP    string `json:"ip"`
	Ports []int  `json:"ports"`
}

// ScanRequest is the POST /v1/scan-request body (schema/scan-request.schema.json).
type ScanRequest struct {
	SchemaVersion        string `json:"schema_version"`
	RengineScanHistoryID int64  `json:"rengine_scan_history_id"`
	Target               string `json:"target,omitempty"`
	Engagement           string `json:"engagement,omitempty"`
	Hosts                []Host `json:"hosts"`
}

// Job is the persisted state of one scan request (registry entry / GET response).
type Job struct {
	RequestID     string    `json:"request_id"`              // unguessable external id (UUID)
	Tenant        string    `json:"tenant"`                  // cert O — ownership key
	CN            string    `json:"cn"`                      // cert CN — for audit
	ScanHistoryID int64     `json:"rengine_scan_history_id"` // idempotency anchor
	Target        string    `json:"target,omitempty"`
	Engagement    string    `json:"engagement,omitempty"`
	Hosts         []Host    `json:"hosts"`
	GVMTargetID   string    `json:"gvm_target_id,omitempty"`
	GVMTaskID     string    `json:"gvm_task_id,omitempty"`
	GVMReportID   string    `json:"gvm_report_id,omitempty"`
	State         State     `json:"state"`
	Progress      int       `json:"progress"`
	Error         string    `json:"error,omitempty"`
	StopRequested bool      `json:"stop_requested,omitempty"` // DELETE sets it; the reconciler performs the stop
	SubmittedAt   time.Time `json:"submitted_at"`
	StartedAt     time.Time `json:"started_at,omitempty"`
	CompletedAt   time.Time `json:"completed_at,omitempty"`
}

// clone returns a deep copy so callers never mutate the registry's stored Job.
func (j *Job) clone() *Job {
	cp := *j
	cp.Hosts = make([]Host, len(j.Hosts))
	for i, h := range j.Hosts {
		ports := make([]int, len(h.Ports))
		copy(ports, h.Ports)
		cp.Hosts[i] = Host{IP: h.IP, Ports: ports}
	}
	return &cp
}

// taskName is the deterministic gvmd task/target name — a pure function of the
// reNgine scan_history_id, so a retried launch finds the same task (idempotent)
// and the ingest can reconstruct state from gvmd after a restart.
func (j *Job) taskName() string {
	return "suricatoos-rengine-" + strconv.FormatInt(j.ScanHistoryID, 10)
}
