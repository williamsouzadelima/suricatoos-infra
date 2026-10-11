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

// failedState reports whether s is a terminal FAILURE (not a success). A failed scan
// must not block a retry of the same target/scan_history — unlike Completed, which is
// a genuine success the anti-storm cooldown should honor.
func failedState(s State) bool {
	switch s {
	case StateFailed, StateStopped, StateExpired:
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

	// Reconciler bookkeeping — additive in the registry JSON (absent = zero).
	Attempt        int  `json:"attempt,omitempty"`         // gvmd task generation of this request (the bridge appends -a<N> when > 0)
	RetryNewTask   bool `json:"retry_new_task,omitempty"`  // set only by failDone: the next reopen moves to a new attempt
	FetchFailures  int  `json:"fetch_failures,omitempty"`  // failed fetch/cache attempts of a Done task (bounded by SCAN_FETCH_RETRY_LIMIT)
	StatusFailures int  `json:"status_failures,omitempty"` // consecutive status errors (expiry past the cap needs StatusFailuresToExpire)
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
// reNgine scan_history_id (and the request_id, below), so a retried launch finds
// the same task (idempotent) and the ingest can reconstruct state from gvmd after
// a restart. It mirrors scan_bridge.py `_task_name`, which is what actually names
// the task: a suffix with the first 12 alphanumerics of the request_id makes it
// unique PER REQUEST, so a scan_history_id re-sent after its job was reaped gets a
// fresh task instead of the old Done one (and its stale findings). Jobs launched
// before the suffix keep the legacy name "suricatoos-rengine-<id>"; the bridge
// falls back to it (pinned to the job's gvm_task_id) for status/fetch/stop.
// "-a<Attempt>" is appended when Attempt > 0 (a re-sent job that measured nothing
// rescans on a new task).
func (j *Job) taskName() string {
	name := "suricatoos-rengine-" + strconv.FormatInt(j.ScanHistoryID, 10)
	var suffix []rune
	for _, r := range j.RequestID {
		if len(suffix) == 12 {
			break
		}
		if r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' {
			suffix = append(suffix, r)
		}
	}
	if len(suffix) > 0 {
		name += "-" + string(suffix)
	}
	if j.Attempt > 0 {
		name += "-a" + strconv.Itoa(j.Attempt)
	}
	return name
}
