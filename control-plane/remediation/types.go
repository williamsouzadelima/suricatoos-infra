// Package remediation is the cloud-side durable queue for endpoint remediation
// jobs (patch + config hardening), the counterpart that lets the otherwise
// passive agent APPLY a fix — but only one that a human approved (ADR-0010).
//
// Design invariants (see ADR-0010):
//   - A job is born PENDING_APPROVAL and is SIGNED only on Approve. The agent
//     acts solely on a job carrying a valid signature, so a leaked/forged queue
//     entry without approval is inert.
//   - The signature binds the job to ONE agent and tenant plus a single-use
//     nonce and an expiry (canonical.go), so a job cannot be replayed to another
//     host or reused.
//   - Every poll/ack/report is scoped to the caller's cert identity: CN == the
//     job's agent_id AND O == its tenant. An agent only ever sees its own jobs.
//   - VERIFIED is set SERVER-SIDE after a re-scan confirms the fix; the agent
//     only ever reports APPLIED/FAILED — it never declares itself verified.
package remediation

import (
	"encoding/json"
	"time"
)

// SchemaVersion is the remediation-job contract version (schema/remediation-job.schema.json).
const SchemaVersion = "1.0.0"

// PolicyAgentEndpoint is the cert OU an agent must present to poll remediation jobs.
const PolicyAgentEndpoint = "agent-endpoint"

// Type is the kind of remediation a job carries. The payload shape depends on it
// (the agent-side executor interprets it); the queue treats the payload as opaque.
type Type string

const (
	TypePackagePatch    Type = "package_patch"    // apply a specific vendor update (e.g. a KB)
	TypeConfigHardening Type = "config_hardening" // set a specific security configuration
)

func (t Type) valid() bool {
	return t == TypePackagePatch || t == TypeConfigHardening
}

// JobState is a job's lifecycle. The human-approval gate (PENDING_APPROVAL →
// APPROVED) precedes any delivery, and APPLIED is NOT terminal — the server
// still has to confirm the fix (→ VERIFIED) by re-scanning.
//
// An operator can take a job out of the queue in two ways, and which one depends on
// whether the agent has it: REJECTED is for a job NOT delivered yet (PENDING_APPROVAL
// or APPROVED) — nothing happened on any host; CLOSED is for one the agent already
// received (DELIVERED, ACKED, APPLIED or FAILED), where a change may have reached the
// host and the record of it (approver, result, rollback_token) has to be kept.
//
// ExpiresAt only bounds the states BEFORE the agent has effectively taken the job
// (see expirable): once a job is ACKED or APPLIED the deadline no longer applies.
type JobState string

const (
	StatePendingApproval JobState = "PENDING_APPROVAL"
	StateApproved        JobState = "APPROVED"
	StateDelivered       JobState = "DELIVERED"
	StateAcked           JobState = "ACKED"
	StateApplied         JobState = "APPLIED"
	StateFailed          JobState = "FAILED"
	StateVerified        JobState = "VERIFIED"
	StateExpired         JobState = "EXPIRED"
	StateRejected        JobState = "REJECTED"
	StateClosed          JobState = "CLOSED"
)

// terminal reports whether a job is in a final state (never delivered again).
func (s JobState) terminal() bool {
	switch s {
	case StateVerified, StateFailed, StateExpired, StateRejected, StateClosed:
		return true
	}
	return false
}

// expirable reports whether a lapsed ExpiresAt still moves a job in this state to
// EXPIRED. It does for the states BEFORE the agent has effectively taken the job:
// PENDING_APPROVAL and APPROVED (never handed out) and DELIVERED (handed out but
// not acked yet — the agent re-checks the signed expiry itself before acting, so
// it refuses a lapsed job too).
//
// It does NOT for ACKED (the agent accepted the job and may be applying it) nor
// APPLIED (already applied, awaiting the re-scan that verifies it): expiring those
// would discard the apply result — Report only accepts DELIVERED/ACKED jobs — and
// the very fact that the fix was applied. Terminal states are already final.
//
// Caveat: today's agent runner acks AFTER applying (right before it reports), so
// a job being applied is still DELIVERED here, and one whose ack/report never
// arrives before ExpiresAt lapses can still be swept. Acking before applying, on
// the agent side, would close that window.
func (s JobState) expirable() bool {
	switch s {
	case StatePendingApproval, StateApproved, StateDelivered:
		return true
	}
	return false
}

// allStates lists every lifecycle state (the listing filter accepts exactly these).
var allStates = []JobState{
	StatePendingApproval, StateApproved, StateDelivered, StateAcked, StateApplied,
	StateFailed, StateVerified, StateExpired, StateRejected, StateClosed,
}

// valid reports whether s is one of the lifecycle states.
func (s JobState) valid() bool {
	for _, st := range allStates {
		if s == st {
			return true
		}
	}
	return false
}

// Result is the agent's report of applying a job (schema/remediation-result.schema.json).
type Result struct {
	Status        string    `json:"status"` // "applied" | "failed"
	Detail        string    `json:"detail,omitempty"`
	Before        string    `json:"before,omitempty"`         // prior state, for rollback/audit
	After         string    `json:"after,omitempty"`          // resulting state
	RollbackToken string    `json:"rollback_token,omitempty"` // opaque handle the agent kept
	RebootPending bool      `json:"reboot_pending,omitempty"`
	ReportedAt    time.Time `json:"reported_at,omitempty"`
}

// RemediationJob is one dispatched remediation (schema/remediation-job.schema.json).
// The cloud assigns all identity fields; the agent never sets them.
type RemediationJob struct {
	SchemaVersion string          `json:"schema_version"`
	JobID         string          `json:"job_id"`         // cloud-assigned, unguessable
	CorrelationID string          `json:"correlation_id"` // job → finding → ticket
	Tenant        string          `json:"tenant"`         // = cert O; server-set
	AgentID       string          `json:"agent_id"`       // = cert CN; the ONE host this job is for
	Type          Type            `json:"type"`
	Payload       json.RawMessage `json:"payload"`        // opaque to the queue; the executor reads it
	PayloadSHA256 string          `json:"payload_sha256"` // binds the payload into the signature
	Nonce         string          `json:"nonce"`          // per-job entropy folded into the signature; replay defense (dedup by job_id + VerifyAt expiry) is enforced by the agent executor in Fase 3, not consumed here
	State         JobState        `json:"state"`
	IssuedAt      time.Time       `json:"issued_at,omitempty"`  // when it was signed (= approval time)
	NotBefore     time.Time       `json:"not_before,omitempty"` // maintenance window start
	NotAfter      time.Time       `json:"not_after,omitempty"`  // maintenance window end
	ExpiresAt     time.Time       `json:"expires_at,omitempty"`
	ApprovedBy    string          `json:"approved_by,omitempty"` // operator identity (audit)
	ApprovedAt    time.Time       `json:"approved_at,omitempty"`
	RejectedBy    string          `json:"rejected_by,omitempty"` // who rejected the job (REJECTED); ApprovedBy is never overwritten by it
	RejectedAt    time.Time       `json:"rejected_at,omitzero"`
	ClosedBy      string          `json:"closed_by,omitempty"` // who took a delivered job out of the queue (CLOSED)
	ClosedAt      time.Time       `json:"closed_at,omitzero"`
	ClosedReason  string          `json:"closed_reason,omitempty"`
	Signature     string          `json:"signature,omitempty"` // base64 Ed25519 over the canonical; set on Approve
	CreatedAt     time.Time       `json:"created_at"`
	DeliveredAt   time.Time       `json:"delivered_at,omitempty"`
	AckedAt       time.Time       `json:"acked_at,omitempty"`
	VerifiedAt    time.Time       `json:"verified_at,omitzero"` // when an operator marked the APPLIED job VERIFIED (MarkVerified)
	ExpiredAt     time.Time       `json:"expired_at,omitzero"`  // when the expiry sweep moved the job to EXPIRED (the poll that found the deadline lapsed)
	Result        *Result         `json:"result,omitempty"`
	// LateReports keeps the reports the queue refused (see Registry.Report) whole, so
	// an operator can still reach their before/rollback_token: at most maxLateReports
	// of them — the FIRST one, pinned for good, and the most recent ones, which rotate.
	// A report equal to a kept one is not stored again. LateReportsTotal counts the
	// reports stored, so the pinned one is #1 and the newest kept is #LateReportsTotal
	// (the number the audit line quotes).
	LateReports      []Result `json:"late_reports,omitempty"`
	LateReportsTotal int      `json:"late_reports_total,omitempty"`
}

// EnqueueRequest is the internal request to create a PENDING_APPROVAL job. The
// cloud assigns job_id/correlation_id/nonce and computes payload_sha256.
type EnqueueRequest struct {
	Tenant    string
	AgentID   string
	Type      Type
	Payload   json.RawMessage
	NotBefore time.Time
	NotAfter  time.Time
	TTL       time.Duration // 0 → default
}

// lastEventAt is when something worth keeping last happened to the job: its creation, a
// rejection, a closure, a verification, an expiry, the agent's result or the latest
// report it refused. A final job is reaped a retention AFTER this — not after its
// creation — so closing or verifying an old APPLIED job, an expiry that the sweep only
// finds out about on the agent's next poll, a result that arrives late or a late refused
// report restarts the clock instead of handing the data they just preserved (approver,
// result, rollback_token) to the very next Enqueue's reaper. Every final state has a
// stamp of its own here (VERIFIED: VerifiedAt, EXPIRED: ExpiredAt, REJECTED: RejectedAt,
// CLOSED: ClosedAt, FAILED: the result's ReportedAt); jobs persisted before VerifiedAt
// and ExpiredAt existed simply do not have those two, and fall back to the rest.
//
// The clock restarts, but not for ever: reapLocked also caps a final job's life to
// maxFinalAge from its creation, because some of these events (a late report) are the
// agent's to produce.
func (j *RemediationJob) lastEventAt() time.Time {
	last := j.CreatedAt
	later := func(t time.Time) {
		if t.After(last) {
			last = t
		}
	}
	later(j.RejectedAt)
	later(j.ClosedAt)
	later(j.VerifiedAt)
	later(j.ExpiredAt)
	if j.Result != nil {
		later(j.Result.ReportedAt)
	}
	for _, lr := range j.LateReports {
		later(lr.ReportedAt)
	}
	return last
}

// lateReportIndex is the index in LateReports of the kept report with the same content
// as res (everything the agent supplies; the server's timestamp does not count), or -1.
func (j *RemediationJob) lateReportIndex(res Result) int {
	for i, lr := range j.LateReports {
		if sameReport(lr, res) {
			return i
		}
	}
	return -1
}

// lateReportNumber is the "late_report #n" of the kept report at index i: the pinned
// first one is #1, and the rest are the most recent ones, so the last is
// #LateReportsTotal, the one before it #LateReportsTotal-1.
func (j *RemediationJob) lateReportNumber(i int) int {
	if i == 0 {
		return 1
	}
	return j.LateReportsTotal - (len(j.LateReports) - 1 - i)
}

func (j *RemediationJob) clone() *RemediationJob {
	cp := *j
	cp.Payload = append(json.RawMessage(nil), j.Payload...)
	if j.Result != nil {
		r := *j.Result
		cp.Result = &r
	}
	cp.LateReports = append([]Result(nil), j.LateReports...)
	return &cp
}
