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
)

// terminal reports whether a job is in a final state (never delivered again).
func (s JobState) terminal() bool {
	switch s {
	case StateVerified, StateFailed, StateExpired, StateRejected:
		return true
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
	Signature     string          `json:"signature,omitempty"` // base64 Ed25519 over the canonical; set on Approve
	CreatedAt     time.Time       `json:"created_at"`
	DeliveredAt   time.Time       `json:"delivered_at,omitempty"`
	AckedAt       time.Time       `json:"acked_at,omitempty"`
	Result        *Result         `json:"result,omitempty"`
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

func (j *RemediationJob) clone() *RemediationJob {
	cp := *j
	cp.Payload = append(json.RawMessage(nil), j.Payload...)
	if j.Result != nil {
		r := *j.Result
		cp.Result = &r
	}
	return &cp
}
