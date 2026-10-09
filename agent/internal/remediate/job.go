// Package remediate is the agent-side counterpart of the cloud remediation queue
// (ADR-0010). THIS slice (Fase 3a) only RECEIVES and cryptographically VERIFIES a
// signed job — it writes NOTHING to the OS. The isolated executor that applies a
// verified job (WUA/winget/CIS, with captured prior state for rollback and a
// maintenance window) is a later slice.
//
// A job is acted upon only if VerifyAt passes against the remediation public key
// pinned at enroll (enroll.Identity.RemediationPublicKey): the signature binds the
// job to THIS agent + tenant + a single-use nonce + an expiry (canonical.go), so a
// job cannot be transplanted to another host, replayed, or paired with a swapped
// payload.
package remediate

import (
	"encoding/json"
	"time"
)

// Type is the kind of remediation a job carries. The executor interprets the
// payload; verification treats it as opaque (folded in only by SHA-256).
type Type string

const (
	TypePackagePatch    Type = "package_patch"    // apply a specific vendor update (e.g. a KB)
	TypeConfigHardening Type = "config_hardening" // set a specific security configuration
)

// Job is one dispatched remediation as received from the control-plane
// (schema/remediation-job.schema.json). The cloud assigns every field; the agent
// only verifies and (later) applies. Only the fields the agent acts on are
// modelled — server bookkeeping (created_at, delivered_at, acked_at, result) is
// ignored on decode, so unknown JSON fields are simply dropped.
type Job struct {
	SchemaVersion string          `json:"schema_version"`
	JobID         string          `json:"job_id"`
	CorrelationID string          `json:"correlation_id"`
	Tenant        string          `json:"tenant"`
	AgentID       string          `json:"agent_id"`
	Type          Type            `json:"type"`
	Payload       json.RawMessage `json:"payload"`
	PayloadSHA256 string          `json:"payload_sha256"`
	Nonce         string          `json:"nonce"`
	State         string          `json:"state"`
	IssuedAt      time.Time       `json:"issued_at"`
	NotBefore     time.Time       `json:"not_before"`
	NotAfter      time.Time       `json:"not_after"`
	ExpiresAt     time.Time       `json:"expires_at"`
	ApprovedBy    string          `json:"approved_by"`
	Signature     string          `json:"signature"`
}
