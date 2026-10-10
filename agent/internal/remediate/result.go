package remediate

import "time"

// Report status values the control-plane accepts (anything else is rejected by
// its ReportHandler). APPLIED is NOT terminal server-side — the cloud still
// re-scans to confirm (→ VERIFIED); the agent never declares itself verified.
const (
	StatusApplied = "applied"
	StatusFailed  = "failed"
)

// Result is the agent's report of applying a job
// (schema/remediation-result.schema.json), POSTed to the report endpoint. It
// mirrors the control-plane's remediation.Result wire shape so the JSON decodes
// there unchanged. Before/After/RollbackToken let the cloud audit the change and
// drive a later rollback; RebootPending defers verification until the next boot.
type Result struct {
	Status        string    `json:"status"` // StatusApplied | StatusFailed
	Detail        string    `json:"detail,omitempty"`
	Before        string    `json:"before,omitempty"`         // prior state, captured for rollback/audit
	After         string    `json:"after,omitempty"`          // resulting state
	RollbackToken string    `json:"rollback_token,omitempty"` // opaque handle the agent kept
	RebootPending bool      `json:"reboot_pending,omitempty"`
	ReportedAt    time.Time `json:"reported_at,omitempty"`
}
