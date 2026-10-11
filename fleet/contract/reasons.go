package contract

// RejectReason is every reason a node refuses a command for (fleet-result.schema.json#/$defs/reject_reason),
// one per row of the ADR-0011 table "Verificação no nó".
type RejectReason string

// The reasons, in the schema's enum order.
const (
	ReasonBadEnvelope              RejectReason = "bad_envelope"
	ReasonPayloadMismatch          RejectReason = "payload_mismatch"
	ReasonBadSignature             RejectReason = "bad_signature"
	ReasonNotYetValid              RejectReason = "not_yet_valid"
	ReasonExpired                  RejectReason = "expired"
	ReasonBadWindow                RejectReason = "bad_window"
	ReasonWrongNode                RejectReason = "wrong_node"
	ReasonReplay                   RejectReason = "replay"
	ReasonTenantUnknown            RejectReason = "tenant_unknown"
	ReasonUnsupported              RejectReason = "unsupported"
	ReasonTypeNotAllowed           RejectReason = "type_not_allowed"
	ReasonRateLimited              RejectReason = "rate_limited"
	ReasonBadPayload               RejectReason = "bad_payload"
	ReasonUnsupportedReportVariant RejectReason = "unsupported_report_variant"
	ReasonScopeDenied              RejectReason = "scope_denied"
	ReasonUnavailable              RejectReason = "unavailable"
)

// Decision is the decision an ack carries (ack.decision). The hub treats a repeated ack as the same one when
// (command_id, decision, reason) match: see SameAck.
type Decision string

const (
	// DecisionAccepted: passed lines 0–9. FINAL too: recorded with the nonce and the command_id before the ack and
	// before any effect (the budget consumption is recorded with it).
	DecisionAccepted Decision = "accepted"
	// DecisionRejected: final (lines 3–9); see ReasonClass for which ones are recorded.
	DecisionRejected Decision = "rejected"
	// DecisionDeferred: retryable, never recorded (not_yet_valid, unavailable).
	DecisionDeferred Decision = "deferred"
)

// ReasonClass is the destination of a refused command (ADR-0011, the "Decisão" column and the three
// destinations below the table).
type ReasonClass int

const (
	// ClassUnauthenticated: lines 0–2. No ack bound to the command_id, nothing recorded, no audit line of its
	// own: the node only counts it (heartbeat unauthenticated_rejections, periodic "unauthenticated" lines).
	ClassUnauthenticated ReasonClass = iota + 1
	// ClassFinalNotRecorded: line 3 (bad_window, expired). Ack "rejected", final, but NOT recorded: it depends
	// only on the envelope and the verification clock, so a redelivery recomputes the same decision.
	ClassFinalNotRecorded
	// ClassFinalRecorded: lines 4–9. Ack "rejected", final, recorded with the nonce AND the command_id before
	// the ack; a redelivery gets the recorded ack (line 2a).
	ClassFinalRecorded
	// ClassDeferred: not_yet_valid, unavailable. Ack "deferred", retryable, never recorded: the hub may
	// redeliver the same envelope until not_after.
	ClassDeferred
)

// reasonRows is the ADR table "Verificação no nó": verification line ("—" = any line) and class of each reason.
var reasonRows = map[RejectReason]struct {
	line  string
	class ReasonClass
}{
	ReasonBadEnvelope:              {"0", ClassUnauthenticated},
	ReasonPayloadMismatch:          {"1", ClassUnauthenticated},
	ReasonBadSignature:             {"2", ClassUnauthenticated},
	ReasonBadWindow:                {"3", ClassFinalNotRecorded},
	ReasonNotYetValid:              {"3", ClassDeferred},
	ReasonExpired:                  {"3", ClassFinalNotRecorded},
	ReasonWrongNode:                {"4", ClassFinalRecorded},
	ReasonReplay:                   {"5", ClassFinalRecorded},
	ReasonTenantUnknown:            {"6", ClassFinalRecorded},
	ReasonUnsupported:              {"7", ClassFinalRecorded},
	ReasonTypeNotAllowed:           {"7", ClassFinalRecorded},
	ReasonRateLimited:              {"7", ClassFinalRecorded},
	ReasonBadPayload:               {"8", ClassFinalRecorded},
	ReasonUnsupportedReportVariant: {"8", ClassFinalRecorded},
	ReasonScopeDenied:              {"9", ClassFinalRecorded},
	ReasonUnavailable:              {"—", ClassDeferred},
}

// RejectReasons returns every reason in the schema's enum order.
func RejectReasons() []RejectReason {
	return []RejectReason{
		ReasonBadEnvelope, ReasonPayloadMismatch, ReasonBadSignature, ReasonNotYetValid, ReasonExpired,
		ReasonBadWindow, ReasonWrongNode, ReasonReplay, ReasonTenantUnknown, ReasonUnsupported,
		ReasonTypeNotAllowed, ReasonRateLimited, ReasonBadPayload, ReasonUnsupportedReportVariant,
		ReasonScopeDenied, ReasonUnavailable,
	}
}

// Valid reports whether r is a reason of the contract.
func (r RejectReason) Valid() bool { _, ok := reasonRows[r]; return ok }

// Line is the verification line of r in the ADR table ("0"…"9"; "—" for unavailable, which can happen at any
// line that needs a local dependency). "" for an unknown reason.
func (r RejectReason) Line() string { return reasonRows[r].line }

// Class is the destination of a command refused for r; 0 for an unknown reason.
func (r RejectReason) Class() ReasonClass { return reasonRows[r].class }

// Decision is the ack decision for r: rejected (final) or deferred. ok is false for the unauthenticated
// reasons (lines 0–2), which never produce an ack, and for an unknown reason.
func (r RejectReason) Decision() (d Decision, ok bool) {
	switch r.Class() {
	case ClassFinalRecorded, ClassFinalNotRecorded:
		return DecisionRejected, true
	case ClassDeferred:
		return DecisionDeferred, true
	}
	return "", false
}

// Recorded reports whether the node records a decision for r in its anti-replay store before the ack (with
// the nonce and the command_id): only the final reasons of lines 4–9.
func (r RejectReason) Recorded() bool { return r.Class() == ClassFinalRecorded }

// PolicyEvent reports whether a rejection for r also becomes the event command.rejected_by_policy: the
// authentic commands refused locally at lines 6–9 (fleet-event.schema.json#/$defs/data_command_rejected).
func (r RejectReason) PolicyEvent() bool {
	switch r.Line() {
	case "6", "7", "8", "9":
		return true
	}
	return false
}
