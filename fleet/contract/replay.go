package contract

import "slices"

// ReplayClass is the answer of the anti-replay store about one authenticated envelope (ADR-0011 "Anti-replay,
// idempotência e entrega").
type ReplayClass int

const (
	// ReplayFresh: nothing recorded under this nonce or command_id — continue with lines 3–9.
	ReplayFresh ReplayClass = iota
	// ReplayRedelivery: this exact canonical form is recorded (as a decision, or as a recorded replay) — line 2a,
	// consulted right after authentication and BEFORE the window: resend the recorded ack (and result), never
	// re-evaluate lines 3–9 nor execute again; count it in redeliveries.
	ReplayRedelivery
	// ReplayConflict: another canonical form is recorded under the same nonce or command_id — line 5, after lines
	// 3–4 passed: reject as replay (final, recorded by its own canonical form).
	ReplayConflict
)

func (c ReplayClass) String() string {
	switch c {
	case ReplayFresh:
		return "fresh"
	case ReplayRedelivery:
		return "redelivery"
	case ReplayConflict:
		return string(ReasonReplay)
	}
	return "?"
}

// ClassifyReplay is the PURE rule of lines 2a and 5, which the persisted store (F2.4) reuses: canonicalSHA256 is
// Verified.CanonicalSHA256() of the envelope being verified and recorded holds the canonical-form sha256 of every
// entry the store has under the same nonce OR the same command_id (the canonical form includes both, so an entry
// with the very same form is always among them). The comparison is exact.
//
// The store's order is: Verify (0–2) → ClassifyReplay == ReplayRedelivery? (2a) → CheckAt (3–4) →
// ClassifyReplay == ReplayConflict? (5) → lines 6–9 (connector).
func ClassifyReplay(canonicalSHA256 string, recorded []string) ReplayClass {
	switch {
	case slices.Contains(recorded, canonicalSHA256):
		return ReplayRedelivery
	case len(recorded) > 0:
		return ReplayConflict
	}
	return ReplayFresh
}
