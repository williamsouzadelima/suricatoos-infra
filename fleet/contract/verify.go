package contract

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"
)

var (
	// ErrInvalidPublicKey: the pinned command key is not an Ed25519 public key (local configuration error).
	ErrInvalidPublicKey = errors.New("contract: chave pública Ed25519 inválida")
	// ErrInvalidSkew: the clock skew is outside [0, MaxClockSkew] (FLEET_CLOCK_SKEW; the connector does not
	// start with it).
	ErrInvalidSkew = errors.New("contract: skew fora de [0, 10m] (FLEET_CLOCK_SKEW)")
	// ErrNotVerified: CheckAt was called on a *Verified that Verify did not produce (a programming error: the
	// signature was never checked).
	ErrNotVerified = errors.New("contract: Verified não produzido por Verify")
)

// RejectError is a refusal of the verification lines of ADR-0011, with the exact reject_reason. Reason.Class()
// says its destination. For lines 0–2 Envelope is nil: the envelope is not authenticated, so there is no ack
// (count only). For lines 3–4 Envelope is the authenticated envelope: ack its Command().CommandID with
// Reason.Decision().
type RejectError struct {
	Reason    RejectReason
	Violation *Violation // line 0 (bad_envelope): the keyword and JSON pointer of the defect
	Detail    string     // short and connector-generated; never raw input
	Envelope  *Verified  // the authenticated envelope of a refusal at lines 3–4; nil for lines 0–2
}

func (e *RejectError) Error() string {
	if e.Violation != nil {
		return "fleet: " + string(e.Reason) + ": " + e.Violation.Error()
	}
	return "fleet: " + string(e.Reason) + ": " + e.Detail
}

func (e *RejectError) Unwrap() error {
	if e.Violation == nil {
		return nil
	}
	return e.Violation
}

// ReasonOf returns the reject_reason carried by err, if it is (or wraps) a *RejectError.
func ReasonOf(err error) (RejectReason, bool) {
	var re *RejectError
	if errors.As(err, &re) {
		return re.Reason, true
	}
	return "", false
}

// Verified is an envelope that passed verification lines 0–2: authentic, under the pinned key. It carries what
// the anti-replay store needs for lines 2a and 5 (the canonical form and its sha256 — the store key — plus the
// nonce and command_id inside Command()) and the exact payload bytes for line 8. It never aliases the input.
//
// Its content is read-only and is exactly what Verify authenticated: every field is unexported and every
// accessor returns a copy, so neither the holder nor a copy of the value (w := *v) can change what CheckAt checks
// (node_id, issued_at, not_after) or what the store keys on. Only Verify builds one; the zero value — all that
// another package can build — is refused by CheckAt (ErrNotVerified).
type Verified struct {
	cmd             Command
	signature       []byte // the 64 decoded signature bytes
	canonical       []byte
	canonicalSHA256 string // lowercase hex
	issuedAt        time.Time
	notAfter        time.Time
	sealed          bool // set by Verify only
}

// Command returns a copy of the authenticated envelope (Payload included: the raw bytes as received).
func (v *Verified) Command() Command {
	c := v.cmd
	c.Payload = bytes.Clone(v.cmd.Payload)
	return c
}

// Signature returns a copy of the 64 decoded signature bytes.
func (v *Verified) Signature() []byte { return bytes.Clone(v.signature) }

// Canonical returns a copy of the canonical form the signature was verified over.
func (v *Verified) Canonical() []byte { return bytes.Clone(v.canonical) }

// CanonicalSHA256 returns the lowercase hex sha256 of the canonical form: the anti-replay store key.
func (v *Verified) CanonicalSHA256() string { return v.canonicalSHA256 }

// IssuedAt returns the authenticated issued_at.
func (v *Verified) IssuedAt() time.Time { return v.issuedAt }

// NotAfter returns the authenticated not_after.
func (v *Verified) NotAfter() time.Time { return v.notAfter }

// Verify runs verification lines 0–2 of ADR-0011 in order, stopping at the first failure:
//
//	0  the envelope's form (parseEnvelope)                                         -> bad_envelope
//	1  sha256(raw bytes of payload, as received) == payload_sha256                  -> payload_mismatch
//	2  Ed25519 over the canonical form, with pub = the PINNED command key           -> bad_signature
//
// A refusal returns a *RejectError and no *Verified: an unauthenticated envelope gets no ack and is only
// counted. pub must be an Ed25519 public key (else ErrInvalidPublicKey, a configuration error).
func Verify(pub ed25519.PublicKey, raw []byte) (*Verified, error) {
	if len(pub) != ed25519.PublicKeySize {
		return nil, ErrInvalidPublicKey
	}
	c, viol := parseEnvelope(raw)
	if viol != nil {
		return nil, &RejectError{Reason: ReasonBadEnvelope, Violation: viol}
	}
	if payloadDigest(c.Payload) != c.PayloadSHA256 {
		return nil, &RejectError{Reason: ReasonPayloadMismatch, Detail: "sha256 dos bytes crus do payload difere de payload_sha256"}
	}
	canonical := Canonical(c)
	sig, _ := decodeSignature(c.Signature) // checked at line 0
	if !ed25519.Verify(pub, canonical, sig) {
		return nil, &RejectError{Reason: ReasonBadSignature, Detail: "assinatura Ed25519 não confere com a chave de comando pinada"}
	}
	issuedAt, _ := ParseUTCTime(c.IssuedAt) // checked at line 0
	notAfter, _ := ParseUTCTime(c.NotAfter)
	sum := sha256.Sum256(canonical)
	return &Verified{
		cmd:             *c,
		signature:       sig,
		canonical:       canonical,
		canonicalSHA256: hex.EncodeToString(sum[:]),
		issuedAt:        issuedAt,
		notAfter:        notAfter,
		sealed:          true,
	}, nil
}

// CheckAt runs verification lines 3–4 on an envelope Verify authenticated, in the ADR's order:
//
//	3  issued_at < not_after <= issued_at + 24h                                     -> bad_window (final, not recorded)
//	3  t >= issued_at - skew                                                        -> not_yet_valid (deferred)
//	3  t <= not_after + skew                                                        -> expired (final, not recorded)
//	4  node_id == ownNodeID (the CN of the node's own fleet certificate)            -> wrong_node (final, recorded)
//
// t is the node's verification clock (max(now, persisted watermark): the connector's job, F2.4) and skew the
// FLEET_CLOCK_SKEW, in [0, 10 min]. node_id and the window come only from what Verify authenticated (see
// Verified). A refusal is a *RejectError whose Envelope is v (it gets an ack). Line 2a (a redelivery of a
// recorded canonical form) comes BEFORE this call and line 5 (replay) after it: see VerifyAt.
func (v *Verified) CheckAt(t time.Time, ownNodeID string, skew time.Duration) error {
	if v == nil || !v.sealed {
		return ErrNotVerified
	}
	if skew < 0 || skew > MaxClockSkew {
		return ErrInvalidSkew
	}
	reject := func(r RejectReason, detail string) error {
		return &RejectError{Reason: r, Detail: detail, Envelope: v}
	}
	if !v.issuedAt.Before(v.notAfter) || v.notAfter.After(v.issuedAt.Add(MaxWindow)) {
		return reject(ReasonBadWindow, "janela exige issued_at < not_after <= issued_at + 24h")
	}
	if t.Before(v.issuedAt.Add(-skew)) {
		return reject(ReasonNotYetValid, "relógio de verificação antes de issued_at - skew")
	}
	if t.After(v.notAfter.Add(skew)) {
		return reject(ReasonExpired, "relógio de verificação depois de not_after + skew")
	}
	if v.cmd.NodeID != ownNodeID {
		return reject(ReasonWrongNode, "node_id do envelope não é este nó")
	}
	return nil
}

// VerifyAt runs verification lines 0–4 (Verify, then CheckAt) for a caller WITHOUT an anti-replay store (tests,
// the hub's self-check): it skips line 2a and line 5. It returns a *Verified only when everything passed; on any
// refusal the *Verified is nil and, for lines 3–4, the authenticated envelope is in the RejectError's Envelope
// (to ack it).
//
// A store-backed connector must NOT use VerifyAt. Its sequence is:
//
//	v, err := Verify(pub, raw)                                  // lines 0–2; err: only count it, no ack
//	ClassifyReplay(v.CanonicalSHA256(), recorded) == ReplayRedelivery
//	                                                            // line 2a: resend the recorded ack/result, stop
//	err = v.CheckAt(t, ownNodeID, skew)                         // lines 3–4; err: ack it (Reason.Decision())
//	ClassifyReplay(v.CanonicalSHA256(), recorded) == ReplayConflict
//	                                                            // line 5: replay (final, recorded)
//	                                                            // then lines 6–9: tenant, catalog/policy/budget,
//	                                                            // DecodePayload, scope
//
// recorded = the canonical-form sha256 of every store entry under v's nonce or command_id.
func VerifyAt(pub ed25519.PublicKey, raw []byte, t time.Time, ownNodeID string, skew time.Duration) (*Verified, error) {
	if skew < 0 || skew > MaxClockSkew {
		return nil, ErrInvalidSkew
	}
	v, err := Verify(pub, raw)
	if err != nil {
		return nil, err
	}
	if err := v.CheckAt(t, ownNodeID, skew); err != nil {
		return nil, err
	}
	return v, nil
}
