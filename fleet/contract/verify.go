package contract

import (
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
)

// RejectError is a refusal of the verification lines of ADR-0011, with the exact reject_reason. Reason.Class()
// says its destination: for lines 0–2 there is no ack (count only); for lines 3–4 the caller acks the
// returned *Verified with Reason.Decision().
type RejectError struct {
	Reason    RejectReason
	Violation *Violation // line 0 (bad_envelope): the keyword and JSON pointer of the defect
	Detail    string     // short and connector-generated; never raw input
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
// nonce and command_id inside Command) and the exact payload bytes for line 8. It never aliases the input.
type Verified struct {
	Command         Command
	Signature       []byte // the 64 decoded signature bytes
	Canonical       []byte
	CanonicalSHA256 string // lowercase hex
	IssuedAt        time.Time
	NotAfter        time.Time
}

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
		Command:         *c,
		Signature:       sig,
		Canonical:       canonical,
		CanonicalSHA256: hex.EncodeToString(sum[:]),
		IssuedAt:        issuedAt,
		NotAfter:        notAfter,
	}, nil
}

// CheckAt runs verification lines 3–4 on an authenticated envelope, in the ADR's order:
//
//	3  issued_at < not_after <= issued_at + 24h                                     -> bad_window (final, not recorded)
//	3  t >= issued_at - skew                                                        -> not_yet_valid (deferred)
//	3  t <= not_after + skew                                                        -> expired (final, not recorded)
//	4  node_id == ownNodeID (the CN of the node's own fleet certificate)            -> wrong_node (final, recorded)
//
// t is the node's verification clock (max(now, persisted watermark): the connector's job, F2.4) and skew the
// FLEET_CLOCK_SKEW, in [0, 10 min]. Line 2a (a redelivery of a recorded canonical form) comes BEFORE this call
// and line 5 (replay) after it: see ClassifyReplay.
func (v *Verified) CheckAt(t time.Time, ownNodeID string, skew time.Duration) error {
	if skew < 0 || skew > MaxClockSkew {
		return ErrInvalidSkew
	}
	if !v.IssuedAt.Before(v.NotAfter) || v.NotAfter.After(v.IssuedAt.Add(MaxWindow)) {
		return &RejectError{Reason: ReasonBadWindow, Detail: "janela exige issued_at < not_after <= issued_at + 24h"}
	}
	if t.Before(v.IssuedAt.Add(-skew)) {
		return &RejectError{Reason: ReasonNotYetValid, Detail: "relógio de verificação antes de issued_at - skew"}
	}
	if t.After(v.NotAfter.Add(skew)) {
		return &RejectError{Reason: ReasonExpired, Detail: "relógio de verificação depois de not_after + skew"}
	}
	if v.Command.NodeID != ownNodeID {
		return &RejectError{Reason: ReasonWrongNode, Detail: "node_id do envelope não é este nó"}
	}
	return nil
}

// VerifyAt runs verification lines 0–4 (Verify, then CheckAt). On a refusal at lines 3–4 it returns the
// *Verified too: the envelope is authentic and the refusal gets an ack. On lines 0–2 the *Verified is nil.
func VerifyAt(pub ed25519.PublicKey, raw []byte, t time.Time, ownNodeID string, skew time.Duration) (*Verified, error) {
	if skew < 0 || skew > MaxClockSkew {
		return nil, ErrInvalidSkew
	}
	v, err := Verify(pub, raw)
	if err != nil {
		return nil, err
	}
	if err := v.CheckAt(t, ownNodeID, skew); err != nil {
		return v, err
	}
	return v, nil
}
