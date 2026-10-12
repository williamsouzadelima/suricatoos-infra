package contract

import (
	"crypto/ed25519"
	"fmt"
	"time"
)

// GoldenFormat tags the golden vectors file, testdata/golden-v1.json (ADR-0011 "Golden vectors").
const GoldenFormat = "suricatoos-fleet-golden/1"

// The non-reason outcomes of a vector.
const (
	OutcomeAccept     = "accept"     // passes every check the contract alone can decide (see GoldenVector.Outcome)
	OutcomeRedelivery = "redelivery" // line 2a: the canonical form is already recorded (in Seen)
)

// GoldenFile is the golden vectors file. The node's tests and the hub's (commandcenter, which consumes the same
// file pinned by sha256) must pass every vector before either talks to a real node.
type GoldenFile struct {
	Format      string         `json:"format"`
	Domain      string         `json:"domain"`
	SkewSeconds int            `json:"skew_seconds"`
	TestKey     GoldenKey      `json:"test_key"`
	Vectors     []GoldenVector `json:"vectors"`
}

// GoldenKey describes the PUBLIC golden test key (GoldenTestKeySeedText).
type GoldenKey struct {
	SeedDerivation string `json:"seed_derivation"`
	PublicKeyPEM   string `json:"public_key_pem"`
	Pin            string `json:"pin"`
}

// GoldenVector is one vector. CommandJSON holds the exact envelope bytes as a hub would send them; Canonical is
// the exact message its signature was made over (for a vector whose defect is a field altered after signing,
// that is the form BEFORE the change); PayloadSHA256 is the sha256 of the raw payload bytes inside CommandJSON;
// Seen lists the canonical-form sha256 already recorded under the same nonce or command_id (lines 2a and 5);
// Expect is OutcomeAccept, OutcomeRedelivery or a reject_reason.
type GoldenVector struct {
	Name            string   `json:"name"`
	OwnNodeID       string   `json:"own_node_id"`
	VerifyAt        string   `json:"verify_at"`
	CommandJSON     string   `json:"command_json"`
	Canonical       string   `json:"canonical"`
	CanonicalSHA256 string   `json:"canonical_sha256"`
	PayloadSHA256   string   `json:"payload_sha256"`
	Seen            []string `json:"seen,omitzero"`
	Expect          string   `json:"expect"`
}

// ParseGoldenFile decodes a golden vectors file strictly.
func ParseGoldenFile(b []byte) (*GoldenFile, error) {
	var f GoldenFile
	if err := DecodeStrict(b, &f); err != nil {
		return nil, err
	}
	if f.Format != GoldenFormat {
		return nil, fmt.Errorf("contract: formato de golden %q, esperado %q", f.Format, GoldenFormat)
	}
	return &f, nil
}

// Outcome is the vector runner that ADR-0011 makes normative ("Golden vectors", procedure item 5; a hub that is
// not Go implements the same one to reach the same expect). It runs the vector through the node's verification in
// the ADR's order, as far as the contract alone can decide it: Verify (lines 0–2), the redelivery shortcut (2a)
// against Seen, CheckAt (3–4) at VerifyAt for OwnNodeID, replay (5) against Seen, then the contract part of lines
// 7–8: a type outside the closed v1 catalog is unsupported and a payload invalid for its type (ValidatePayload,
// semantic rules included) is bad_payload. The checks that need local state are taken as passed — the tenant (6),
// the node_kind, policy and budget of line 7, the report_formats capability of line 8 and the scope gate (9).
// It returns OutcomeAccept, OutcomeRedelivery or the reject_reason; an error only for a malformed vector.
func (v *GoldenVector) Outcome(pub ed25519.PublicKey, skew time.Duration) (string, error) {
	t, err := ParseUTCTime(v.VerifyAt)
	if err != nil {
		return "", fmt.Errorf("verify_at: %w", err)
	}
	ver, err := Verify(pub, []byte(v.CommandJSON))
	if err != nil {
		if r, ok := ReasonOf(err); ok {
			return string(r), nil
		}
		return "", err
	}
	if ClassifyReplay(ver.CanonicalSHA256(), v.Seen) == ReplayRedelivery {
		return OutcomeRedelivery, nil
	}
	if err := ver.CheckAt(t, v.OwnNodeID, skew); err != nil {
		if r, ok := ReasonOf(err); ok {
			return string(r), nil
		}
		return "", err
	}
	if ClassifyReplay(ver.CanonicalSHA256(), v.Seen) == ReplayConflict {
		return string(ReasonReplay), nil
	}
	cmd := ver.Command()
	if _, ok := LookupType(cmd.Type); !ok {
		return string(ReasonUnsupported), nil
	}
	if err := ValidatePayload(cmd.Type, cmd.Payload); err != nil {
		return string(ReasonBadPayload), nil
	}
	return OutcomeAccept, nil
}

// Check runs the whole file: the test key is the documented public golden key with its pin, every vector's
// canonical_sha256 is the sha256 of its canonical, every authenticated envelope yields exactly that canonical
// form and payload hash, and every vector's Outcome is its Expect. nil means the implementation conforms.
func (f *GoldenFile) Check() []error {
	var errs []error
	if f.Domain != Domain {
		errs = append(errs, fmt.Errorf("domain %q, esperado %q", f.Domain, Domain))
	}
	pub, err := ParsePublicKeyPEM([]byte(f.TestKey.PublicKeyPEM))
	if err != nil {
		return append(errs, fmt.Errorf("test_key: %w", err))
	}
	if !IsGoldenTestKey(pub) {
		errs = append(errs, fmt.Errorf("test_key não é a chave de teste pública do ADR-0011"))
	}
	if pin, _ := KeyPin(pub); pin != f.TestKey.Pin {
		errs = append(errs, fmt.Errorf("test_key.pin %s, esperado %s", f.TestKey.Pin, pin))
	}
	skew := time.Duration(f.SkewSeconds) * time.Second
	for i := range f.Vectors {
		v := &f.Vectors[i]
		if payloadDigest([]byte(v.Canonical)) != v.CanonicalSHA256 {
			errs = append(errs, fmt.Errorf("%s: canonical_sha256 não é o sha256 de canonical", v.Name))
		}
		if ver, err := Verify(pub, []byte(v.CommandJSON)); err == nil {
			if string(ver.Canonical()) != v.Canonical || ver.Command().PayloadSHA256 != v.PayloadSHA256 {
				errs = append(errs, fmt.Errorf("%s: forma canônica ou payload_sha256 diferem do envelope", v.Name))
			}
		}
		got, err := v.Outcome(pub, skew)
		switch {
		case err != nil:
			errs = append(errs, fmt.Errorf("%s: %w", v.Name, err))
		case got != v.Expect:
			errs = append(errs, fmt.Errorf("%s: resultado %s, esperado %s", v.Name, got, v.Expect))
		}
	}
	return errs
}
