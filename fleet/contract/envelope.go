package contract

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
)

// strictBase64 is the standard base64 alphabet with padding that refuses non-zero padding bits: one signature,
// one encoding.
var strictBase64 = base64.StdEncoding.Strict()

// appendEnvelope appends the JSON of c with the members in the order of the ADR-0011 worked example, the
// payload bytes VERBATIM and no HTML escaping. It is assembled by hand, not with encoding/json: when
// encoding/json runs on the json/v2 core (GOEXPERIMENT=jsonv2 — in the baseline of go1.27, not of go1.25) the
// encoder rewrites U+2028/U+2029 even inside a json.RawMessage, so the bytes the payload hash covers would
// depend on the Go toolchain.
func appendEnvelope(dst []byte, c *Command) []byte {
	member := func(name, value string, first bool) {
		if !first {
			dst = append(dst, ',')
		}
		dst = appendJSONString(dst, name, false)
		dst = append(dst, ':')
		dst = appendJSONString(dst, value, false)
	}
	dst = append(dst, '{')
	member("schema_version", c.SchemaVersion, true)
	member("command_id", c.CommandID, false)
	member("node_id", c.NodeID, false)
	member("tenant", c.Tenant, false)
	member("type", string(c.Type), false)
	member("issued_by", c.IssuedBy, false)
	member("issued_at", c.IssuedAt, false)
	member("not_after", c.NotAfter, false)
	member("nonce", c.Nonce, false)
	member("payload_sha256", c.PayloadSHA256, false)
	dst = append(dst, `,"payload":`...)
	dst = append(dst, c.Payload...)
	member("signature", c.Signature, false)
	return append(dst, '}')
}

func payloadDigest(payload []byte) string {
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

func decodeSignature(s string) ([]byte, error) {
	sig, err := strictBase64.DecodeString(s)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return nil, errors.New("assinatura não é o base64 padrão de 64 bytes")
	}
	return sig, nil
}

// parseEnvelope is verification line 0 (ADR-0011): the raw envelope within 64 KiB; strict JSON (UTF-8, one
// value, no duplicate member at any level, case-exact names, no unknown or missing member, no null, every
// number an integer literal); the payload an object within 48 KiB; every member in its exact form
// ($defs/envelope: schema_version 1.0.0, lowercase UUID, utc_time of a real instant, lowercase 64-hex nonce, a
// type matching command_type_any, the node_id/tenant/issued_by patterns, no control character nor U+FFFE/U+FFFF)
// and a signature in CANONICAL standard base64 (the schema's pattern pins it), decoded to exactly 64 bytes. A type
// outside the catalog is NOT refused here (it is unsupported, line 7).
func parseEnvelope(raw []byte) (*Command, *Violation) {
	if len(raw) > MaxEnvelopeBytes {
		return nil, &Violation{Keyword: "size", Detail: fmt.Sprintf("envelope com mais de %d bytes", MaxEnvelopeBytes)}
	}
	var c Command
	if viol := decodeStrict(raw, &c, scanOptions{integersOnly: true}); viol != nil {
		return nil, viol
	}
	if len(c.Payload) > MaxPayloadBytes {
		return nil, &Violation{Keyword: "size", Path: "/payload", Detail: fmt.Sprintf("payload com mais de %d bytes", MaxPayloadBytes)}
	}
	if viol := envelopeSpec.validate(reflect.ValueOf(&c).Elem(), ""); viol != nil {
		return nil, viol
	}
	if _, err := decodeSignature(c.Signature); err != nil {
		return nil, &Violation{Keyword: "base64", Path: "/signature", Detail: err.Error()}
	}
	return &c, nil
}

// windowOK is the line-3 window rule issued_at < not_after <= issued_at + 24h.
func windowOK(c *Command) bool {
	issuedAt, err1 := ParseUTCTime(c.IssuedAt)
	notAfter, err2 := ParseUTCTime(c.NotAfter)
	return err1 == nil && err2 == nil && issuedAt.Before(notAfter) && !notAfter.After(issuedAt.Add(MaxWindow))
}

// Sign is the hub side: it builds the envelope a node accepts. cmd carries the ten signed fields except
// payload_sha256 (Payload, PayloadSHA256 and Signature of cmd are ignored and recomputed). payload must be ONE
// compact JSON object (no insignificant whitespace; build it with MarshalCompact), at most 48 KiB, under the same
// strict rules as line 0. Sign hashes exactly those bytes, signs the canonical form with priv (Ed25519, domain
// suricatoos-fleet-command-v1) and returns the serialized envelope in the ADR's member order with the payload
// verbatim.
//
// It is fail-closed: it refuses to emit an envelope that would not pass verification line 0, or whose window
// would be bad_window (line 3). It does not check the catalog nor the payload against its type: validate it
// with ValidatePayload first.
func Sign(priv ed25519.PrivateKey, cmd Command, payload []byte) ([]byte, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, errors.New("contract: chave privada Ed25519 inválida")
	}
	if viol := scanJSON(payload, scanOptions{integersOnly: true}); viol != nil {
		return nil, fmt.Errorf("contract: payload: %w", viol)
	}
	if len(payload) == 0 || payload[0] != '{' || !isCompactJSON(payload) {
		return nil, errors.New("contract: o payload precisa ser um objeto JSON compacto (sem espaço insignificante)")
	}
	if len(payload) > MaxPayloadBytes {
		return nil, fmt.Errorf("contract: payload com mais de %d bytes", MaxPayloadBytes)
	}
	cmd.Payload = append([]byte(nil), payload...)
	cmd.PayloadSHA256 = payloadDigest(payload)
	cmd.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, Canonical(&cmd)))
	raw := appendEnvelope(nil, &cmd)
	if _, viol := parseEnvelope(raw); viol != nil {
		return nil, fmt.Errorf("contract: o envelope seria recusado na linha 0: %w", viol)
	}
	if !windowOK(&cmd) {
		return nil, errors.New("contract: janela inválida (exige issued_at < not_after <= issued_at + 24h)")
	}
	return raw, nil
}
