package remediation

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strconv"
	"time"
)

// canonicalDomain prefixes every signed message so a signature for one purpose
// can never be replayed as another (feed/update use their own prefixes).
const canonicalDomain = "suricatoos-remediation-v1"

// Canonical returns the exact bytes signed for a job. It binds the job to ONE
// agent + tenant + type, a single-use nonce, an issue time and an expiry, and
// the payload (by SHA-256). Changing ANY of these changes the bytes, so a
// signature cannot be transplanted to another host, replayed, or applied to a
// different payload.
//
// Framing is LENGTH-PREFIXED ("key=<len>:<value>\n"), not a plain separator
// join: the update/feed canonicals use "\t"/"\n" joins that do not escape field
// contents, so a value containing the separator could be ambiguous. Here the
// length tells the verifier exactly how many bytes each value is, so no value —
// including an attacker-chosen one — can forge the framing.
//
// The agent re-derives these bytes independently; a golden test pins them so the
// two implementations can never drift (same discipline as update.Canonical).
func Canonical(j *RemediationJob) []byte {
	var b bytes.Buffer
	b.WriteString(canonicalDomain)
	b.WriteByte('\n')
	field(&b, "job_id", j.JobID)
	field(&b, "agent_id", j.AgentID)
	field(&b, "tenant", j.Tenant)
	field(&b, "type", string(j.Type))
	field(&b, "issued_at", rfc3339(j.IssuedAt))
	field(&b, "expires_at", rfc3339(j.ExpiresAt))
	field(&b, "nonce", j.Nonce)
	field(&b, "payload_sha256", j.PayloadSHA256)
	return b.Bytes()
}

func field(b *bytes.Buffer, key, val string) {
	b.WriteString(key)
	b.WriteByte('=')
	b.WriteString(strconv.Itoa(len(val)))
	b.WriteByte(':')
	b.WriteString(val)
	b.WriteByte('\n')
}

// rfc3339 renders a time as UTC RFC3339 seconds (stable, second-resolution), or
// "" for the zero time, so the string round-trips byte-identically on both sides.
func rfc3339(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// ComputePayloadSHA256 is the hex SHA-256 of a payload, stored in the job and
// folded into the canonical so the signature also covers the payload bytes.
func ComputePayloadSHA256(payload []byte) string {
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

// Signer signs the canonical bytes (satisfied by signkeys.Key).
type Signer interface{ Sign(msg []byte) []byte }

// Sign returns the base64 Ed25519 signature of the job's canonical form.
func Sign(j *RemediationJob, s Signer) string {
	return base64.StdEncoding.EncodeToString(s.Sign(Canonical(j)))
}

// Verify checks a job's signature against pub. It also re-checks that the stored
// payload_sha256 matches the actual payload, so a signature cannot be paired
// with a swapped payload.
func Verify(j *RemediationJob, pub ed25519.PublicKey) bool {
	if j.Signature == "" {
		return false
	}
	if ComputePayloadSHA256(j.Payload) != j.PayloadSHA256 {
		return false
	}
	sig, err := base64.StdEncoding.DecodeString(j.Signature)
	if err != nil {
		return false
	}
	return ed25519.Verify(pub, Canonical(j), sig)
}
