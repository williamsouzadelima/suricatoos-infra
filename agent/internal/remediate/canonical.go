package remediate

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strconv"
	"time"
)

// canonicalDomain MUST equal the control-plane's (control-plane/remediation/
// canonical.go). It namespaces the signature so a remediation signature can
// never be replayed as a feed/update one (those use their own prefixes).
const canonicalDomain = "suricatoos-remediation-v1"

// Canonical re-derives, byte-for-byte, the message the control-plane signed for a
// job. It MUST stay identical to control-plane/remediation/canonical.go: the
// field order, the length-prefixed framing ("key=<len>:<value>\n"), and the time
// formatting are the contract. A golden test (canonical_test.go) pins the exact
// bytes on BOTH sides so the two implementations can never drift.
//
// The length prefix (not a plain separator join) is what makes the framing
// unforgeable: the verifier knows exactly how many bytes each value is, so no
// attacker-chosen value — even one containing '\n' or ':' — can shift a field
// boundary.
func Canonical(j *Job) []byte {
	var b bytes.Buffer
	b.WriteString(canonicalDomain)
	b.WriteByte('\n')
	field(&b, "schema_version", j.SchemaVersion)
	field(&b, "job_id", j.JobID)
	field(&b, "correlation_id", j.CorrelationID)
	field(&b, "tenant", j.Tenant)
	field(&b, "agent_id", j.AgentID)
	field(&b, "type", string(j.Type))
	field(&b, "approved_by", j.ApprovedBy)
	field(&b, "issued_at", rfc3339(j.IssuedAt))
	field(&b, "not_before", rfc3339(j.NotBefore))
	field(&b, "not_after", rfc3339(j.NotAfter))
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

// rfc3339 renders a time as UTC RFC3339 seconds (or "" for the zero time), so the
// string round-trips byte-identically on both sides.
func rfc3339(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// computePayloadSHA256 is the hex SHA-256 of the payload; it MUST match the job's
// payload_sha256, or the signature does not cover the bytes the agent holds.
func computePayloadSHA256(payload []byte) string {
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

// Verify checks a job's Ed25519 signature against pub AND that the stored
// payload_sha256 matches the payload bytes (so a valid signature cannot be paired
// with a swapped payload). It is time-INDEPENDENT; a caller about to act on a job
// MUST use VerifyAt instead.
func Verify(j *Job, pub ed25519.PublicKey) bool {
	if j.Signature == "" {
		return false
	}
	if computePayloadSHA256(j.Payload) != j.PayloadSHA256 {
		return false
	}
	sig, err := base64.StdEncoding.DecodeString(j.Signature)
	if err != nil {
		return false
	}
	return ed25519.Verify(pub, Canonical(j), sig)
}

// VerifyAt is Verify plus a freshness window: the job must fall within
// [issued_at - skew, expires_at + skew]. The signature itself is valid regardless
// of time, so without this a captured-but-expired job could be replayed; the
// agent MUST call VerifyAt (not bare Verify) before acting. skew absorbs clock
// drift between the cloud and the endpoint.
func VerifyAt(j *Job, pub ed25519.PublicKey, now time.Time, skew time.Duration) bool {
	if !Verify(j, pub) {
		return false
	}
	if !j.IssuedAt.IsZero() && now.Before(j.IssuedAt.Add(-skew)) {
		return false
	}
	if !j.ExpiresAt.IsZero() && now.After(j.ExpiresAt.Add(skew)) {
		return false
	}
	return true
}
