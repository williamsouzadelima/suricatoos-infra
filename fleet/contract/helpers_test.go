package contract

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

// The ADR-0011 worked example ("Exemplo verificável"), verbatim; TestADRWorkedExampleText re-reads it from
// the ADR file so these constants can never drift from the document.
const (
	adrEnvelope  = `{"schema_version":"1.0.0","command_id":"6f1c2a9e-3b7d-4c8a-9e21-5d4f0a7b3c18","node_id":"node-lab-0001","tenant":"acme","type":"task.start","issued_by":"op-7f3a","issued_at":"2026-10-11T12:00:00Z","not_after":"2026-10-11T13:00:00Z","nonce":"750113b701a52bd32b0fdca1342ddd2d74add6f219ddacef4cede043dfadca02","payload_sha256":"202e584626515573d531f5508c9094f8d6b705e0fc0fe6fbf29c76969fef313f","payload":{"task_id":"2d5b8f0e-1c4a-4e6b-9a3d-7f0c5e1b2a49"},"signature":"6XVZpdCuyN9EZ86zy0kVdNqmfLDrI4QVrPmDs6vv5wdW4HLdEBz2xRI5qSvwmNvmY/eRQ4E3xUdocjIDOyWGCw=="}`
	adrCanonical = "suricatoos-fleet-command-v1\n" +
		"schema_version=5:1.0.0\n" +
		"command_id=36:6f1c2a9e-3b7d-4c8a-9e21-5d4f0a7b3c18\n" +
		"node_id=13:node-lab-0001\n" +
		"tenant=4:acme\n" +
		"type=10:task.start\n" +
		"issued_by=7:op-7f3a\n" +
		"issued_at=20:2026-10-11T12:00:00Z\n" +
		"not_after=20:2026-10-11T13:00:00Z\n" +
		"nonce=64:750113b701a52bd32b0fdca1342ddd2d74add6f219ddacef4cede043dfadca02\n" +
		"payload_sha256=64:202e584626515573d531f5508c9094f8d6b705e0fc0fe6fbf29c76969fef313f\n"
	adrCanonicalSHA256 = "a9a4d1759628b5708691988ce1512e3cbfa6881f90dfc0000d3fea08edcb7d74"
	adrPayload         = `{"task_id":"2d5b8f0e-1c4a-4e6b-9a3d-7f0c5e1b2a49"}`
	adrPayloadBytes    = 50
	adrSignature       = "6XVZpdCuyN9EZ86zy0kVdNqmfLDrI4QVrPmDs6vv5wdW4HLdEBz2xRI5qSvwmNvmY/eRQ4E3xUdocjIDOyWGCw=="
	adrPublicKeySPKI   = "MCowBQYDK2VwAyEAB9q67lsE3i3PULOubuP+pQXTCUwAye7O14Zsa5+EqWw="
	adrPin             = "sha256:a35dc29cebfbe26dff2e840afc6550f291e734caba174011c56b7a8de353b6b1"
)

func keyFromSeedText(text string) ed25519.PrivateKey {
	seed := sha256.Sum256([]byte(text))
	return ed25519.NewKeyFromSeed(seed[:])
}

var (
	// goldenPriv is the PUBLIC golden test key of ADR-0011 (never a production key).
	goldenPriv = keyFromSeedText("suricatoos-fleet-command-v1/golden-test-key")
	goldenPub  = goldenPriv.Public().(ed25519.PublicKey)
	// otherPriv signs the "other key" vectors.
	otherPriv = keyFromSeedText("suricatoos-fleet-command-v1/golden-other-key")
)

func sha256hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func utc(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return t
}

// adrCommand returns the signed fields of the ADR worked example.
func adrCommand() Command {
	return Command{
		SchemaVersion: "1.0.0",
		CommandID:     "6f1c2a9e-3b7d-4c8a-9e21-5d4f0a7b3c18",
		NodeID:        "node-lab-0001",
		Tenant:        "acme",
		Type:          TypeTaskStart,
		IssuedBy:      "op-7f3a",
		IssuedAt:      "2026-10-11T12:00:00Z",
		NotAfter:      "2026-10-11T13:00:00Z",
		Nonce:         "750113b701a52bd32b0fdca1342ddd2d74add6f219ddacef4cede043dfadca02",
		PayloadSHA256: "202e584626515573d531f5508c9094f8d6b705e0fc0fe6fbf29c76969fef313f",
	}
}

// envelopeFor signs c with priv (fleet domain), with payload_sha256 over the exact payload bytes, and returns
// the envelope bytes in the ADR member order. Unchecked: it also builds envelopes that line 0 refuses.
func envelopeFor(priv ed25519.PrivateKey, c Command, payload string) []byte {
	c.Payload = json.RawMessage(payload)
	c.PayloadSHA256 = sha256hex([]byte(payload))
	c.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, Canonical(&c)))
	return appendEnvelope(nil, &c)
}

// replaceOnce replaces exactly one occurrence of old in s (test mutations must hit what they mean to).
func replaceOnce(t *testing.T, s, old, new string) string {
	t.Helper()
	if strings.Count(s, old) != 1 {
		t.Fatalf("mutação ambígua: %q aparece %d vezes", old, strings.Count(s, old))
	}
	return strings.Replace(s, old, new, 1)
}

// rejectOf returns the reject reason and line-0 violation of a Verify/VerifyAt error.
func rejectOf(t *testing.T, err error) (RejectReason, *Violation) {
	t.Helper()
	if err == nil {
		return "", nil
	}
	var re *RejectError
	if !errors.As(err, &re) {
		t.Fatalf("erro não é *RejectError: %T %v", err, err)
	}
	return re.Reason, re.Violation
}
