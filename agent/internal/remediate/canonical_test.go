package remediate

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"
)

func goldenJob() *Job {
	return &Job{
		JobID:         "j1",
		AgentID:       "win-abc",
		Tenant:        "acme",
		Type:          TypePackagePatch,
		IssuedAt:      time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC),
		ExpiresAt:     time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC),
		Nonce:         "n1",
		PayloadSHA256: "abc",
	}
}

// TestCanonicalGolden pins the EXACT signed bytes. This string MUST be
// byte-identical to control-plane/remediation/canonical_test.go's `want`: the
// control-plane signs these bytes and the agent re-derives them to verify. If
// either side changes the framing, BOTH goldens must change in lockstep or the
// agent can no longer verify a cloud-signed job.
func TestCanonicalGolden(t *testing.T) {
	want := "suricatoos-remediation-v1\n" +
		"schema_version=0:\n" +
		"job_id=2:j1\n" +
		"correlation_id=0:\n" +
		"tenant=4:acme\n" +
		"agent_id=7:win-abc\n" +
		"type=13:package_patch\n" +
		"approved_by=0:\n" +
		"issued_at=20:2026-10-08T12:00:00Z\n" +
		"not_before=0:\n" +
		"not_after=0:\n" +
		"expires_at=20:2026-10-09T12:00:00Z\n" +
		"nonce=2:n1\n" +
		"payload_sha256=3:abc\n"
	if got := string(Canonical(goldenJob())); got != want {
		t.Fatalf("canonical drift vs control-plane contract:\n got=%q\nwant=%q", got, want)
	}
}

// signGolden produces a job signed with a fresh key (the agent never signs in
// production — only the control-plane does — so the test synthesises a signer).
func signGolden(t *testing.T) (*Job, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	j := goldenJob()
	j.Payload = json.RawMessage(`{"kb":"KB5041580"}`)
	j.PayloadSHA256 = computePayloadSHA256(j.Payload)
	j.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, Canonical(j)))
	return j, pub
}

func TestVerifyRoundTripAndBindings(t *testing.T) {
	j, pub := signGolden(t)
	if !Verify(j, pub) {
		t.Fatal("assinatura válida deve verificar")
	}

	// A swapped payload (sha no longer matches) must fail even with a good sig.
	swapped := *j
	swapped.Payload = json.RawMessage(`{"kb":"KB0000000"}`)
	if Verify(&swapped, pub) {
		t.Error("troca de payload deve falhar (ligação por sha256)")
	}

	// Transplant to another host: agent_id is signed, so the canonical changes
	// and the signature no longer matches — the core cross-host guard.
	transplant := *j
	transplant.AgentID = "win-other"
	if Verify(&transplant, pub) {
		t.Error("transplante p/ outro agent_id deve falhar")
	}

	// Transplant to another tenant likewise.
	crossTenant := *j
	crossTenant.Tenant = "evil"
	if Verify(&crossTenant, pub) {
		t.Error("transplante p/ outro tenant deve falhar")
	}

	// A different key must fail.
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	if Verify(j, otherPub) {
		t.Error("chave errada deve falhar")
	}

	// An unsigned job must fail.
	unsigned := *j
	unsigned.Signature = ""
	if Verify(&unsigned, pub) {
		t.Error("job sem assinatura deve falhar")
	}
}

func TestVerifyAtWindow(t *testing.T) {
	j, pub := signGolden(t)
	// bare Verify is time-independent and must still pass.
	if !Verify(j, pub) {
		t.Fatal("Verify (sem tempo) deve passar")
	}
	if !VerifyAt(j, pub, j.IssuedAt.Add(30*time.Minute), time.Minute) {
		t.Error("job fresco dentro da janela deve verificar")
	}
	if VerifyAt(j, pub, j.ExpiresAt.Add(2*time.Minute), time.Minute) {
		t.Error("job expirado deve ser rejeitado por VerifyAt (mesmo com assinatura válida)")
	}
	if VerifyAt(j, pub, j.IssuedAt.Add(-2*time.Minute), time.Minute) {
		t.Error("job ainda-não-emitido (além do skew) deve ser rejeitado")
	}
}
