package remediation

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/williamsouzadelima/suricatoos-infra/control-plane/signkeys"
)

func goldenJob() *RemediationJob {
	return &RemediationJob{
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

// TestCanonicalGolden pins the exact signed bytes. The agent re-derives these
// independently; if this string changes, the agent copy MUST change in lockstep.
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
		t.Fatalf("canonical drift:\n got=%q\nwant=%q", got, want)
	}
}

func TestCanonicalBindsEveryField(t *testing.T) {
	base := string(Canonical(goldenJob()))
	mut := map[string]func(*RemediationJob){
		"schema_version": func(j *RemediationJob) { j.SchemaVersion = "9.9.9" },
		"job_id":         func(j *RemediationJob) { j.JobID = "j2" },
		"correlation_id": func(j *RemediationJob) { j.CorrelationID = "c2" },
		"agent_id":       func(j *RemediationJob) { j.AgentID = "other" },
		"tenant":         func(j *RemediationJob) { j.Tenant = "evil" },
		"type":           func(j *RemediationJob) { j.Type = TypeConfigHardening },
		"approved_by":    func(j *RemediationJob) { j.ApprovedBy = "mallory" },
		"issued_at":      func(j *RemediationJob) { j.IssuedAt = j.IssuedAt.Add(time.Second) },
		"not_before":     func(j *RemediationJob) { j.NotBefore = j.IssuedAt.Add(time.Hour) },
		"not_after":      func(j *RemediationJob) { j.NotAfter = j.IssuedAt.Add(2 * time.Hour) },
		"expires_at":     func(j *RemediationJob) { j.ExpiresAt = j.ExpiresAt.Add(time.Second) },
		"nonce":          func(j *RemediationJob) { j.Nonce = "n2" },
		"payload_sha256": func(j *RemediationJob) { j.PayloadSHA256 = "def" },
	}
	for name, f := range mut {
		j := goldenJob()
		f(j)
		if string(Canonical(j)) == base {
			t.Errorf("changing %s must change the canonical (replay/transplant guard)", name)
		}
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	key, err := signkeys.LoadOrCreate("")
	if err != nil {
		t.Fatal(err)
	}
	payload := json.RawMessage(`{"kb":"KB5041580"}`)
	j := goldenJob()
	j.Payload = payload
	j.PayloadSHA256 = ComputePayloadSHA256(payload)
	j.Signature = Sign(j, key)

	if !Verify(j, key.Public()) {
		t.Fatal("valid signature must verify")
	}
	// A swapped payload (sha no longer matches) must fail even with a good sig.
	tampered := j.clone()
	tampered.Payload = json.RawMessage(`{"kb":"KB0000000"}`)
	if Verify(tampered, key.Public()) {
		t.Error("payload swap must fail verification (sha256 binding)")
	}
	// A different key must fail.
	other, _ := signkeys.LoadOrCreate("")
	if Verify(j, other.Public()) {
		t.Error("wrong key must fail verification")
	}
	// An unsigned job must fail.
	j.Signature = ""
	if Verify(j, key.Public()) {
		t.Error("unsigned job must fail verification")
	}
}

func TestVerifyAt(t *testing.T) {
	key, _ := signkeys.LoadOrCreate("")
	now := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	j := goldenJob()
	j.IssuedAt = now
	j.ExpiresAt = now.Add(time.Hour)
	j.Payload = json.RawMessage(`{"kb":"x"}`)
	j.PayloadSHA256 = ComputePayloadSHA256(j.Payload)
	j.Signature = Sign(j, key)

	if !VerifyAt(j, key.Public(), now.Add(30*time.Minute), time.Minute) {
		t.Error("fresh job must verify")
	}
	if VerifyAt(j, key.Public(), now.Add(2*time.Hour), time.Minute) {
		t.Error("expired job must be rejected by VerifyAt (even though the signature is valid)")
	}
	if VerifyAt(j, key.Public(), now.Add(-2*time.Minute), time.Minute) {
		t.Error("not-yet-issued job (beyond skew) must be rejected")
	}
	if !Verify(j, key.Public()) {
		t.Error("bare Verify is time-independent and must still pass")
	}
}
