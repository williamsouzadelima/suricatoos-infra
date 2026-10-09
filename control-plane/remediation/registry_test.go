package remediation

import (
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/williamsouzadelima/suricatoos-infra/control-plane/signkeys"
)

func testReg(t *testing.T) (*Registry, *signkeys.Key) {
	t.Helper()
	key, err := signkeys.LoadOrCreate("")
	if err != nil {
		t.Fatal(err)
	}
	r, err := NewRegistry(Config{Path: filepath.Join(t.TempDir(), "rem.json"), Signer: key})
	if err != nil {
		t.Fatal(err)
	}
	return r, key
}

func enq(t *testing.T, r *Registry, agent, tenant string) *RemediationJob {
	t.Helper()
	j, err := r.Enqueue(EnqueueRequest{
		Tenant: tenant, AgentID: agent, Type: TypePackagePatch,
		Payload: json.RawMessage(`{"kb":"KB5041580"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	return j
}

func TestEnqueueIsPendingUnsigned(t *testing.T) {
	r, _ := testReg(t)
	j := enq(t, r, "win1", "acme")
	if j.State != StatePendingApproval {
		t.Errorf("state = %s, want PENDING_APPROVAL", j.State)
	}
	if j.Signature != "" {
		t.Error("a pending job must NOT be signed")
	}
	if j.Nonce == "" || j.PayloadSHA256 == "" || j.JobID == "" {
		t.Error("nonce/payload_sha256/job_id must be assigned")
	}
	// Not deliverable before approval.
	if _, ok := r.Poll("win1", "acme"); ok {
		t.Error("an unapproved job must not be delivered")
	}
}

func TestApproveSignsAndIsVerifiable(t *testing.T) {
	r, key := testReg(t)
	j := enq(t, r, "win1", "acme")
	appr, err := r.Approve(j.JobID, "operator@strati")
	if err != nil {
		t.Fatal(err)
	}
	if appr.State != StateApproved || appr.Signature == "" || appr.ApprovedBy != "operator@strati" {
		t.Fatalf("approve result wrong: %+v", appr)
	}
	if !Verify(appr, key.Public()) {
		t.Error("approved job signature must verify")
	}
	// Re-approving a non-pending job is an error.
	if _, err := r.Approve(j.JobID, "x"); err == nil {
		t.Error("approving a non-pending job must error")
	}
}

func TestApproveNeedsSigner(t *testing.T) {
	r, _ := NewRegistry(Config{}) // no signer
	r2 := r
	j, _ := r2.Enqueue(EnqueueRequest{Tenant: "acme", AgentID: "win1", Type: TypePackagePatch, Payload: json.RawMessage(`{}`)})
	if _, err := r2.Approve(j.JobID, "op"); err == nil {
		t.Error("approve without a configured signer must error")
	}
}

func TestCrossHostAndTenantIsolation(t *testing.T) {
	r, _ := testReg(t)
	j := enq(t, r, "winA", "acme")
	if _, err := r.Approve(j.JobID, "op"); err != nil {
		t.Fatal(err)
	}
	// Wrong agent, wrong tenant → never delivered.
	if _, ok := r.Poll("winB", "acme"); ok {
		t.Error("another agent must not receive the job")
	}
	if _, ok := r.Poll("winA", "other"); ok {
		t.Error("another tenant must not receive the job")
	}
	// Ack/Get with wrong identity → false (no cross-host action, no enumeration).
	if r.Ack(j.JobID, "winB", "acme") {
		t.Error("cross-agent ack must fail")
	}
	if _, ok := r.Get(j.JobID, "winA", "other"); ok {
		t.Error("cross-tenant get must fail")
	}
	// Correct identity receives it exactly once (then it's DELIVERED).
	got, ok := r.Poll("winA", "acme")
	if !ok || got.JobID != j.JobID {
		t.Fatal("the owning agent must receive its job")
	}
	if _, ok := r.Poll("winA", "acme"); ok {
		t.Error("a just-delivered job must not be redelivered immediately")
	}
}

func TestApplyThenServerVerifies(t *testing.T) {
	r, _ := testReg(t)
	j := enq(t, r, "win1", "acme")
	r.Approve(j.JobID, "op")
	r.Poll("win1", "acme")
	if !r.Ack(j.JobID, "win1", "acme") {
		t.Fatal("ack failed")
	}
	if !r.Report(j.JobID, "win1", "acme", &Result{Status: "applied", After: "patched"}) {
		t.Fatal("report failed")
	}
	if got, _ := r.Get(j.JobID, "win1", "acme"); got.State != StateApplied {
		t.Fatalf("state = %s, want APPLIED", got.State)
	}
	// The agent can never declare VERIFIED — only the server (after a re-scan).
	if !r.MarkVerified(j.JobID) {
		t.Fatal("MarkVerified failed")
	}
	if got, _ := r.Get(j.JobID, "win1", "acme"); got.State != StateVerified {
		t.Fatalf("state = %s, want VERIFIED", got.State)
	}
}

func TestReportFailedIsTerminal(t *testing.T) {
	r, _ := testReg(t)
	j := enq(t, r, "win1", "acme")
	r.Approve(j.JobID, "op")
	r.Poll("win1", "acme")
	r.Report(j.JobID, "win1", "acme", &Result{Status: "failed", Detail: "reboot loop"})
	got, _ := r.Get(j.JobID, "win1", "acme")
	if got.State != StateFailed || !got.State.terminal() {
		t.Fatalf("failed must be terminal: %s", got.State)
	}
	// MarkVerified must NOT resurrect a failed job.
	if r.MarkVerified(j.JobID); got.State == StateVerified {
		t.Error("a failed job must not become verified")
	}
}

func TestExpirySweep(t *testing.T) {
	r, _ := testReg(t)
	base := time.Date(2026, 10, 8, 0, 0, 0, 0, time.UTC)
	r.now = func() time.Time { return base }
	j, _ := r.Enqueue(EnqueueRequest{Tenant: "acme", AgentID: "win1", Type: TypePackagePatch, Payload: json.RawMessage(`{}`), TTL: time.Hour})
	r.Approve(j.JobID, "op")
	r.now = func() time.Time { return base.Add(2 * time.Hour) } // past expiry
	if _, ok := r.Poll("win1", "acme"); ok {
		t.Error("expired job must not be delivered")
	}
	if got, _ := r.Get(j.JobID, "win1", "acme"); got.State != StateExpired {
		t.Fatalf("state = %s, want EXPIRED", got.State)
	}
}

func TestMaintenanceWindow(t *testing.T) {
	r, _ := testReg(t)
	base := time.Date(2026, 10, 8, 0, 0, 0, 0, time.UTC)
	r.now = func() time.Time { return base }
	j, _ := r.Enqueue(EnqueueRequest{
		Tenant: "acme", AgentID: "win1", Type: TypeConfigHardening, Payload: json.RawMessage(`{}`),
		NotBefore: base.Add(time.Hour), NotAfter: base.Add(2 * time.Hour), TTL: 24 * time.Hour,
	})
	r.Approve(j.JobID, "op")
	// Before the window → held.
	if _, ok := r.Poll("win1", "acme"); ok {
		t.Error("must not deliver before the maintenance window opens")
	}
	// Inside the window → delivered.
	r.now = func() time.Time { return base.Add(90 * time.Minute) }
	if _, ok := r.Poll("win1", "acme"); !ok {
		t.Error("must deliver inside the maintenance window")
	}
}

func TestPersistRoundTrip(t *testing.T) {
	key, _ := signkeys.LoadOrCreate("")
	path := filepath.Join(t.TempDir(), "rem.json")
	r1, _ := NewRegistry(Config{Path: path, Signer: key})
	j := enq(t, r1, "win1", "acme")
	appr, _ := r1.Approve(j.JobID, "op")

	r2, err := NewRegistry(Config{Path: path, Signer: key})
	if err != nil {
		t.Fatal(err)
	}
	got, ok := r2.Get(j.JobID, "win1", "acme")
	if !ok || got.State != StateApproved || got.Signature != appr.Signature {
		t.Fatalf("job not restored intact: %+v", got)
	}
	if !Verify(got, key.Public()) {
		t.Error("restored signature must still verify")
	}
}
