package remediation

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
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
	appr, err := r.Approve(j.JobID, "operator@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if appr.State != StateApproved || appr.Signature == "" || appr.ApprovedBy != "operator@example.com" {
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
	if err := r.Report(j.JobID, "win1", "acme", &Result{Status: "applied", After: "patched"}); err != nil {
		t.Fatalf("report failed: %v", err)
	}
	if got, _ := r.Get(j.JobID, "win1", "acme"); got.State != StateApplied {
		t.Fatalf("state = %s, want APPLIED", got.State)
	}
	// The agent can never declare VERIFIED — only the server (after a re-scan).
	verified, err := r.MarkVerified(j.JobID)
	if err != nil {
		t.Fatalf("MarkVerified: %v", err)
	}
	if verified.State != StateVerified {
		t.Fatalf("returned state = %s, want VERIFIED", verified.State)
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
	if _, err := r.MarkVerified(j.JobID); !errors.Is(err, ErrInvalidState) {
		t.Errorf("MarkVerified of a FAILED job: err = %v, want ErrInvalidState", err)
	}
	if got, _ := r.Get(j.JobID, "win1", "acme"); got.State != StateFailed {
		t.Errorf("a failed job must stay FAILED, got %s", got.State)
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

func TestPersistRoundTripHTMLPayload(t *testing.T) {
	// A config_hardening payload with <,>,& must still verify after a reload.
	// (json.Marshal escapes them to </>/&; the sha was over the
	// json.Compact bytes → the signature would break. saveLocked uses
	// SetEscapeHTML(false) to keep the payload byte-stable.)
	key, _ := signkeys.LoadOrCreate("")
	path := filepath.Join(t.TempDir(), "rem.json")
	r1, _ := NewRegistry(Config{Path: path, Signer: key})
	j, err := r1.Enqueue(EnqueueRequest{
		Tenant: "acme", AgentID: "win1", Type: TypeConfigHardening,
		Payload: json.RawMessage(`{"rule":"a<b && c>d","amp":"x&y"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r1.Approve(j.JobID, "op"); err != nil {
		t.Fatal(err)
	}
	r2, err := NewRegistry(Config{Path: path, Signer: key})
	if err != nil {
		t.Fatal(err)
	}
	got, ok := r2.Get(j.JobID, "win1", "acme")
	if !ok {
		t.Fatal("job not restored")
	}
	if !Verify(got, key.Public()) {
		t.Fatal("payload with <,>,& must still verify after reload")
	}
}

func TestReportRequiresDeliveryAndNoClobber(t *testing.T) {
	r, _ := testReg(t)
	j := enq(t, r, "win1", "acme")
	r.Approve(j.JobID, "op")
	// Report before delivery (still APPROVED) → rejected (never handed out).
	if err := r.Report(j.JobID, "win1", "acme", &Result{Status: "applied"}); !errors.Is(err, ErrNotFound) {
		t.Errorf("report before delivery: err = %v, want ErrNotFound", err)
	}
	r.Poll("win1", "acme") // → DELIVERED (ACK is optional for Report)
	if err := r.Report(j.JobID, "win1", "acme", &Result{Status: "applied", After: "patched"}); err != nil {
		t.Fatalf("report after delivery must succeed: %v", err)
	}
	got, _ := r.Get(j.JobID, "win1", "acme")
	if got.State != StateApplied || got.Result == nil || got.Result.After != "patched" {
		t.Fatalf("state/result wrong: %+v", got)
	}
	// Re-report must NOT clobber the recorded result nor flip the state.
	r.Report(j.JobID, "win1", "acme", &Result{Status: "failed", After: "WIPED"})
	g2, _ := r.Get(j.JobID, "win1", "acme")
	if g2.State != StateApplied || g2.Result.After != "patched" {
		t.Errorf("re-report clobbered the result: %+v", g2)
	}
}

func TestReapDropsOldTerminal(t *testing.T) {
	r, _ := testReg(t)
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	r.now = func() time.Time { return base }
	j := enq(t, r, "win1", "acme")
	r.Reject(j.JobID, "op") // terminal
	if n := r.Reap(time.Hour); n != 0 {
		t.Errorf("reap too early removed %d", n)
	}
	r.now = func() time.Time { return base.Add(48 * time.Hour) }
	if n := r.Reap(24 * time.Hour); n != 1 {
		t.Errorf("reap should drop 1 old terminal, got %d", n)
	}
	if _, ok := r.Get(j.JobID, "win1", "acme"); ok {
		t.Error("reaped job still present")
	}
}

func TestLoadDropsIncoherentSignedState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rem.json")
	// A DELIVERED job with NO signature is incoherent (tampered/corrupt) → dropped.
	bad := `[{"schema_version":"1.0.0","job_id":"x","tenant":"acme","agent_id":"win1","type":"package_patch","payload":{},"payload_sha256":"z","nonce":"n","state":"DELIVERED","created_at":"2026-10-08T00:00:00Z"}]`
	if err := os.WriteFile(path, []byte(bad), 0o600); err != nil {
		t.Fatal(err)
	}
	r, err := NewRegistry(Config{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := r.Get("x", "win1", "acme"); ok {
		t.Error("a post-approval-state job with no signature must be dropped on load")
	}
}

// at pins a registry clock at t (tests move the clock by reassigning r.now).
func at(t time.Time) func() time.Time { return func() time.Time { return t } }

// clockBase is the instant the lifecycle tests enqueue at; every job there has a
// 1h TTL, so clockBase+2h is past ExpiresAt (and past the redeliver window).
var clockBase = time.Date(2026, 10, 8, 0, 0, 0, 0, time.UTC)

// lifecycle lists every state a job can be in. It is written out here rather than
// taken from the package, so a state added to the lifecycle shows up as a missing
// row (jobIn refuses it) instead of as a silently untested one.
var lifecycle = []JobState{
	StatePendingApproval, StateApproved, StateDelivered, StateAcked, StateApplied,
	StateFailed, StateVerified, StateExpired, StateRejected, StateClosed,
}

// jobIn enqueues a win1/acme job (1h TTL, at the registry's current clock) and
// drives it to st through the real transitions — Approve, Poll, Ack, Report,
// MarkVerified, Reject, Close — never by poking State, so the tests exercise the
// production path. Any state of the lifecycle works. REJECTED is a PENDING_APPROVAL
// job that was rejected and CLOSED an ACKED one that an operator closed (closedFrom
// builds the others); EXPIRED moves the registry clock 2h forward, past the 1h TTL,
// and polls so the lapsed APPROVED job is swept. The poll hands out the OLDEST
// deliverable job, so in a registry that holds several jobs build the ones the agent
// receives before the ones that stay undelivered.
func jobIn(t *testing.T, r *Registry, st JobState) *RemediationJob {
	t.Helper()
	j, err := r.Enqueue(EnqueueRequest{
		Tenant: "acme", AgentID: "win1", Type: TypePackagePatch,
		Payload: json.RawMessage(`{"kb":"KB5041580"}`), TTL: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	if st == StatePendingApproval {
		return j
	}
	if st == StateRejected {
		if err := r.Reject(j.JobID, "op"); err != nil {
			t.Fatal(err)
		}
		return j
	}
	if _, err := r.Approve(j.JobID, "op"); err != nil {
		t.Fatal(err)
	}
	if st == StateApproved {
		return j
	}
	if st == StateExpired {
		r.now = at(r.now().Add(2 * time.Hour))
		r.Poll("win1", "acme")
		return j
	}
	if _, ok := r.Poll("win1", "acme"); !ok {
		t.Fatal("poll must deliver the approved job")
	}
	if st == StateDelivered {
		return j
	}
	if !r.Ack(j.JobID, "win1", "acme") {
		t.Fatal("ack failed")
	}
	if st == StateAcked {
		return j
	}
	if st == StateClosed {
		if _, err := r.Close(j.JobID, "op", ""); err != nil {
			t.Fatal(err)
		}
		return j
	}
	status := "applied"
	if st == StateFailed {
		status = "failed"
	}
	if err := r.Report(j.JobID, "win1", "acme", &Result{Status: status, After: "patched"}); err != nil {
		t.Fatalf("report failed: %v", err)
	}
	if st == StateVerified {
		if _, err := r.MarkVerified(j.JobID); err != nil {
			t.Fatal(err)
		}
	}
	return j
}

// reportedJob drives a fresh job to ACKED and has the agent report res, so a test
// controls every field of the stored Result (before, rollback_token, ...).
func reportedJob(t *testing.T, r *Registry, res Result) *RemediationJob {
	t.Helper()
	j := jobIn(t, r, StateAcked)
	if err := r.Report(j.JobID, "win1", "acme", &res); err != nil {
		t.Fatalf("report failed: %v", err)
	}
	return j
}

// failSaves makes every later persist of r fail while the file on disk stays as it
// is: the temp file the registry writes before the rename becomes a directory.
func failSaves(t *testing.T, r *Registry) {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.path == "" {
		t.Fatal("a registry without a file never fails to save")
	}
	if err := os.Mkdir(r.path+".tmp", 0o700); err != nil {
		t.Fatal(err)
	}
}

// onDisk loads what r last persisted: a second registry over the same file.
func onDisk(t *testing.T, r *Registry) *Registry {
	t.Helper()
	d, err := NewRegistry(Config{Path: r.path})
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// linesWith returns the lines of the captured log that contain sub.
func linesWith(buf *lockedBuf, sub string) []string {
	var out []string
	for _, l := range strings.Split(buf.String(), "\n") {
		if strings.Contains(l, sub) {
			out = append(out, l)
		}
	}
	return out
}

// sameResult fails the test unless got carries exactly want's agent-supplied
// fields; reported_at is the server's own stamp and is checked separately.
func sameResult(t *testing.T, where string, got *Result, want Result) {
	t.Helper()
	if got == nil {
		t.Errorf("%s: result = nil, want %+v", where, want)
		return
	}
	g := *got
	g.ReportedAt = time.Time{}
	if g != want {
		t.Errorf("%s: result = %+v, want %+v", where, g, want)
	}
}

func stateOf(t *testing.T, r *Registry, id string) JobState {
	t.Helper()
	got, ok := r.Get(id, "win1", "acme")
	if !ok {
		t.Fatalf("job %s not found", id)
	}
	return got.State
}

// ExpiresAt bounds only the states BEFORE the agent has effectively taken the job
// (PENDING_APPROVAL, APPROVED, DELIVERED-unacked). An ACKED job (the agent accepted
// it) and an APPLIED one (applied, awaiting verification) must survive a lapsed
// ExpiresAt, or the apply result — and the fact that it was applied — is lost.
func TestPollExpiresOnlyBeforeEffectiveDelivery(t *testing.T) {
	cases := []struct {
		state  JobState
		expire bool
	}{
		{StatePendingApproval, true},
		{StateApproved, true},
		{StateDelivered, true},
		{StateAcked, false},
		{StateApplied, false},
	}
	for _, tc := range cases {
		t.Run(string(tc.state), func(t *testing.T) {
			r, _ := testReg(t)
			r.now = at(clockBase)
			j := jobIn(t, r, tc.state)
			if got := stateOf(t, r, j.JobID); got != tc.state {
				t.Fatalf("setup: state = %s, want %s", got, tc.state)
			}
			r.now = at(clockBase.Add(2 * time.Hour)) // past ExpiresAt
			if _, ok := r.Poll("win1", "acme"); ok {
				t.Error("an expired / already-taken job must not be delivered again")
			}
			want := tc.state
			if tc.expire {
				want = StateExpired
			}
			if got := stateOf(t, r, j.JobID); got != want {
				t.Errorf("state after the lapsed ExpiresAt = %s, want %s", got, want)
			}
		})
	}
}

func TestReportAfterExpiryOfAckedJobIsAccepted(t *testing.T) {
	r, _ := testReg(t)
	r.now = at(clockBase)
	j := jobIn(t, r, StateAcked)

	// The deadline lapses while the agent is still applying; its next poll runs the
	// expiry sweep — which must leave the ACKED job alone.
	r.now = at(clockBase.Add(2 * time.Hour))
	r.Poll("win1", "acme")

	if err := r.Report(j.JobID, "win1", "acme", &Result{Status: "applied", After: "patched"}); err != nil {
		t.Fatalf("a report for an ACKED job past ExpiresAt must be accepted: %v", err)
	}
	got, _ := r.Get(j.JobID, "win1", "acme")
	if got.State != StateApplied || got.Result == nil || got.Result.After != "patched" {
		t.Fatalf("the apply result was lost: %+v", got)
	}
}

// MarkVerified is the server-side close of the cycle: ONLY an APPLIED job moves to
// VERIFIED. Anything else is a conflict (ErrInvalidState) and is left untouched; an
// unknown id is ErrNotFound.
func TestMarkVerifiedOnlyFromApplied(t *testing.T) {
	for _, st := range []JobState{StatePendingApproval, StateApproved, StateDelivered, StateAcked, StateFailed} {
		t.Run(string(st), func(t *testing.T) {
			r, _ := testReg(t)
			j := jobIn(t, r, st)
			if _, err := r.MarkVerified(j.JobID); !errors.Is(err, ErrInvalidState) {
				t.Errorf("MarkVerified from %s: err = %v, want ErrInvalidState", st, err)
			}
			if got := stateOf(t, r, j.JobID); got != st {
				t.Errorf("a refused MarkVerified changed %s to %s", st, got)
			}
		})
	}

	t.Run("REJECTED", func(t *testing.T) {
		r, _ := testReg(t)
		j := jobIn(t, r, StatePendingApproval)
		if err := r.Reject(j.JobID, "op"); err != nil {
			t.Fatal(err)
		}
		if _, err := r.MarkVerified(j.JobID); !errors.Is(err, ErrInvalidState) {
			t.Errorf("err = %v, want ErrInvalidState", err)
		}
	})
	t.Run("EXPIRED", func(t *testing.T) {
		r, _ := testReg(t)
		r.now = at(clockBase)
		j := jobIn(t, r, StateApproved)
		r.now = at(clockBase.Add(2 * time.Hour))
		r.Poll("win1", "acme") // sweeps the lapsed APPROVED job
		if _, err := r.MarkVerified(j.JobID); !errors.Is(err, ErrInvalidState) {
			t.Errorf("err = %v, want ErrInvalidState", err)
		}
	})
	t.Run("VERIFIED is not verified twice", func(t *testing.T) {
		r, _ := testReg(t)
		j := jobIn(t, r, StateApplied)
		if _, err := r.MarkVerified(j.JobID); err != nil {
			t.Fatal(err)
		}
		if _, err := r.MarkVerified(j.JobID); !errors.Is(err, ErrInvalidState) {
			t.Errorf("second MarkVerified: err = %v, want ErrInvalidState", err)
		}
	})
	t.Run("unknown id", func(t *testing.T) {
		r, _ := testReg(t)
		if _, err := r.MarkVerified("nao-existe"); !errors.Is(err, ErrNotFound) {
			t.Errorf("err = %v, want ErrNotFound", err)
		}
	})
}

// An APPLIED job waits for the re-scan to confirm it — possibly well past the
// original ExpiresAt. It must still be verifiable (and still be there).
func TestMarkVerifiedAfterLapsedExpiry(t *testing.T) {
	r, _ := testReg(t)
	r.now = at(clockBase)
	j := jobIn(t, r, StateApplied)
	r.now = at(clockBase.Add(48 * time.Hour))
	r.Poll("win1", "acme") // the sweep must not touch an APPLIED job
	verified, err := r.MarkVerified(j.JobID)
	if err != nil {
		t.Fatalf("MarkVerified: %v", err)
	}
	if verified.State != StateVerified || verified.Result == nil || verified.Result.After != "patched" {
		t.Errorf("the verified job lost its apply result: %+v", verified)
	}
}

// Reject is for a job nobody has received: PENDING_APPROVAL and APPROVED. Once the
// agent has it (DELIVERED, ACKED, APPLIED, FAILED) — or it is final already — there
// is no rejecting it: Close is the honest way out of the queue for a delivered one.
// A refused Reject changes nothing, not even for a job that was already REJECTED.
func TestRejectOnlyBeforeDelivery(t *testing.T) {
	rejectable := map[JobState]bool{StatePendingApproval: true, StateApproved: true}
	for _, st := range lifecycle {
		t.Run(string(st), func(t *testing.T) {
			r, _ := testReg(t)
			j := jobIn(t, r, st)
			before, _ := r.Get(j.JobID, "win1", "acme")
			err := r.Reject(j.JobID, "bob")
			after, _ := r.Get(j.JobID, "win1", "acme")
			if rejectable[st] {
				if err != nil {
					t.Fatalf("Reject from %s: %v", st, err)
				}
				if after.State != StateRejected {
					t.Errorf("Reject from %s left the job in %s, want REJECTED", st, after.State)
				}
				return
			}
			if !errors.Is(err, ErrInvalidState) {
				t.Errorf("Reject from %s: err = %v, want ErrInvalidState", st, err)
			}
			if after.State != st || after.ApprovedBy != before.ApprovedBy || !after.ApprovedAt.Equal(before.ApprovedAt) ||
				after.RejectedBy != before.RejectedBy || !after.RejectedAt.Equal(before.RejectedAt) {
				t.Errorf("a refused Reject changed the %s job: %+v -> %+v", st, before, after)
			}
		})
	}
	t.Run("unknown id", func(t *testing.T) {
		r, _ := testReg(t)
		if err := r.Reject("nao-existe", "bob"); !errors.Is(err, ErrNotFound) {
			t.Errorf("err = %v, want ErrNotFound", err)
		}
	})
}

// Rejecting records WHO rejected in its own fields and leaves the approval alone: the
// approver of an APPROVED job (which the job's signature covers, so it must still
// verify) and, for a job nobody approved, no approver at all. The same holds for
// what was persisted, not only for memory.
func TestRejectKeepsTheApproverAndRecordsTheRejecter(t *testing.T) {
	for _, st := range []JobState{StatePendingApproval, StateApproved} {
		t.Run(string(st), func(t *testing.T) {
			r, key := testReg(t)
			r.now = at(clockBase)
			j := jobIn(t, r, st) // APPROVED: approved by "op" at clockBase
			before, _ := r.Get(j.JobID, "win1", "acme")
			rejectedAt := clockBase.Add(5 * time.Minute)
			r.now = at(rejectedAt)
			if err := r.Reject(j.JobID, "bob"); err != nil {
				t.Fatal(err)
			}

			check := func(where string, got *RemediationJob) {
				t.Helper()
				if got.State != StateRejected || got.RejectedBy != "bob" || !got.RejectedAt.Equal(rejectedAt) {
					t.Errorf("%s: rejection record wrong: state=%s by=%q at=%v", where, got.State, got.RejectedBy, got.RejectedAt)
				}
				if got.ApprovedBy != before.ApprovedBy || !got.ApprovedAt.Equal(before.ApprovedAt) || got.Signature != before.Signature {
					t.Errorf("%s: the approval was overwritten: approved_by=%q approved_at=%v", where, got.ApprovedBy, got.ApprovedAt)
				}
				if st == StateApproved && !Verify(got, key.Public()) {
					t.Errorf("%s: the signature of the approved change no longer verifies", where)
				}
			}
			got, _ := r.Get(j.JobID, "win1", "acme")
			check("memory", got)
			disk, ok := onDisk(t, r).Get(j.JobID, "win1", "acme")
			if !ok {
				t.Fatal("the rejected job is missing from the file")
			}
			check("disk", disk)
		})
	}
}

// A write that fails leaves the job as it was (as Approve does): same state, no
// rejecter recorded, memory agreeing with the file, the error returned and nothing
// audited. Once the write is fixed the same reject goes through.
func TestRejectRevertsWhenTheWriteFails(t *testing.T) {
	for _, st := range []JobState{StatePendingApproval, StateApproved} {
		t.Run(string(st), func(t *testing.T) {
			logs := captureLog(t)
			r, _ := testReg(t)
			j := jobIn(t, r, st)
			failSaves(t, r)
			err := r.Reject(j.JobID, "bob")
			if err == nil {
				t.Fatal("Reject must report the failed write")
			}
			if errors.Is(err, ErrInvalidState) || errors.Is(err, ErrNotFound) {
				t.Errorf("a failed write is neither a state nor a not-found error: %v", err)
			}
			mem, _ := r.Get(j.JobID, "win1", "acme")
			if mem.State != st || mem.RejectedBy != "" || !mem.RejectedAt.IsZero() {
				t.Errorf("memory was not reverted to %s: %+v", st, mem)
			}
			if disk, _ := onDisk(t, r).Get(j.JobID, "win1", "acme"); disk.State != st {
				t.Errorf("memory (%s) and file (%s) disagree", mem.State, disk.State)
			}
			if lines := linesWith(logs, "rejeitado por"); len(lines) != 0 {
				t.Errorf("a rejection that did not happen was audited: %q", lines)
			}

			if err := os.Remove(r.path + ".tmp"); err != nil {
				t.Fatal(err)
			}
			if err := r.Reject(j.JobID, "bob"); err != nil {
				t.Fatalf("after the write is fixed the same reject must go through: %v", err)
			}
			if got := stateOf(t, r, j.JobID); got != StateRejected {
				t.Errorf("state after the retry = %s, want REJECTED", got)
			}
		})
	}
}

// Every effective rejection writes ONE audit line — who, the state it was in, the
// approver kept on the job, the tenant and the agent. A reject that changed nothing
// (refused state, unknown id) writes none.
func TestRejectLogsOneAuditLinePerEffectiveRejection(t *testing.T) {
	logs := captureLog(t)
	r, _ := testReg(t)
	j := jobIn(t, r, StateApproved) // approved by "op"
	if err := r.Reject(j.JobID, "bob"); err != nil {
		t.Fatal(err)
	}
	lines := linesWith(logs, "rejeitado por")
	if len(lines) != 1 {
		t.Fatalf("want exactly 1 audit line for the rejection, got %d: %q", len(lines), lines)
	}
	for _, want := range []string{
		j.JobID, `rejeitado por "bob"`, "estado anterior APPROVED", `aprovador "op"`, `tenant="acme"`, `agent="win1"`,
	} {
		if !strings.Contains(lines[0], want) {
			t.Errorf("the audit line should contain %q: %s", want, lines[0])
		}
	}

	// A job nobody approved has no approver: it is logged as "".
	p := jobIn(t, r, StatePendingApproval)
	if err := r.Reject(p.JobID, "alice"); err != nil {
		t.Fatal(err)
	}
	lines = linesWith(logs, "rejeitado por")
	if len(lines) != 2 {
		t.Fatalf("want 2 audit lines in total, got %d: %q", len(lines), lines)
	}
	for _, want := range []string{p.JobID, `rejeitado por "alice"`, `aprovador ""`, "estado anterior PENDING_APPROVAL"} {
		if !strings.Contains(lines[1], want) {
			t.Errorf("the audit line should contain %q: %s", want, lines[1])
		}
	}

	// A reject that is refused (already REJECTED, a delivered job) or targets an
	// unknown id changes nothing, so it logs nothing.
	if err := r.Reject(j.JobID, "mallory"); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("second reject: err = %v, want ErrInvalidState", err)
	}
	d := jobIn(t, r, StateDelivered)
	if err := r.Reject(d.JobID, "mallory"); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("reject of a DELIVERED job: err = %v, want ErrInvalidState", err)
	}
	if err := r.Reject("nao-existe", "mallory"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown id: err = %v, want ErrNotFound", err)
	}
	if n := len(linesWith(logs, "rejeitado por")); n != 2 {
		t.Errorf("a reject that changed nothing must not log (%d lines): %q", n, linesWith(logs, "rejeitado por"))
	}
}

// The rejecter, the approver, the tenant and the agent come from outside (request
// bodies): they are logged quoted, so none of them can start a line of its own.
func TestRejectAuditLineQuotesTheValuesItLogs(t *testing.T) {
	logs := captureLog(t)
	r, _ := testReg(t)
	evil := "x\nremediation: job fake aprovado por \"mallory\""
	j, err := r.Enqueue(EnqueueRequest{
		Tenant: evil, AgentID: evil, Type: TypePackagePatch, Payload: json.RawMessage(`{}`), TTL: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Approve(j.JobID, evil); err != nil {
		t.Fatal(err)
	}
	start := len(logs.String())
	if err := r.Reject(j.JobID, evil); err != nil {
		t.Fatal(err)
	}
	if out := logs.String()[start:]; strings.Count(out, "\n") != 1 {
		t.Errorf("the audit entry must be ONE line, got: %q", out)
	}
}

func TestMarkVerifiedPersists(t *testing.T) {
	key, _ := signkeys.LoadOrCreate("")
	path := filepath.Join(t.TempDir(), "rem.json")
	r1, _ := NewRegistry(Config{Path: path, Signer: key})
	j := jobIn(t, r1, StateApplied)
	if _, err := r1.MarkVerified(j.JobID); err != nil {
		t.Fatal(err)
	}
	r2, err := NewRegistry(Config{Path: path, Signer: key})
	if err != nil {
		t.Fatal(err)
	}
	if got := stateOf(t, r2, j.JobID); got != StateVerified {
		t.Fatalf("after reload state = %s, want VERIFIED", got)
	}
}

func TestListFiltersOrdersAndLimits(t *testing.T) {
	r, _ := testReg(t)
	mk := func(minute int, tenant, agent string) *RemediationJob {
		r.now = at(clockBase.Add(time.Duration(minute) * time.Minute))
		j, err := r.Enqueue(EnqueueRequest{
			Tenant: tenant, AgentID: agent, Type: TypePackagePatch,
			Payload: json.RawMessage(`{}`), TTL: 24 * time.Hour,
		})
		if err != nil {
			t.Fatal(err)
		}
		return j
	}
	a := mk(0, "acme", "win1")
	b := mk(1, "acme", "win2")
	c := mk(2, "globex", "win3")
	d := mk(3, "acme", "win1")
	if _, err := r.Approve(b.JobID, "op"); err != nil {
		t.Fatal(err)
	}
	ids := func(js []*RemediationJob) []string {
		out := make([]string, 0, len(js))
		for _, j := range js {
			out = append(out, j.JobID)
		}
		return out
	}
	check := func(what string, f ListFilter, wantTotal int, want ...*RemediationJob) {
		t.Helper()
		got, total := r.List(f)
		w := make([]string, 0, len(want))
		for _, j := range want {
			w = append(w, j.JobID)
		}
		g := ids(got)
		if len(g) != len(w) {
			t.Errorf("%s: ids = %v, want %v", what, g, w)
			return
		}
		for i := range w {
			if g[i] != w[i] {
				t.Errorf("%s: ids = %v, want %v", what, g, w)
				return
			}
		}
		if total != wantTotal {
			t.Errorf("%s: total = %d, want %d", what, total, wantTotal)
		}
	}

	check("sem filtro: created_at desc", ListFilter{}, 4, d, c, b, a)
	check("state", ListFilter{State: StateApproved}, 1, b)
	check("tenant", ListFilter{Tenant: "acme"}, 3, d, b, a)
	check("agent_id", ListFilter{AgentID: "win1"}, 2, d, a)
	check("tenant+agent_id", ListFilter{Tenant: "acme", AgentID: "win1"}, 2, d, a)
	check("sem ocorrência", ListFilter{Tenant: "acme", AgentID: "win3"}, 0)
	check("limit mantém os mais novos", ListFilter{Limit: 2}, 4, d, c)
	check("limit com filtro", ListFilter{Tenant: "acme", Limit: 1}, 3, d)
	check("limit <= 0 = padrão (nunca ilimitado)", ListFilter{Limit: -1}, 4, d, c, b, a)

	// List hands out CLONES: scribbling on a result must not touch the queue.
	got, _ := r.List(ListFilter{})
	got[0].State = StateVerified
	got[0].Payload[0] = 'X'
	if again, _ := r.List(ListFilter{}); again[0].State == StateVerified || again[0].Payload[0] == 'X' {
		t.Error("List must return clones")
	}
}

// Jobs created in the same instant still list in a stable order (JobID breaks the tie).
func TestListTieBreakIsDeterministic(t *testing.T) {
	r, _ := testReg(t)
	r.now = at(clockBase)
	var want []string
	for range 5 {
		want = append(want, enq(t, r, "win1", "acme").JobID)
	}
	sort.Strings(want)
	for range 3 {
		got, _ := r.List(ListFilter{})
		for i, j := range got {
			if j.JobID != want[i] {
				t.Fatalf("tied jobs must list by job_id: got %v, want %v", j.JobID, want[i])
			}
		}
	}
}

func TestClampLimit(t *testing.T) {
	for in, want := range map[int]int{-5: 200, 0: 200, 1: 1, 7: 7, 1000: 1000, 1001: 1000, 100000: 1000} {
		if got := clampLimit(in); got != want {
			t.Errorf("clampLimit(%d) = %d, want %d", in, got, want)
		}
	}
}

// Close takes a job the agent has already received out of the queue. DELIVERED,
// ACKED, APPLIED and FAILED are closable; a job nobody delivered has Reject, and one
// that is already final has nothing left to close. A refused Close changes nothing.
func TestCloseOnlyAfterDelivery(t *testing.T) {
	closable := map[JobState]bool{StateDelivered: true, StateAcked: true, StateApplied: true, StateFailed: true}
	for _, st := range lifecycle {
		t.Run(string(st), func(t *testing.T) {
			r, _ := testReg(t)
			j := jobIn(t, r, st)
			before, _ := r.Get(j.JobID, "win1", "acme")
			got, err := r.Close(j.JobID, "bob", "agente fora do ar")
			after, _ := r.Get(j.JobID, "win1", "acme")
			if closable[st] {
				if err != nil {
					t.Fatalf("Close from %s: %v", st, err)
				}
				if got.State != StateClosed || after.State != StateClosed {
					t.Errorf("Close from %s: returned %s, stored %s, want CLOSED", st, got.State, after.State)
				}
				return
			}
			if !errors.Is(err, ErrInvalidState) {
				t.Errorf("Close from %s: err = %v, want ErrInvalidState", st, err)
			}
			if got != nil {
				t.Errorf("a refused Close returned a job: %+v", got)
			}
			if after.State != st || after.ClosedBy != before.ClosedBy || !after.ClosedAt.Equal(before.ClosedAt) || after.ClosedReason != before.ClosedReason {
				t.Errorf("a refused Close changed the %s job: %+v -> %+v", st, before, after)
			}
		})
	}
	t.Run("unknown id", func(t *testing.T) {
		r, _ := testReg(t)
		if _, err := r.Close("nao-existe", "bob", ""); !errors.Is(err, ErrNotFound) {
			t.Errorf("err = %v, want ErrNotFound", err)
		}
	})
}

// A close with no one to blame is refused: the audit trail of a manual intervention
// must always say who did it.
func TestCloseNeedsAnOperator(t *testing.T) {
	r, _ := testReg(t)
	j := jobIn(t, r, StateAcked)
	if _, err := r.Close(j.JobID, "", "sem dono"); err == nil || errors.Is(err, ErrNotFound) || errors.Is(err, ErrInvalidState) {
		t.Errorf("Close without an operator: err = %v, want a plain refusal", err)
	}
	if got := stateOf(t, r, j.JobID); got != StateAcked {
		t.Errorf("a refused Close changed ACKED to %s", got)
	}
	// Nothing was half-done: with an operator the same job closes normally.
	closed, err := r.Close(j.JobID, "bob", "com dono")
	if err != nil {
		t.Fatalf("Close with an operator after the refusal: %v", err)
	}
	if closed.ClosedBy != "bob" || closed.ClosedReason != "com dono" {
		t.Errorf("closed record wrong: by=%q reason=%q", closed.ClosedBy, closed.ClosedReason)
	}
}

// Close must leave the record of the change intact — the approver (which the job's
// signature covers, so it must still verify), the delivery times and the agent's
// Result with its before/rollback_token — and add who/when/why it was closed. The
// same holds for what was persisted, not only for memory.
func TestClosePreservesTheApprovalAndTheResult(t *testing.T) {
	applied := Result{Status: "applied", Detail: "KB instalado", Before: "KB5040000", After: "KB5041580", RollbackToken: "rb-0123", RebootPending: true}
	failed := Result{Status: "failed", Detail: "reboot loop", Before: "KB5040000", After: "KB5040000", RollbackToken: "rb-0456"}
	for _, tc := range []struct {
		name  string
		build func(*testing.T, *Registry) *RemediationJob
		want  *Result // the job's Result before the close; nil = none yet
	}{
		{"DELIVERED", func(t *testing.T, r *Registry) *RemediationJob { return jobIn(t, r, StateDelivered) }, nil},
		{"ACKED", func(t *testing.T, r *Registry) *RemediationJob { return jobIn(t, r, StateAcked) }, nil},
		{"APPLIED", func(t *testing.T, r *Registry) *RemediationJob { return reportedJob(t, r, applied) }, &applied},
		{"FAILED", func(t *testing.T, r *Registry) *RemediationJob { return reportedJob(t, r, failed) }, &failed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, key := testReg(t)
			r.now = at(clockBase)
			j := tc.build(t, r)
			before, _ := r.Get(j.JobID, "win1", "acme")
			closedAt := clockBase.Add(10 * time.Minute)
			r.now = at(closedAt)
			if _, err := r.Close(j.JobID, "bob", "agente fora do ar"); err != nil {
				t.Fatal(err)
			}

			check := func(where string, got *RemediationJob) {
				t.Helper()
				if got.State != StateClosed || got.ClosedBy != "bob" || got.ClosedReason != "agente fora do ar" || !got.ClosedAt.Equal(closedAt) {
					t.Errorf("%s: closed record wrong: state=%s by=%q reason=%q at=%v", where, got.State, got.ClosedBy, got.ClosedReason, got.ClosedAt)
				}
				if got.ApprovedBy != "op" || !got.ApprovedAt.Equal(before.ApprovedAt) || got.Signature != before.Signature {
					t.Errorf("%s: the approval was not preserved: by=%q at=%v", where, got.ApprovedBy, got.ApprovedAt)
				}
				if !Verify(got, key.Public()) {
					t.Errorf("%s: the signature of the approved change no longer verifies", where)
				}
				if !got.DeliveredAt.Equal(before.DeliveredAt) || !got.AckedAt.Equal(before.AckedAt) {
					t.Errorf("%s: delivery/ack times changed", where)
				}
				if tc.want == nil {
					if got.Result != nil {
						t.Errorf("%s: Close invented a result: %+v", where, got.Result)
					}
					return
				}
				sameResult(t, where, got.Result, *tc.want)
				if got.Result != nil && !got.Result.ReportedAt.Equal(before.Result.ReportedAt) {
					t.Errorf("%s: reported_at changed", where)
				}
			}
			got, _ := r.Get(j.JobID, "win1", "acme")
			check("memory", got)
			disk, ok := onDisk(t, r).Get(j.JobID, "win1", "acme")
			if !ok {
				t.Fatal("the closed job is missing from the file")
			}
			check("disk", disk)
		})
	}
}

// A write that fails leaves nothing half-done: the job goes back to the state it was
// in (not to a fixed one), memory agrees with the file, the caller gets the error,
// and since nothing changed nothing is audited. The failure was the write's alone:
// once it is fixed the very same close goes through.
func TestCloseRevertsWhenTheWriteFails(t *testing.T) {
	for _, st := range []JobState{StateDelivered, StateAcked, StateApplied, StateFailed} {
		t.Run(string(st), func(t *testing.T) {
			logs := captureLog(t)
			r, _ := testReg(t)
			j := jobIn(t, r, st)
			failSaves(t, r)
			got, err := r.Close(j.JobID, "bob", "agente fora do ar")
			if err == nil {
				t.Fatal("Close must report the failed write")
			}
			if errors.Is(err, ErrInvalidState) || errors.Is(err, ErrNotFound) {
				t.Errorf("a failed write is neither a state nor a not-found error: %v", err)
			}
			if got != nil {
				t.Errorf("a failed Close returned a job: %+v", got)
			}
			mem, _ := r.Get(j.JobID, "win1", "acme")
			if mem.State != st || mem.ClosedBy != "" || !mem.ClosedAt.IsZero() || mem.ClosedReason != "" {
				t.Errorf("memory was not reverted to %s: %+v", st, mem)
			}
			if disk, _ := onDisk(t, r).Get(j.JobID, "win1", "acme"); disk.State != st {
				t.Errorf("memory (%s) and file (%s) disagree", mem.State, disk.State)
			}
			if lines := linesWith(logs, "fechado por"); len(lines) != 0 {
				t.Errorf("a close that did not happen was audited: %q", lines)
			}

			if err := os.Remove(r.path + ".tmp"); err != nil {
				t.Fatal(err)
			}
			if _, err := r.Close(j.JobID, "bob", "agente fora do ar"); err != nil {
				t.Fatalf("after the write is fixed the same close must go through: %v", err)
			}
			if got := stateOf(t, r, j.JobID); got != StateClosed {
				t.Errorf("state after the retry = %s, want CLOSED", got)
			}
		})
	}
}

// Every effective close writes ONE audit line — who, why, the state it was in, the
// approver of the change, the tenant and the agent. A close that changed nothing
// (refused state, unknown id) writes none.
func TestCloseLogsOneAuditLinePerEffectiveClose(t *testing.T) {
	logs := captureLog(t)
	r, _ := testReg(t)
	j := jobIn(t, r, StateAcked) // approved by "op"
	if _, err := r.Close(j.JobID, "bob", "agente fora do ar"); err != nil {
		t.Fatal(err)
	}
	lines := linesWith(logs, "fechado por")
	if len(lines) != 1 {
		t.Fatalf("want exactly 1 audit line for the close, got %d: %q", len(lines), lines)
	}
	for _, want := range []string{
		j.JobID, `fechado por "bob"`, "estado anterior ACKED", `aprovador "op"`, `motivo "agente fora do ar"`, `tenant="acme"`, `agent="win1"`,
	} {
		if !strings.Contains(lines[0], want) {
			t.Errorf("the audit line should contain %q: %s", want, lines[0])
		}
	}

	if _, err := r.Close(j.JobID, "mallory", ""); !errors.Is(err, ErrInvalidState) { // already CLOSED
		t.Fatalf("second close: err = %v, want ErrInvalidState", err)
	}
	if _, err := r.Close("nao-existe", "mallory", ""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown id: err = %v, want ErrNotFound", err)
	}
	approved := jobIn(t, r, StateApproved) // never delivered: Reject's job, not Close's
	if _, err := r.Close(approved.JobID, "mallory", ""); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("close of an APPROVED job: err = %v, want ErrInvalidState", err)
	}
	if n := len(linesWith(logs, "fechado por")); n != 1 {
		t.Errorf("a close that changed nothing must not log (%d lines): %q", n, linesWith(logs, "fechado por"))
	}
}

// The operator, the reason, the tenant and the agent come from outside (the request
// body, the enqueue request): they are logged quoted, so none of them can start a
// line of its own in the audit trail.
func TestCloseAuditLineQuotesTheValuesItLogs(t *testing.T) {
	logs := captureLog(t)
	r, _ := testReg(t)
	evil := "x\nremediation: job fake aprovado por \"mallory\""
	j, err := r.Enqueue(EnqueueRequest{
		Tenant: evil, AgentID: evil, Type: TypePackagePatch, Payload: json.RawMessage(`{}`), TTL: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Approve(j.JobID, evil); err != nil {
		t.Fatal(err)
	}
	if _, ok := r.Poll(evil, evil); !ok {
		t.Fatal("poll must deliver the approved job")
	}
	start := len(logs.String())
	if _, err := r.Close(j.JobID, evil, evil); err != nil {
		t.Fatal(err)
	}
	if out := logs.String()[start:]; strings.Count(out, "\n") != 1 {
		t.Errorf("the audit entry must be ONE line, got: %q", out)
	}
}

// reports the late-report tests use: the agent's Result for an applied and a failed run.
var (
	appliedRun = Result{Status: "applied", Detail: "KB instalado", Before: "KB5040000", After: "KB5041580", RollbackToken: "rb-0123", RebootPending: true}
	failedRun  = Result{Status: "failed", Detail: "reboot loop", Before: "KB5040000", After: "KB5040000", RollbackToken: "rb-0456"}
)

// closedFrom drives a fresh job to st and has an operator close it.
func closedFrom(t *testing.T, r *Registry, st JobState) *RemediationJob {
	t.Helper()
	j := jobIn(t, r, st)
	if _, err := r.Close(j.JobID, "bob", "teste"); err != nil {
		t.Fatal(err)
	}
	return j
}

// finalWithResult builds the final jobs that hold the agent's Result, each with the
// Result it holds.
var finalWithResult = []struct {
	name  string
	res   Result
	build func(*testing.T, *Registry, Result) *RemediationJob
}{
	{"FAILED", failedRun, func(t *testing.T, r *Registry, res Result) *RemediationJob { return reportedJob(t, r, res) }},
	{"VERIFIED", appliedRun, func(t *testing.T, r *Registry, res Result) *RemediationJob {
		j := reportedJob(t, r, res)
		if _, err := r.MarkVerified(j.JobID); err != nil {
			t.Fatal(err)
		}
		return j
	}},
	{"CLOSED after APPLIED", appliedRun, func(t *testing.T, r *Registry, res Result) *RemediationJob {
		j := reportedJob(t, r, res)
		if _, err := r.Close(j.JobID, "bob", "teste"); err != nil {
			t.Fatal(err)
		}
		return j
	}},
	{"CLOSED after FAILED", failedRun, func(t *testing.T, r *Registry, res Result) *RemediationJob {
		j := reportedJob(t, r, res)
		if _, err := r.Close(j.JobID, "bob", "teste"); err != nil {
			t.Fatal(err)
		}
		return j
	}},
}

// finalWithoutResult builds the final jobs that never got a Result: the agent's
// report, if one comes now, is the first and only word on what happened to the host.
var finalWithoutResult = []struct {
	name  string
	build func(*testing.T, *Registry) *RemediationJob
}{
	{"REJECTED", func(t *testing.T, r *Registry) *RemediationJob { return jobIn(t, r, StateRejected) }},
	{"EXPIRED", func(t *testing.T, r *Registry) *RemediationJob { return jobIn(t, r, StateExpired) }},
	{"CLOSED after DELIVERED", func(t *testing.T, r *Registry) *RemediationJob { return closedFrom(t, r, StateDelivered) }},
	{"CLOSED after ACKED", func(t *testing.T, r *Registry) *RemediationJob { return closedFrom(t, r, StateAcked) }},
}

// The agent may deliver the same report twice (a retry after a lost answer). On a
// final job that already holds exactly that result it is an idempotent success: no
// error, no log, nothing rewritten. The agent's own reported_at does not count — the
// stored one is the server's stamp.
func TestLateReportIdenticalToTheStoredOneIsIdempotent(t *testing.T) {
	for _, tc := range finalWithResult {
		t.Run(tc.name, func(t *testing.T) {
			logs := captureLog(t)
			r, _ := testReg(t)
			r.now = at(clockBase)
			j := tc.build(t, r, tc.res)
			before, _ := r.Get(j.JobID, "win1", "acme")
			logged := logs.String()

			retry := tc.res
			retry.ReportedAt = clockBase.Add(time.Hour)
			r.now = at(clockBase.Add(2 * time.Hour))
			if err := r.Report(j.JobID, "win1", "acme", &retry); err != nil {
				t.Fatalf("identical late report: %v", err)
			}
			after, _ := r.Get(j.JobID, "win1", "acme")
			if after.State != before.State {
				t.Errorf("state %s -> %s", before.State, after.State)
			}
			sameResult(t, "stored result", after.Result, tc.res)
			if !after.Result.ReportedAt.Equal(before.Result.ReportedAt) {
				t.Errorf("reported_at rewritten: %v -> %v", before.Result.ReportedAt, after.Result.ReportedAt)
			}
			if got := logs.String(); got != logged {
				t.Errorf("an idempotent retry must not log: %q", got[len(logged):])
			}
		})
	}
}

// Anything else reported on a final job is NOT a retry: the agent says it did
// something the queue no longer expects (applied a rejected/expired/closed job, or
// contradicts what it reported before). It is refused (ErrInvalidState), the recorded
// Result is never overwritten, and ONE audit line tells the operator which job, in
// which state, got which report. "Else" includes a report that matches the stored one
// in status and detail but differs in anything else the agent supplied.
func TestLateReportDifferentFromTheStoredOneIsRefusedAndAudited(t *testing.T) {
	flip := func(s string) string {
		if s == "applied" {
			return "failed"
		}
		return "applied"
	}
	for _, tc := range finalWithResult {
		for _, v := range []struct {
			name string
			edit func(*Result)
		}{
			{"status", func(x *Result) { x.Status = flip(x.Status) }},
			{"detail", func(x *Result) { x.Detail = "outro-detalhe" }},
			{"rollback_token", func(x *Result) { x.RollbackToken = "rb-outro" }},
			{"after", func(x *Result) { x.After = "KB9999999" }},
		} {
			t.Run(tc.name+"/"+v.name, func(t *testing.T) {
				logs := captureLog(t)
				r, _ := testReg(t)
				r.now = at(clockBase)
				j := tc.build(t, r, tc.res)
				before, _ := r.Get(j.JobID, "win1", "acme")
				logged := logs.String()

				late := tc.res
				v.edit(&late)
				err := r.Report(j.JobID, "win1", "acme", &late)
				if !errors.Is(err, ErrInvalidState) {
					t.Fatalf("different late report: err = %v, want ErrInvalidState", err)
				}
				after, _ := r.Get(j.JobID, "win1", "acme")
				if after.State != before.State {
					t.Errorf("state %s -> %s", before.State, after.State)
				}
				sameResult(t, "stored result", after.Result, tc.res)
				if !after.Result.ReportedAt.Equal(before.Result.ReportedAt) {
					t.Errorf("reported_at rewritten")
				}

				out := logs.String()[len(logged):]
				if strings.Count(out, "\n") != 1 {
					t.Fatalf("want exactly 1 audit line, got %q", out)
				}
				for _, want := range []string{j.JobID, "relatório tardio", string(before.State), `"` + late.Status + `"`, `tenant="acme"`, `agent="win1"`} {
					if !strings.Contains(out, want) {
						t.Errorf("the audit line should contain %q: %s", want, out)
					}
				}
				// The agent's free text and the rollback handle stay out of the log.
				for _, secret := range []string{late.Detail, late.RollbackToken, late.After} {
					if secret != "" && strings.Contains(out, secret) {
						t.Errorf("the audit line must not carry the agent's %q: %s", secret, out)
					}
				}
			})
		}
	}
}

// A job that never got a Result and is final (rejected, expired or closed before the
// agent reported) must not swallow a report: the agent applied — or tried — something
// the queue had already dropped. Same answer and same single audit line, and the job
// stays exactly as it was.
func TestLateReportOnAFinalJobWithoutResultIsRefusedAndAudited(t *testing.T) {
	for _, tc := range finalWithoutResult {
		for _, status := range []string{"applied", "failed"} {
			t.Run(tc.name+"/"+status, func(t *testing.T) {
				logs := captureLog(t)
				r, _ := testReg(t)
				j := tc.build(t, r)
				before, _ := r.Get(j.JobID, "win1", "acme")
				logged := logs.String()

				err := r.Report(j.JobID, "win1", "acme", &Result{Status: status, Detail: "x", After: "patched", RollbackToken: "rb-77"})
				if !errors.Is(err, ErrInvalidState) {
					t.Fatalf("late report: err = %v, want ErrInvalidState", err)
				}
				after, _ := r.Get(j.JobID, "win1", "acme")
				if after.State != before.State || after.Result != nil {
					t.Errorf("the refused report changed the job: state %s -> %s, result %+v", before.State, after.State, after.Result)
				}
				out := logs.String()[len(logged):]
				if strings.Count(out, "\n") != 1 {
					t.Fatalf("want exactly 1 audit line, got %q", out)
				}
				for _, want := range []string{j.JobID, "relatório tardio", string(before.State), `"` + status + `"`, `tenant="acme"`, `agent="win1"`} {
					if !strings.Contains(out, want) {
						t.Errorf("the audit line should contain %q: %s", want, out)
					}
				}
				if strings.Contains(out, "rb-77") {
					t.Errorf("the audit line must not carry the rollback handle: %s", out)
				}
			})
		}
	}
}

// What the audit line says comes from the agent (the reported status) and from the
// enqueue request (tenant, agent): all logged quoted, so none starts a line of its own.
func TestLateReportAuditLineQuotesTheValuesItLogs(t *testing.T) {
	logs := captureLog(t)
	r, _ := testReg(t)
	evil := "x\nremediation: job fake aprovado por \"mallory\""
	j, err := r.Enqueue(EnqueueRequest{
		Tenant: evil, AgentID: evil, Type: TypePackagePatch, Payload: json.RawMessage(`{}`), TTL: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Reject(j.JobID, "op"); err != nil {
		t.Fatal(err)
	}
	start := len(logs.String())
	if err := r.Report(j.JobID, evil, evil, &Result{Status: evil}); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("err = %v, want ErrInvalidState", err)
	}
	if out := logs.String()[start:]; strings.Count(out, "\n") != 1 {
		t.Errorf("the audit entry must be ONE line, got: %q", out)
	}
}

// APPLIED is not final: it keeps the rules it always had. A repeated report is
// accepted silently — even a contradictory one — and never rewrites the recorded
// Result or the state.
func TestReportOnAppliedJobKeepsTheCurrentRules(t *testing.T) {
	logs := captureLog(t)
	r, _ := testReg(t)
	r.now = at(clockBase)
	j := reportedJob(t, r, appliedRun)
	logged := logs.String()

	for _, late := range []Result{appliedRun, {Status: "failed", After: "WIPED"}} {
		if err := r.Report(j.JobID, "win1", "acme", &late); err != nil {
			t.Fatalf("repeated report on an APPLIED job: %v", err)
		}
	}
	after, _ := r.Get(j.JobID, "win1", "acme")
	if after.State != StateApplied {
		t.Errorf("state = %s, want APPLIED", after.State)
	}
	sameResult(t, "stored result", after.Result, appliedRun)
	if got := logs.String(); got != logged {
		t.Errorf("a repeated report on an APPLIED job must not log: %q", got[len(logged):])
	}
}

// A report is scoped to the job's own agent and tenant — whatever the state, the
// answer to anyone else is "not found" and nothing is audited — and it is only valid
// after delivery: a job nobody handed out has nothing to report.
func TestReportOfAForeignOrUndeliveredJobIsNotFound(t *testing.T) {
	for _, st := range lifecycle {
		t.Run(string(st), func(t *testing.T) {
			logs := captureLog(t)
			r, _ := testReg(t)
			j := jobIn(t, r, st)
			before, _ := r.Get(j.JobID, "win1", "acme")
			logged := logs.String()
			for _, who := range [][2]string{{"winB", "acme"}, {"win1", "globex"}} {
				if err := r.Report(j.JobID, who[0], who[1], &Result{Status: "applied"}); !errors.Is(err, ErrNotFound) {
					t.Errorf("report by %v: err = %v, want ErrNotFound", who, err)
				}
			}
			if st == StatePendingApproval || st == StateApproved {
				if err := r.Report(j.JobID, "win1", "acme", &Result{Status: "applied"}); !errors.Is(err, ErrNotFound) {
					t.Errorf("report of a never-delivered %s job: err = %v, want ErrNotFound", st, err)
				}
			}
			after, _ := r.Get(j.JobID, "win1", "acme")
			if after.State != before.State || (before.Result == nil) != (after.Result == nil) {
				t.Errorf("a refused report changed the job: %s -> %s", before.State, after.State)
			}
			if got := logs.String(); got != logged {
				t.Errorf("a report that found no job must not log: %q", got[len(logged):])
			}
		})
	}
}

// CLOSED is final: it never comes back to the agent — a DELIVERED job past the
// redeliver window would have — and the janitor reaps it like the other final states.
func TestClosedJobIsFinal(t *testing.T) {
	r, _ := testReg(t)
	r.now = at(clockBase)
	j := jobIn(t, r, StateDelivered)
	if _, err := r.Close(j.JobID, "bob", ""); err != nil {
		t.Fatal(err)
	}
	r.now = at(clockBase.Add(30 * time.Minute)) // past the redeliver window, inside the TTL
	if _, ok := r.Poll("win1", "acme"); ok {
		t.Error("a CLOSED job must not be delivered again")
	}
	if got := stateOf(t, r, j.JobID); got != StateClosed {
		t.Errorf("state after the poll = %s, want CLOSED", got)
	}
	r.now = at(clockBase.Add(48 * time.Hour))
	if n := r.Reap(24 * time.Hour); n != 1 {
		t.Errorf("reap should drop the old CLOSED job, got %d", n)
	}
	if _, ok := r.Get(j.JobID, "win1", "acme"); ok {
		t.Error("reaped job still present")
	}
}
