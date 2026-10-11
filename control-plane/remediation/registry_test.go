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
	if !r.Report(j.JobID, "win1", "acme", &Result{Status: "applied", After: "patched"}) {
		t.Fatal("report failed")
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
	if r.Report(j.JobID, "win1", "acme", &Result{Status: "applied"}) {
		t.Error("report before delivery must be rejected")
	}
	r.Poll("win1", "acme") // → DELIVERED (ACK is optional for Report)
	if !r.Report(j.JobID, "win1", "acme", &Result{Status: "applied", After: "patched"}) {
		t.Fatal("report after delivery must succeed")
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

// jobIn enqueues a win1/acme job (1h TTL, at the registry's current clock) and
// drives it to st through the real transitions — Approve, Poll, Ack, Report — never
// by poking State, so the tests exercise the production path. st is one of
// PENDING_APPROVAL, APPROVED, DELIVERED, ACKED, APPLIED, FAILED.
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
	if _, err := r.Approve(j.JobID, "op"); err != nil {
		t.Fatal(err)
	}
	if st == StateApproved {
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
	status := "applied"
	if st == StateFailed {
		status = "failed"
	}
	if !r.Report(j.JobID, "win1", "acme", &Result{Status: status, After: "patched"}) {
		t.Fatal("report failed")
	}
	return j
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

	if !r.Report(j.JobID, "win1", "acme", &Result{Status: "applied", After: "patched"}) {
		t.Fatal("a report for an ACKED job past ExpiresAt must be accepted")
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

// Reject overwrites ApprovedBy/ApprovedAt with whoever rejected, which would erase
// the approver of a signed (possibly applied) change. The audit log line is where
// the previous approver survives: exactly one line per EFFECTIVE rejection, none for
// a no-op.
func TestRejectLogsThePreviousApprover(t *testing.T) {
	logs := captureLog(t)
	rejectLines := func() []string {
		var out []string
		for _, l := range strings.Split(logs.String(), "\n") {
			if strings.Contains(l, "rejeitado por") {
				out = append(out, l)
			}
		}
		return out
	}

	r, _ := testReg(t)
	j := jobIn(t, r, StateApplied) // approved by "op" (jobIn), then delivered, acked and applied
	if err := r.Reject(j.JobID, "bob"); err != nil {
		t.Fatal(err)
	}
	lines := rejectLines()
	if len(lines) != 1 {
		t.Fatalf("want exactly 1 audit line for the rejection, got %d: %q", len(lines), lines)
	}
	for _, want := range []string{
		j.JobID, `rejeitado por "bob"`, `aprovador anterior "op"`, "estado anterior APPLIED", "tenant=acme", "agent=win1",
	} {
		if !strings.Contains(lines[0], want) {
			t.Errorf("the audit line should contain %q: %s", want, lines[0])
		}
	}

	// A no-op (already terminal) and an unknown id change nothing, so log nothing.
	if err := r.Reject(j.JobID, "mallory"); err != nil {
		t.Fatal(err)
	}
	if err := r.Reject("nao-existe", "mallory"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown id: err = %v, want ErrNotFound", err)
	}
	if n := len(rejectLines()); n != 1 {
		t.Errorf("a reject that changed nothing must not log (%d lines): %q", n, rejectLines())
	}

	// A job nobody approved has no previous approver: it is logged as "".
	p := jobIn(t, r, StatePendingApproval)
	if err := r.Reject(p.JobID, "alice"); err != nil {
		t.Fatal(err)
	}
	lines = rejectLines()
	if len(lines) != 2 {
		t.Fatalf("want 2 audit lines in total, got %d: %q", len(lines), lines)
	}
	for _, want := range []string{p.JobID, `rejeitado por "alice"`, `aprovador anterior ""`, "estado anterior PENDING_APPROVAL"} {
		if !strings.Contains(lines[1], want) {
			t.Errorf("the audit line should contain %q: %s", want, lines[1])
		}
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
