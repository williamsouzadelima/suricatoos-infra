package remediate

import (
	"context"
	"crypto/ed25519"
	"log"
	"net/http"
	"time"
)

// applier is the executor seam the Runner drives (satisfied by *Executor). Kept an
// interface so the loop logic is unit-tested without a real executor or the OS.
type applier interface {
	Apply(ctx context.Context, j *Job) (Outcome, *Result, error)
}

// jobSource is the control-plane seam: fetch the next verified job and report
// back. The production adapter wraps PollJob/AckJob/ReportJob; tests fake it.
type jobSource interface {
	poll(ctx context.Context) (*Job, error)
	ack(ctx context.Context, jobID string) error
	report(ctx context.Context, jobID string, res *Result) error
}

// Runner ties the control-plane job channel to the executor: it polls ONE verified
// job, runs it through the executor's gates + handler, and reports the outcome. It
// is the agent-side counterpart of the cloud queue lifecycle
// (DELIVERED→ACKED→APPLIED/FAILED). Authenticity is enforced in poll (PollJob
// verifies inline, fail-closed); WHEN/WHETHER to apply is the executor's job; the
// Runner only maps outcome → ack/report.
type Runner struct {
	src  jobSource
	exec applier
	now  func() time.Time
}

// NewRunner builds the production Runner: it polls serverURL (the enrolled
// control-plane base ending in /agent/v1) over the mTLS client hc, verifies with
// pub (the remediation key pinned at enroll), and drives exec. skew is the
// freshness tolerance passed to verification.
func NewRunner(hc *http.Client, serverURL string, pub ed25519.PublicKey, exec *Executor, skew time.Duration) *Runner {
	now := time.Now
	return &Runner{
		src:  &httpJobSource{hc: hc, serverURL: serverURL, pub: pub, now: now, skew: skew},
		exec: exec,
		now:  now,
	}
}

// RunOnce polls at most one job and processes it. No pending job — or a job that
// fails verification — is a no-op for this tick. A poll/report error is returned
// for the caller to log; the control-plane redelivers unacked jobs, so a transient
// failure is retried on the next tick.
func (r *Runner) RunOnce(ctx context.Context) error {
	job, err := r.src.poll(ctx)
	if err != nil {
		return err // includes fail-closed verification errors: nothing is acted on
	}
	if job == nil {
		return nil // nothing approved for us
	}
	outcome, res, err := r.exec.Apply(ctx, job)
	if err != nil {
		return err
	}
	switch outcome {
	case OutcomeDeferred:
		// Before the maintenance window: do NOT ack or report. The cloud redelivers
		// the unacked job; the executor keeps deferring until the window opens.
		return nil
	case OutcomeSkipped:
		// Already applied (a redelivered job whose ack/report was lost). Re-report
		// APPLIED so the cloud advances to re-scan→VERIFIED instead of redelivering
		// forever. Honest: Skipped means the journal recorded a prior success.
		res = &Result{Status: StatusApplied, ReportedAt: r.now(), Detail: "idempotente: job já aplicado anteriormente"}
	case OutcomeApplied, OutcomeFailed:
		if res == nil { // defensive: the executor sets a Result for both
			res = &Result{Status: StatusFailed, ReportedAt: r.now(), Detail: "resultado ausente do executor"}
		}
	}
	// Accept (hygiene; report also works from DELIVERED) then report. An ack failure
	// is non-fatal — the report still advances the job past DELIVERED.
	if err := r.src.ack(ctx, job.JobID); err != nil {
		log.Printf("remediação: ack %s falhou (seguindo p/ report): %v", job.JobID, err)
	}
	return r.src.report(ctx, job.JobID, res)
}

// Loop runs RunOnce on a fixed cadence until ctx is cancelled. Errors are logged
// and retried next tick.
func (r *Runner) Loop(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if err := r.RunOnce(ctx); err != nil {
			log.Printf("remediação: %v", err)
		}
	}
}

// httpJobSource is the production jobSource backed by the client.go HTTP calls.
type httpJobSource struct {
	hc        *http.Client
	serverURL string
	pub       ed25519.PublicKey
	now       func() time.Time
	skew      time.Duration
}

func (s *httpJobSource) poll(ctx context.Context) (*Job, error) {
	return PollJob(ctx, s.hc, s.serverURL, s.pub, s.now(), s.skew)
}

func (s *httpJobSource) ack(ctx context.Context, id string) error {
	return AckJob(ctx, s.hc, s.serverURL, id)
}

func (s *httpJobSource) report(ctx context.Context, id string, res *Result) error {
	return ReportJob(ctx, s.hc, s.serverURL, id, res)
}
