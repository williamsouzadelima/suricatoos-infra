package remediate

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

// Outcome is the result of an executor Apply attempt.
type Outcome int

const (
	OutcomeApplied  Outcome = iota // the handler applied the change
	OutcomeFailed                  // a precheck or the handler failed (report FAILED)
	OutcomeDeferred                // before the maintenance window — retry later, do NOT ack
	OutcomeSkipped                 // already applied (idempotent; a redelivered job)
)

func (o Outcome) String() string {
	switch o {
	case OutcomeApplied:
		return "applied"
	case OutcomeFailed:
		return "failed"
	case OutcomeDeferred:
		return "deferred"
	case OutcomeSkipped:
		return "skipped"
	default:
		return "unknown"
	}
}

// Handler applies ONE kind of remediation. Implementations live in OS-specific
// files (WUA/winget/registry) added in a later, LAB-gated slice; they MUST be
// idempotent (a no-op when already in the desired state) and SHOULD capture prior
// state into Result.Before for rollback/audit. THIS slice ships NO real handler —
// only the orchestrator and a fake used in tests, so nothing writes to the OS.
type Handler interface {
	Type() Type
	Apply(ctx context.Context, j *Job) (*Result, error)
}

// Executor runs a signature-verified job through three POLICY gates before it can
// touch the OS — single-flight, idempotency (journal), and the maintenance window
// — then dispatches to the Handler registered for the job's Type. The Executor
// itself never writes to the OS; the Handler does.
//
// Authenticity is NOT its job: the caller MUST have verified the job
// (PollJob/VerifyAt) first. Apply assumes a genuine, approved job and enforces
// WHEN and WHETHER it may run: never twice, never outside the window, never an
// unsupported type, never two at once.
type Executor struct {
	mu       sync.Mutex
	stateDir string
	handlers map[Type]Handler
	now      func() time.Time
	journal  *journal
}

// NewExecutor builds an Executor persisting its idempotency journal under
// stateDir and serving the given handlers (one per Type).
func NewExecutor(stateDir string, handlers ...Handler) *Executor {
	e := &Executor{
		stateDir: stateDir,
		handlers: make(map[Type]Handler, len(handlers)),
		now:      time.Now,
		journal:  loadJournal(stateDir),
	}
	for _, h := range handlers {
		e.handlers[h.Type()] = h
	}
	return e
}

// Apply runs job j through the gates and its handler, returning the outcome and
// (for Applied/Failed) the Result to report to the control-plane. On Deferred and
// Skipped the Result is nil (nothing to report yet / already done).
func (e *Executor) Apply(ctx context.Context, j *Job) (Outcome, *Result, error) {
	e.mu.Lock() // single-flight: never two applies at once, nor one during another
	defer e.mu.Unlock()

	if j == nil || j.JobID == "" {
		return OutcomeFailed, nil, errors.New("job vazio")
	}
	// Idempotency: a redelivered-but-already-applied job is a no-op (lost ack).
	if e.journal.appliedOK(j.JobID) {
		return OutcomeSkipped, nil, nil
	}
	now := e.now()
	// Maintenance window (approval-per-action): never act before it opens; after it
	// closes the approval no longer holds, so refuse rather than apply late.
	if !j.NotBefore.IsZero() && now.Before(j.NotBefore) {
		return OutcomeDeferred, nil, nil
	}
	if !j.NotAfter.IsZero() && now.After(j.NotAfter) {
		return OutcomeFailed, &Result{
			Status:     StatusFailed,
			Detail:     "janela de manutenção expirou antes da aplicação",
			ReportedAt: now,
		}, nil
	}
	h, ok := e.handlers[j.Type]
	if !ok {
		return OutcomeFailed, &Result{
			Status:     StatusFailed,
			Detail:     fmt.Sprintf("tipo de remediação não suportado: %q", j.Type),
			ReportedAt: now,
		}, nil
	}

	res, err := h.Apply(ctx, j)
	if res == nil {
		res = &Result{}
	}
	if res.ReportedAt.IsZero() {
		res.ReportedAt = now
	}
	if err != nil {
		res.Status = StatusFailed
		if res.Detail == "" {
			res.Detail = err.Error()
		}
		e.journal.record(j.JobID, StatusFailed, now) // informational; FAILED stays retriable
		return OutcomeFailed, res, nil
	}
	res.Status = StatusApplied
	e.journal.record(j.JobID, StatusApplied, now) // terminal: suppresses re-apply
	return OutcomeApplied, res, nil
}
