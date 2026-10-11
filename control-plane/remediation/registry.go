package remediation

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// ErrNotFound is returned when a job id is unknown (or out of the caller's scope).
var ErrNotFound = errors.New("job não encontrado")

// ErrInvalidState is returned (wrapped, with the details) when the job exists but
// its state does not allow the requested transition. The HTTP layer maps it to 409.
var ErrInvalidState = errors.New("estado do job não permite a operação")

// Registry is the persistent, approval-gated remediation queue. Modeled on
// sensorjobs' registry (serialized writes, atomic temp+rename persist,
// unguessable ids) but adds the human-approval gate and per-job signing, and
// scopes every agent operation to BOTH the agent_id (CN) and tenant (O).
type Registry struct {
	mu         sync.Mutex
	path       string
	jobs       map[string]*RemediationJob
	signer     Signer
	redeliver  time.Duration
	defaultTTL time.Duration
	now        func() time.Time
}

// Config configures a Registry.
type Config struct {
	Path       string
	Signer     Signer        // signs a job's canonical on Approve (required to approve)
	Redeliver  time.Duration // a DELIVERED-but-unacked job becomes eligible again after this
	DefaultTTL time.Duration // job expiry when EnqueueRequest.TTL is 0
}

// NewRegistry loads the queue from cfg.Path (missing file = fresh).
func NewRegistry(cfg Config) (*Registry, error) {
	r := &Registry{
		path:       cfg.Path,
		jobs:       map[string]*RemediationJob{},
		signer:     cfg.Signer,
		redeliver:  orDur(cfg.Redeliver, 5*time.Minute),
		defaultTTL: orDur(cfg.DefaultTTL, 24*time.Hour),
		now:        time.Now,
	}
	if cfg.Path == "" {
		return r, nil
	}
	b, err := os.ReadFile(cfg.Path)
	if err != nil {
		if os.IsNotExist(err) {
			return r, nil
		}
		return nil, fmt.Errorf("ler remediation registry %s: %w", cfg.Path, err)
	}
	var list []*RemediationJob
	if err := json.Unmarshal(b, &list); err != nil {
		return nil, fmt.Errorf("remediation registry %s corrompido: %w", cfg.Path, err)
	}
	for _, j := range list {
		// Defense-in-depth against a tampered/corrupt state file: a job in a
		// post-approval state MUST carry a signature (Approve set it). One that
		// doesn't is incoherent — drop it rather than let a future server-side
		// consumer that trusts State skip the approval gate. (The agent already
		// rejects an unsigned job, so this never weakens the agent path.)
		if requiresSignature(j.State) && j.Signature == "" {
			log.Printf("remediation: job %s em %s sem assinatura no load — descartado (estado incoerente)", j.JobID, j.State)
			continue
		}
		r.jobs[j.JobID] = j
	}
	return r, nil
}

// requiresSignature reports whether a job state can only have been reached via
// Approve (which signs); such a state with an empty signature is incoherent.
func requiresSignature(s JobState) bool {
	switch s {
	case StateApproved, StateDelivered, StateAcked, StateApplied, StateVerified:
		return true
	}
	return false
}

// defaultReapRetention is how long terminal jobs are kept before Reap drops them.
const defaultReapRetention = 7 * 24 * time.Hour

// Reap removes terminal jobs whose last event is older than retention — the last of the
// job's creation, rejection, closure, result and refused reports, see lastEventAt, so
// that closing an old job or a late report restarts the clock — bounding the queue
// file's growth, and returns the count removed. Called opportunistically from Enqueue;
// the wiring may also call it on a timer.
//
// Only TERMINAL states go (VERIFIED, FAILED, EXPIRED, REJECTED, CLOSED). ACKED and
// APPLIED are not terminal and, since Poll no longer expires them by ExpiresAt,
// NOTHING here removes them: an ACKED job leaves that state when the agent reports
// (→ APPLIED/FAILED) or an operator closes it (→ CLOSED), an APPLIED one when an
// operator marks it verified (→ VERIFIED) or closes it. A job stuck there (agent
// gone, nobody verifies it) stays in the queue until one of those happens — there
// is deliberately no age-based policy for them yet.
func (r *Registry) Reap(retention time.Duration) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := r.reapLocked(retention)
	if n > 0 {
		if err := r.saveLocked(); err != nil {
			log.Printf("remediation: saveLocked após reap: %v", err)
		}
	}
	return n
}

// reapLocked deletes terminal jobs whose last event (see lastEventAt) is older than
// retention (caller holds the lock, caller persists). Returns the count removed.
func (r *Registry) reapLocked(retention time.Duration) int {
	if retention <= 0 {
		retention = defaultReapRetention
	}
	cutoff := r.now().Add(-retention)
	n := 0
	for id, j := range r.jobs {
		if j.State.terminal() && j.lastEventAt().Before(cutoff) {
			delete(r.jobs, id)
			n++
		}
	}
	return n
}

// Enqueue creates a PENDING_APPROVAL job. It is NOT signed and NOT deliverable
// until Approve. The payload is hashed into payload_sha256 and a single-use
// nonce is assigned, both of which the signature will later bind.
func (r *Registry) Enqueue(req EnqueueRequest) (*RemediationJob, error) {
	if req.Tenant == "" || req.AgentID == "" {
		return nil, fmt.Errorf("tenant e agent_id obrigatórios")
	}
	if !req.Type.valid() {
		return nil, fmt.Errorf("tipo de remediação inválido: %q", req.Type)
	}
	// Canonicalize the payload (compact) so payload_sha256 — and thus the
	// signature — is stable across persistence and independent of the submitter's
	// whitespace. It must be valid JSON (it is also re-emitted verbatim on save).
	if len(req.Payload) == 0 {
		return nil, fmt.Errorf("payload obrigatório")
	}
	var pbuf bytes.Buffer
	if err := json.Compact(&pbuf, req.Payload); err != nil {
		return nil, fmt.Errorf("payload deve ser JSON válido: %w", err)
	}
	payload := append(json.RawMessage(nil), pbuf.Bytes()...)
	jid, err := randHex()
	if err != nil {
		return nil, err
	}
	cid, err := randHex()
	if err != nil {
		return nil, err
	}
	nonce, err := randHex()
	if err != nil {
		return nil, err
	}
	ttl := req.TTL
	if ttl <= 0 {
		ttl = r.defaultTTL
	}
	now := r.now().UTC()
	j := &RemediationJob{
		SchemaVersion: SchemaVersion,
		JobID:         jid,
		CorrelationID: cid,
		Tenant:        req.Tenant,
		AgentID:       req.AgentID,
		Type:          req.Type,
		Payload:       payload,
		PayloadSHA256: ComputePayloadSHA256(payload),
		Nonce:         nonce,
		State:         StatePendingApproval,
		NotBefore:     req.NotBefore.UTC(),
		NotAfter:      req.NotAfter.UTC(),
		ExpiresAt:     now.Add(ttl),
		CreatedAt:     now,
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.reapLocked(defaultReapRetention) // bound growth: drop old terminal jobs
	r.jobs[jid] = j
	if err := r.saveLocked(); err != nil {
		delete(r.jobs, jid)
		return nil, err
	}
	return j.clone(), nil
}

// Approve records the operator's approval, sets issued_at, SIGNS the canonical
// (binding agent/tenant/type/issued_at/expires_at/nonce/payload), and moves the
// job to APPROVED — the first state in which it is deliverable. Only a job in
// PENDING_APPROVAL can be approved: an unknown id is ErrNotFound, any other state is
// ErrInvalidState (and the job is left alone). Everything else — a missing signer, a
// write that fails (which undoes the approval in memory) — is a plain error: the
// server's problem, not a conflict with the job's state.
func (r *Registry) Approve(jobID, approver string) (*RemediationJob, error) {
	if blank(approver) {
		return nil, fmt.Errorf("aprovador obrigatório")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	j, ok := r.jobs[jobID]
	if !ok {
		return nil, ErrNotFound
	}
	if j.State != StatePendingApproval {
		return nil, fmt.Errorf("%w: job %s não está em PENDING_APPROVAL (estado %s)", ErrInvalidState, jobID, j.State)
	}
	if r.signer == nil {
		return nil, fmt.Errorf("signer de remediação não configurado")
	}
	now := r.now().UTC()
	j.IssuedAt = now
	j.ApprovedBy = approver
	j.ApprovedAt = now
	j.State = StateApproved
	j.Signature = Sign(j, r.signer) // issued_at/nonce/expires_at already set → covered
	if err := r.saveLocked(); err != nil {
		j.State = StatePendingApproval
		j.Signature, j.ApprovedBy = "", ""
		j.IssuedAt, j.ApprovedAt = time.Time{}, time.Time{}
		return nil, err
	}
	return j.clone(), nil
}

// Reject terminally rejects a job that the agent has NOT received yet — only
// PENDING_APPROVAL or APPROVED qualify — and records who in RejectedBy/RejectedAt.
// The approval (ApprovedBy/ApprovedAt, which the job's signature covers) is left
// exactly as it was.
//
// A job that is already REJECTED is a quiet success (a double click, a retried
// request): there is nothing to do, so nothing changes — the first rejecter and time
// stay on record — and nothing is audited. Any other existing job is ErrInvalidState
// and is left alone: one the agent holds (DELIVERED, ACKED, APPLIED, FAILED) may be
// applying, or may already have applied, a change, and "rejected" would be false about
// it — Close is the operation for taking it out of the queue. An unknown id is
// ErrNotFound. A write that fails undoes the change in memory (as Approve does) and
// returns the error. Every effective rejection writes ONE audit line, values quoted.
func (r *Registry) Reject(jobID, rejecter string) error {
	if blank(rejecter) {
		return fmt.Errorf("operador obrigatório")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	j, ok := r.jobs[jobID]
	if !ok {
		return ErrNotFound
	}
	if j.State == StateRejected {
		return nil
	}
	if j.State != StatePendingApproval && j.State != StateApproved {
		hint := "" // suggest close only where close would work
		if closable(j.State) {
			hint = "; um job já entregue ao agente se fecha com close"
		}
		return fmt.Errorf("%w: job %s não pode ser rejeitado em %s (só PENDING_APPROVAL ou APPROVED%s)", ErrInvalidState, jobID, j.State, hint)
	}
	prevState := j.State
	j.State = StateRejected
	j.RejectedBy, j.RejectedAt = rejecter, r.now().UTC()
	if err := r.saveLocked(); err != nil {
		j.State = prevState
		j.RejectedBy, j.RejectedAt = "", time.Time{}
		return err
	}
	log.Printf("remediation: job %s rejeitado por %q (estado anterior %s; aprovador %q em %s; tenant=%q agent=%q)",
		jobID, rejecter, prevState, j.ApprovedBy, whenOrDash(j.ApprovedAt), j.Tenant, j.AgentID)
	return nil
}

// maxCloseReason caps the reason given to Close, in bytes: it goes into the audit line and
// onto the job, so a longer one is refused instead of bloating either.
const maxCloseReason = 1024

// Close takes a job the agent has already received out of the queue without saying
// anything untrue about it: a DELIVERED, ACKED, APPLIED or FAILED job becomes CLOSED,
// recording WHO closed it, WHEN and (optionally) WHY, and everything else stays as it
// was — the approver (the job's signature covers it), the delivery times and the
// agent's Result with its before/rollback_token.
//
// This is what Reject cannot do. Reject is for a job nobody has received; a job in the
// agent's hands may be applying, or may already have applied, a change. Closing it
// stops the redelivery but claims nothing about the host: the change, if there was
// one, is checked and reverted by hand (rollback_token). Any other existing state is
// ErrInvalidState and the job is left alone; an unknown id is ErrNotFound; a write
// that fails undoes the change in memory (as Approve does) and returns the error.
// Every effective close writes ONE audit line, values quoted.
func (r *Registry) Close(jobID, closer, reason string) (*RemediationJob, error) {
	if blank(closer) {
		return nil, fmt.Errorf("operador obrigatório")
	}
	if len(reason) > maxCloseReason {
		return nil, fmt.Errorf("motivo muito longo (%d bytes; no máximo %d)", len(reason), maxCloseReason)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	j, ok := r.jobs[jobID]
	if !ok {
		return nil, ErrNotFound
	}
	if !closable(j.State) {
		return nil, fmt.Errorf("%w: job %s não pode ser fechado em %s (só DELIVERED, ACKED, APPLIED ou FAILED)", ErrInvalidState, jobID, j.State)
	}
	prevState := j.State
	j.State = StateClosed
	j.ClosedBy, j.ClosedAt, j.ClosedReason = closer, r.now().UTC(), reason
	if err := r.saveLocked(); err != nil {
		j.State = prevState
		j.ClosedBy, j.ClosedAt, j.ClosedReason = "", time.Time{}, ""
		return nil, err
	}
	log.Printf("remediation: job %s fechado por %q (estado anterior %s; aprovador %q em %s; motivo %q; tenant=%q agent=%q)",
		jobID, closer, prevState, j.ApprovedBy, whenOrDash(j.ApprovedAt), reason, j.Tenant, j.AgentID)
	return j.clone(), nil
}

// closable reports whether Close accepts a job in state s: the ones the agent holds.
func closable(s JobState) bool {
	switch s {
	case StateDelivered, StateAcked, StateApplied, StateFailed:
		return true
	}
	return false
}

// blank reports whether who names no one — empty or only whitespace. approve, reject and
// close refuse such an operator themselves, so the audit trail never says "by nobody"
// even for a caller that skipped the handler's check.
func blank(who string) bool { return strings.TrimSpace(who) == "" }

// whenOrDash renders t for an audit line: UTC RFC3339, or "-" when it was never set.
func whenOrDash(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.UTC().Format(time.RFC3339)
}

// Poll returns the next deliverable job for the agent identified by (agentID,
// tenant) — FIFO by CreatedAt — marking it DELIVERED. Eligible = APPROVED, or
// DELIVERED-but-unacked past the redeliver window. Jobs outside their
// maintenance window are held. Jobs whose ExpiresAt lapsed BEFORE the agent took
// them (PENDING_APPROVAL, APPROVED, DELIVERED-unacked) are swept to EXPIRED; an
// ACKED or APPLIED job is never expired here (see JobState.expirable), so a late
// Report still lands and an applied job stays verifiable. A job for a DIFFERENT
// agent or tenant is never returned.
func (r *Registry) Poll(agentID, tenant string) (*RemediationJob, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now().UTC()

	var eligible []*RemediationJob
	changed := false
	for _, j := range r.jobs {
		if j.AgentID != agentID || j.Tenant != tenant || j.State.terminal() {
			continue
		}
		if j.State.expirable() && !j.ExpiresAt.IsZero() && now.After(j.ExpiresAt) {
			j.State = StateExpired
			changed = true
			continue
		}
		if !j.NotBefore.IsZero() && now.Before(j.NotBefore) {
			continue // maintenance window not open yet
		}
		if !j.NotAfter.IsZero() && now.After(j.NotAfter) {
			continue // window closed — wait for expiry or operator action
		}
		switch j.State {
		case StateApproved:
			eligible = append(eligible, j)
		case StateDelivered:
			if now.Sub(j.DeliveredAt) > r.redeliver {
				eligible = append(eligible, j)
			}
		}
	}
	sort.Slice(eligible, func(i, k int) bool { return eligible[i].CreatedAt.Before(eligible[k].CreatedAt) })

	if len(eligible) == 0 {
		if changed {
			if err := r.saveLocked(); err != nil {
				log.Printf("remediation: saveLocked após sweep de expiração: %v", err)
			}
		}
		return nil, false
	}
	next := eligible[0]
	prevState, prevDelivered := next.State, next.DeliveredAt
	next.State = StateDelivered
	next.DeliveredAt = now
	if err := r.saveLocked(); err != nil {
		// Não conseguimos persistir a entrega: reverte para memória e disco
		// concordarem e NUNCA entregar um job que não ficou durável como DELIVERED
		// (ele re-entregaria no restart). O agente não recebe nada neste poll e tenta de novo.
		next.State, next.DeliveredAt = prevState, prevDelivered
		log.Printf("remediation: saveLocked após poll job=%s (revertido): %v", next.JobID, err)
		return nil, false
	}
	return next.clone(), true
}

// Ack marks a DELIVERED job ACKED (the agent accepted it and will apply). Scoped
// to (agentID, tenant); a foreign/unknown id returns false (no cross-host ack).
func (r *Registry) Ack(jobID, agentID, tenant string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	j, ok := r.jobs[jobID]
	if !ok || j.AgentID != agentID || j.Tenant != tenant {
		return false
	}
	if j.State == StateDelivered {
		j.State = StateAcked
		j.AckedAt = r.now().UTC()
		if err := r.saveLocked(); err != nil {
			log.Printf("remediation: saveLocked após ack job=%s: %v", jobID, err)
		}
	}
	return true
}

// Report records the agent's apply result, moving the job to APPLIED (status
// "applied") or FAILED (anything else). Scoped to (agentID, tenant): a foreign or
// unknown id is ErrNotFound, silently. So is a job the agent was never handed
// (DeliveredAt unset: pending, approved, or rejected or expired before the poll
// delivered it), which has nothing to report — but that one is logged, on a line of its
// own ("relatório de job nunca entregue"), and nothing is kept.
//
// A job the agent was handed that already holds its result — a FINAL one (VERIFIED,
// FAILED, EXPIRED, REJECTED, CLOSED, the last three possibly without any) or APPLIED,
// which is not final (the server still verifies by re-scan) but whose result is on
// record all the same — takes no other. If the report is exactly the one it holds — a
// retry — it is an idempotent success. Anything else is a late report the queue can no
// longer honour: the agent applied (or says it tried) something on a job that was
// closed or expired, or contradicts what it reported before. That is ErrInvalidState
// (409, so the agent is told too); the stored Result and the state stay untouched; ONE
// audit line records the job, its state, the status reported and the report's number
// ("late_report #n") — the operator has to know a change may have reached a host — and
// the report itself is kept WHOLE in LateReports (the first one, pinned, and the two
// most recent, persisted), because its before/rollback_token are the only copy of how
// to revert it: the audit line stays at status and state, the operator reads the rest
// on the job. A report equal to one already kept gets the very same 409 and nothing
// else: not stored again, not written, not audited again.
func (r *Registry) Report(jobID, agentID, tenant string, res *Result) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	j, ok := r.jobs[jobID]
	if !ok || j.AgentID != agentID || j.Tenant != tenant {
		return ErrNotFound
	}
	if res == nil {
		res = &Result{Status: "failed", Detail: "relatório vazio"}
	}
	// The agent can only report on a job it was handed. One it never received (still
	// pending or approved, or rejected or expired before the poll delivered it) is not a
	// late report — keeping it would lend such a claim an air of legitimacy — but it is
	// not silent either: the agent is reporting on something it was never given.
	if j.DeliveredAt.IsZero() {
		log.Printf("remediation: relatório de job nunca entregue: job %s está %s e o agente reportou %q (tenant=%q agent=%q)",
			jobID, j.State, res.Status, j.Tenant, j.AgentID)
		return ErrNotFound
	}
	if j.State == StateApplied || j.State.terminal() {
		if j.Result != nil && sameReport(*j.Result, *res) {
			return nil
		}
		// A report the job already keeps is answered like the first time — same 409,
		// naming the kept one — and stored, written and audited no second time: a
		// retrying or hostile agent cannot push the genuine reports out of the three.
		if i := j.lateReportIndex(*res); i >= 0 {
			return fmt.Errorf("%w: job %s está %s e não aceita mais relatório (reportado %q; guardado como late_report #%d)", ErrInvalidState, jobID, j.State, res.Status, j.lateReportNumber(i))
		}
		n := recordLateReport(j, *res, r.now().UTC())
		log.Printf("remediation: relatório tardio recusado: job %s está %s e o agente reportou %q (late_report #%d; tenant=%q agent=%q)",
			jobID, j.State, res.Status, n, j.Tenant, j.AgentID)
		// The refusal stands whatever the disk says, and the kept report is NOT undone
		// on a failed write: it is the only copy of what the agent did, and the next
		// persist that works carries it to disk.
		if err := r.saveLocked(); err != nil {
			log.Printf("remediation: saveLocked após relatório recusado job=%s: %v", jobID, err)
		}
		return fmt.Errorf("%w: job %s está %s e não aceita mais relatório (reportado %q; guardado como late_report #%d)", ErrInvalidState, jobID, j.State, res.Status, n)
	}
	// Only a job the agent holds takes a first report (DELIVERED, or ACKED). Defensive:
	// one that was handed out yet sits in any other state — a hand-edited or corrupt
	// queue file — is not trusted either (404).
	if j.State != StateDelivered && j.State != StateAcked {
		return ErrNotFound
	}
	res.ReportedAt = r.now().UTC()
	j.Result = res
	if res.Status == "applied" {
		j.State = StateApplied
	} else {
		j.State = StateFailed
	}
	if err := r.saveLocked(); err != nil {
		log.Printf("remediation: saveLocked após report job=%s: %v", jobID, err)
	}
	return nil
}

// maxLateReports is how many refused reports a job keeps: the FIRST one, pinned for
// good — it is usually the genuine "applied", with the real before/rollback_token — and
// the most recent ones, which rotate. A report's size is bounded by the 256 KiB cap on
// the request body (before/rollback_token are never truncated), so a job holds at most
// three of them however an agent behaves.
const maxLateReports = 3

// recordLateReport keeps a copy of a refused report on j, stamped with the time it
// arrived (the agent's own reported_at is not trusted any more than a first report's
// is), and returns the report's number among those stored for j: 1, 2, 3, ... Beyond
// maxLateReports the oldest of the rotating ones is dropped — never the first, which is
// pinned as #1. The number never repeats within a run, even after a report is dropped,
// so a "late_report #n" in the log names one report (see RemediationJob.lateReportNumber
// for finding it, and the runbook for the one case where a number can repeat: a crash
// between a refused report and the next persist that works).
func recordLateReport(j *RemediationJob, res Result, at time.Time) int {
	res.ReportedAt = at
	j.LateReports = append(j.LateReports, res)
	if len(j.LateReports) > maxLateReports {
		kept := make([]Result, 0, maxLateReports)
		kept = append(kept, j.LateReports[0])
		kept = append(kept, j.LateReports[len(j.LateReports)-(maxLateReports-1):]...)
		j.LateReports = kept
	}
	j.LateReportsTotal++
	return j.LateReportsTotal
}

// sameReport reports whether a and b carry the same content from the agent.
// ReportedAt is the server's own stamp, so it does not count; every other field does.
// Comparing the structs keeps a field added to Result later in the comparison by
// default (and fails to compile if it makes Result incomparable) instead of letting
// it be ignored.
func sameReport(a, b Result) bool {
	a.ReportedAt, b.ReportedAt = time.Time{}, time.Time{}
	return a == b
}

// MarkVerified moves an APPLIED job to VERIFIED and returns it. This is
// SERVER-SIDE only (an operator route, after a re-scan confirms the fix) — the
// agent can never set it. APPLIED is the only state that qualifies: any other
// existing job is left unchanged and gets ErrInvalidState (a FAILED job must not
// be resurrected, a VERIFIED one is not verified twice); an unknown id gets
// ErrNotFound. APPLIED never expires by ExpiresAt, so a slow re-scan can still
// close it.
func (r *Registry) MarkVerified(jobID string) (*RemediationJob, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	j, ok := r.jobs[jobID]
	if !ok {
		return nil, ErrNotFound
	}
	if j.State != StateApplied {
		return nil, fmt.Errorf("%w: job %s não está em APPLIED (estado %s)", ErrInvalidState, jobID, j.State)
	}
	j.State = StateVerified
	if err := r.saveLocked(); err != nil {
		j.State = StateApplied // memory and disk must agree
		return nil, err
	}
	return j.clone(), nil
}

// Get returns a clone of a job scoped to (agentID, tenant) — foreign/unknown → false.
func (r *Registry) Get(jobID, agentID, tenant string) (*RemediationJob, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	j, ok := r.jobs[jobID]
	if !ok || j.AgentID != agentID || j.Tenant != tenant {
		return nil, false
	}
	return j.clone(), true
}

// Listing bounds: a status listing is never unbounded.
const (
	defaultListLimit = 200
	maxListLimit     = 1000
)

// clampLimit maps a requested page size to the effective one: n <= 0 means "not
// given" (the default); anything above the cap is cut to the cap.
func clampLimit(n int) int {
	if n <= 0 {
		return defaultListLimit
	}
	return min(n, maxListLimit)
}

// ListFilter narrows List; a zero field matches everything.
type ListFilter struct {
	State   JobState
	Tenant  string
	AgentID string
	Limit   int // <= 0 → defaultListLimit; capped at maxListLimit
}

// List returns clones of the jobs matching f — newest first (CreatedAt desc; the
// job id breaks a tie so the order is stable) and at most f.Limit of them — plus
// how many matched before the cut, so a caller can tell the listing was truncated.
//
// This is an operator view across ALL tenants and agents: unlike Get it is not
// scoped to one agent's identity, so only a bearer-gated route may expose it. The
// clones carry the full payload; the HTTP layer decides what to show.
func (r *Registry) List(f ListFilter) (jobs []*RemediationJob, total int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var match []*RemediationJob
	for _, j := range r.jobs {
		if (f.State != "" && j.State != f.State) ||
			(f.Tenant != "" && j.Tenant != f.Tenant) ||
			(f.AgentID != "" && j.AgentID != f.AgentID) {
			continue
		}
		match = append(match, j)
	}
	sort.Slice(match, func(a, b int) bool {
		if !match[a].CreatedAt.Equal(match[b].CreatedAt) {
			return match[a].CreatedAt.After(match[b].CreatedAt)
		}
		return match[a].JobID < match[b].JobID
	})
	total = len(match)
	if limit := clampLimit(f.Limit); len(match) > limit {
		match = match[:limit]
	}
	jobs = make([]*RemediationJob, 0, len(match))
	for _, j := range match {
		jobs = append(jobs, j.clone())
	}
	return jobs, total
}

func (r *Registry) saveLocked() error {
	if r.path == "" {
		return nil
	}
	list := make([]*RemediationJob, 0, len(r.jobs))
	for _, j := range r.jobs {
		list = append(list, j)
	}
	// Persist WITHOUT HTML-escaping and WITHOUT indenting: both would rewrite the
	// embedded payload RawMessage's bytes (indent reflows it; the default
	// json.Marshal escapes <,>,& to </>/&) and diverge them from the
	// json.Compact bytes that payload_sha256 — and thus the signature — was computed
	// over. A config_hardening payload full of <,>,& (XML, rules) would then fail to
	// verify after a control-plane restart (silent, fail-closed, but real). Encoding
	// with SetEscapeHTML(false) keeps the payload byte-stable across the round-trip.
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(list); err != nil {
		return err
	}
	tmp := r.path + ".tmp"
	if err := os.WriteFile(tmp, buf.Bytes(), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, r.path)
}

func randHex() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

func orDur(d, def time.Duration) time.Duration {
	if d > 0 {
		return d
	}
	return def
}
