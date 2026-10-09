package remediation

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"sync"
	"time"
)

// ErrNotFound is returned when a job id is unknown (or out of the caller's scope).
var ErrNotFound = errors.New("job não encontrado")

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
		r.jobs[j.JobID] = j
	}
	return r, nil
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
// PENDING_APPROVAL can be approved.
func (r *Registry) Approve(jobID, approver string) (*RemediationJob, error) {
	if approver == "" {
		return nil, fmt.Errorf("aprovador obrigatório")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	j, ok := r.jobs[jobID]
	if !ok {
		return nil, ErrNotFound
	}
	if j.State != StatePendingApproval {
		return nil, fmt.Errorf("job %s não está em PENDING_APPROVAL (estado %s)", jobID, j.State)
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

// Reject terminally rejects a job (records who). Idempotent on terminal jobs.
func (r *Registry) Reject(jobID, approver string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	j, ok := r.jobs[jobID]
	if !ok {
		return ErrNotFound
	}
	if j.State.terminal() {
		return nil
	}
	j.State = StateRejected
	j.ApprovedBy = approver
	j.ApprovedAt = r.now().UTC()
	return r.saveLocked()
}

// Poll returns the next deliverable job for the agent identified by (agentID,
// tenant) — FIFO by CreatedAt — marking it DELIVERED. Eligible = APPROVED, or
// DELIVERED-but-unacked past the redeliver window. Jobs outside their
// maintenance window are held; expired jobs are swept. A job for a DIFFERENT
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
		if !j.ExpiresAt.IsZero() && now.After(j.ExpiresAt) {
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
			_ = r.saveLocked()
		}
		return nil, false
	}
	next := eligible[0]
	next.State = StateDelivered
	next.DeliveredAt = now
	_ = r.saveLocked()
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
		_ = r.saveLocked()
	}
	return true
}

// Report records the agent's apply result, moving the job to APPLIED (status
// "applied") or FAILED (anything else). Scoped to (agentID, tenant). Terminal
// jobs are left as-is (idempotent). APPLIED is NOT terminal — the server still
// must verify by re-scan.
func (r *Registry) Report(jobID, agentID, tenant string, res *Result) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	j, ok := r.jobs[jobID]
	if !ok || j.AgentID != agentID || j.Tenant != tenant {
		return false
	}
	if j.State.terminal() {
		return true
	}
	if res == nil {
		res = &Result{Status: "failed", Detail: "relatório vazio"}
	}
	res.ReportedAt = r.now().UTC()
	j.Result = res
	if res.Status == "applied" {
		j.State = StateApplied
	} else {
		j.State = StateFailed
	}
	_ = r.saveLocked()
	return true
}

// MarkVerified moves an APPLIED job to VERIFIED. This is SERVER-SIDE only (called
// after a re-scan confirms the fix) — the agent can never set it. A job not in
// APPLIED is left unchanged.
func (r *Registry) MarkVerified(jobID string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	j, ok := r.jobs[jobID]
	if !ok {
		return false
	}
	if j.State == StateApplied {
		j.State = StateVerified
		_ = r.saveLocked()
	}
	return true
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

func (r *Registry) saveLocked() error {
	if r.path == "" {
		return nil
	}
	list := make([]*RemediationJob, 0, len(r.jobs))
	for _, j := range r.jobs {
		list = append(list, j)
	}
	// json.Marshal (NOT MarshalIndent): Indent re-formats the embedded payload
	// RawMessage, which would change its bytes and break payload_sha256 (and thus
	// the signature) on reload. Compact output keeps the payload byte-stable.
	b, err := json.Marshal(list)
	if err != nil {
		return err
	}
	tmp := r.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
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
