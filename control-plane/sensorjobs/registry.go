package sensorjobs

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// ScopeLookup returns the authorized scope for a tenant (nil = unknown/deny-all).
type ScopeLookup func(tenant string) *Scope

// Registry is the persistent, tenant-partitioned scan-job queue. Modeled on
// ingest/scanlaunch's registry: serialized writes, atomic persist (temp+rename),
// unguessable ids, idempotent enqueue. Every poll/ack is authorized against the
// caller's cert O — a sensor never sees another tenant's jobs.
type Registry struct {
	mu         sync.Mutex
	path       string
	jobs       map[string]*ScanJob
	scopeOf    ScopeLookup
	cooldown   time.Duration
	redeliver  time.Duration
	defaultTTL time.Duration
	now        func() time.Time
}

// Config configures a Registry.
type Config struct {
	Path       string
	ScopeOf    ScopeLookup   // tenant → authorized scope (required for enqueue)
	Cooldown   time.Duration // collapse identical (tenant,targets,config) onto the still IN-FLIGHT job within this window (see Enqueue)
	Redeliver  time.Duration // a DELIVERED-but-unacked job becomes eligible again after this
	DefaultTTL time.Duration // job expiry when EnqueueRequest.TTL is 0
}

// NewRegistry loads the queue from cfg.Path (missing file = fresh).
func NewRegistry(cfg Config) (*Registry, error) {
	r := &Registry{
		path:       cfg.Path,
		jobs:       map[string]*ScanJob{},
		scopeOf:    cfg.ScopeOf,
		cooldown:   orDur(cfg.Cooldown, 30*time.Minute),
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
		return nil, fmt.Errorf("ler sensorjobs registry %s: %w", cfg.Path, err)
	}
	var list []*ScanJob
	if err := json.Unmarshal(b, &list); err != nil {
		return nil, fmt.Errorf("sensorjobs registry %s corrompido: %w", cfg.Path, err)
	}
	for _, j := range list {
		r.jobs[j.JobID] = j
	}
	return r, nil
}

// Enqueue dispatches a job for a tenant. It scope-gates the targets (dropping any
// outside the tenant's authorized scope), collapses an identical recent request
// onto the job that is still IN FLIGHT (non-terminal: idempotency/anti-storm — once
// that job is DONE or EXPIRED a new identical request creates a new job, i.e. a
// re-scan), and persists a PENDING job. Returns (nil, nil, err) when nothing is left
// in scope. dropped is the list of rejected targets (log it).
func (r *Registry) Enqueue(req EnqueueRequest) (job *ScanJob, dropped []string, err error) {
	if req.Tenant == "" {
		return nil, nil, fmt.Errorf("tenant obrigatório")
	}
	var scope *Scope
	if r.scopeOf != nil {
		scope = r.scopeOf(req.Tenant)
	}
	if scope == nil {
		scope = &Scope{} // deny-all: unknown tenant scans nothing
	}
	kept, dropped := scope.Gate(req.Targets)
	if len(kept) == 0 {
		return nil, dropped, fmt.Errorf("nenhum alvo dentro do escopo do tenant %q", req.Tenant)
	}
	sort.Strings(kept)

	r.mu.Lock()
	defer r.mu.Unlock()

	key := dedupKey(req.Tenant, kept, req.ScanConfig)
	cutoff := r.now().Add(-r.cooldown)
	for _, j := range r.jobs {
		if !j.State.terminal() && j.Tenant == req.Tenant && j.CreatedAt.After(cutoff) &&
			dedupKey(j.Tenant, j.Targets, j.ScanConfig) == key {
			return j.clone(), dropped, nil // idempotent replay / storm-collapse
		}
	}

	jid, err := randHex()
	if err != nil {
		return nil, dropped, err
	}
	cid, err := randHex()
	if err != nil {
		return nil, dropped, err
	}
	ttl := req.TTL
	if ttl <= 0 {
		ttl = r.defaultTTL
	}
	now := r.now().UTC()
	nj := &ScanJob{
		SchemaVersion: SchemaVersion,
		JobID:         jid,
		CorrelationID: cid,
		Tenant:        req.Tenant,
		Source:        req.Source,
		Targets:       kept,
		Ports:         req.Ports,
		ScanConfig:    req.ScanConfig,
		AliveTest:     req.AliveTest,
		MaxDuration:   req.MaxDuration,
		State:         StatePending,
		CreatedAt:     now,
		ExpiresAt:     now.Add(ttl),
	}
	r.reapLocked(defaultReapRetention) // bound growth: drop old terminal jobs
	r.jobs[jid] = nj
	if err := r.saveLocked(); err != nil {
		delete(r.jobs, jid)
		return nil, dropped, err
	}
	return nj.clone(), dropped, nil
}

// defaultReapRetention is how long terminal jobs (DONE, EXPIRED) are kept before
// the reaper drops them. Same window as the remediation queue.
const defaultReapRetention = 7 * 24 * time.Hour

// Reap removes terminal jobs (DONE, EXPIRED) older than retention (by CreatedAt;
// <= 0 means defaultReapRetention), bounding the queue file's growth, and returns
// the count removed. Non-terminal jobs are never touched, however old. Called
// opportunistically from Enqueue — the same point where the remediation queue
// reaps; the wiring may also call it on a timer.
func (r *Registry) Reap(retention time.Duration) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := r.reapLocked(retention)
	if n > 0 {
		if err := r.saveLocked(); err != nil {
			log.Printf("sensorjobs: saveLocked após reap: %v", err)
		}
	}
	return n
}

// reapLocked deletes terminal jobs older than retention (caller holds the lock,
// caller persists). Returns the count removed.
func (r *Registry) reapLocked(retention time.Duration) int {
	if retention <= 0 {
		retention = defaultReapRetention
	}
	cutoff := r.now().Add(-retention)
	n := 0
	for id, j := range r.jobs {
		if j.State.terminal() && j.CreatedAt.Before(cutoff) {
			delete(r.jobs, id)
			n++
		}
	}
	return n
}

// Poll returns the next deliverable job for a sensor of tenant o (FIFO by
// CreatedAt), marking it DELIVERED. Eligible = PENDING, or DELIVERED-but-unacked
// past the redeliver window (sensor crashed before ack). Expired jobs are swept.
// Returns (nil, false) when the tenant has nothing to do.
func (r *Registry) Poll(o string) (*ScanJob, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now().UTC()

	var eligible []*ScanJob
	changed := false
	for _, j := range r.jobs {
		if j.Tenant != o || j.State.terminal() {
			continue
		}
		if !j.ExpiresAt.IsZero() && now.After(j.ExpiresAt) {
			j.State = StateExpired
			changed = true
			continue
		}
		if !j.NotBefore.IsZero() && now.Before(j.NotBefore) {
			continue
		}
		switch j.State {
		case StatePending:
			eligible = append(eligible, j)
		case StateDelivered:
			if now.Sub(j.DeliveredAt) > r.redeliver {
				eligible = append(eligible, j)
			}
		}
	}
	sort.Slice(eligible, func(i, j int) bool { return eligible[i].CreatedAt.Before(eligible[j].CreatedAt) })

	if len(eligible) == 0 {
		if changed {
			if err := r.saveLocked(); err != nil {
				log.Printf("sensorjobs: saveLocked após sweep de expiração: %v", err)
			}
		}
		return nil, false
	}
	next := eligible[0]
	next.State = StateDelivered
	next.DeliveredAt = now
	// Se a gravação falhou, o job segue entregue (se o control-plane reiniciar antes
	// de uma gravação que dê certo, ele volta ao estado gravado e é reentregue;
	// repetir um scan é seguro), mas a falha não é silenciosa. O log leva só o id do
	// job e o erro — nunca os alvos.
	if err := r.saveLocked(); err != nil {
		log.Printf("sensorjobs: saveLocked após poll job=%s: %v", next.JobID, err)
	}
	return next.clone(), true
}

// Ack marks a job DONE, but ONLY if it belongs to tenant o (owner scope). An
// unknown id or a foreign tenant returns false (no cross-tenant ack; no
// enumeration).
//
// DONE, not ACKED: the sensor acks only AFTER it ran the scan and pushed its
// report (sensor/internal/supervisor.pollOnce) — on a crash or a failed push it
// does not ack and the job is redelivered — so an ack means "concluded". AckedAt
// records when. StateAcked is no longer assigned (legacy records still carry it).
//
// A sensor can only conclude a job it actually received: DELIVERED (or a legacy
// ACKED record) becomes DONE, keeping an AckedAt that is already set; a PENDING job
// was never handed out, so its ack is a no-op that returns false. Final jobs are
// left as-is and answer true (idempotent: a repeated ack keeps the first AckedAt,
// and an EXPIRED job stays EXPIRED).
func (r *Registry) Ack(jobID, o string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	j, ok := r.jobs[jobID]
	if !ok || j.Tenant != o {
		return false
	}
	switch j.State {
	case StatePending:
		return false
	case StateDelivered, StateAcked:
		j.State = StateDone
		if j.AckedAt.IsZero() {
			j.AckedAt = r.now().UTC()
		}
		// Se a gravação falhou o job segue DONE na memória (o sensor já empurrou o
		// relatório), mas a falha não é silenciosa — só o id do job e o erro vão ao log.
		if err := r.saveLocked(); err != nil {
			log.Printf("sensorjobs: saveLocked após ack job=%s: %v", jobID, err)
		}
	}
	return true
}

// Get returns a clone of a job scoped to tenant o (foreign/unknown → false).
func (r *Registry) Get(jobID, o string) (*ScanJob, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	j, ok := r.jobs[jobID]
	if !ok || j.Tenant != o {
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
	State JobState
	Limit int // <= 0 → defaultListLimit; capped at maxListLimit
}

// List returns clones of tenant o's jobs matching f — newest first (CreatedAt
// desc; the job id breaks a tie so the order is stable) and at most f.Limit of
// them — plus how many matched before the cut, so a caller can tell the listing
// was truncated. Like every other operation here it is partitioned by tenant: a
// foreign tenant's job is never returned, and an empty o matches NOTHING (never
// "all tenants").
func (r *Registry) List(o string, f ListFilter) (jobs []*ScanJob, total int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var match []*ScanJob
	if o != "" {
		for _, j := range r.jobs {
			if j.Tenant != o || (f.State != "" && j.State != f.State) {
				continue
			}
			match = append(match, j)
		}
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
	jobs = make([]*ScanJob, 0, len(match))
	for _, j := range match {
		jobs = append(jobs, j.clone())
	}
	return jobs, total
}

func (r *Registry) saveLocked() error {
	if r.path == "" {
		return nil
	}
	list := make([]*ScanJob, 0, len(r.jobs))
	for _, j := range r.jobs {
		list = append(list, j)
	}
	b, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	tmp := r.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, r.path)
}

func dedupKey(tenant string, targets []string, config string) string {
	sorted := append([]string(nil), targets...)
	sort.Strings(sorted)
	h := sha256.Sum256([]byte(tenant + "\x00" + strings.Join(sorted, ",") + "\x00" + config))
	return hex.EncodeToString(h[:])
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
