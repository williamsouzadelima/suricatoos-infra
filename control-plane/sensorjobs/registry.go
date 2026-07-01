package sensorjobs

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
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
	Cooldown   time.Duration // collapse identical (tenant,targets,config) within this window
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
// (idempotency/anti-storm), and persists a PENDING job. Returns (nil, nil, err)
// when nothing is left in scope. dropped is the list of rejected targets (log it).
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
	r.jobs[jid] = nj
	if err := r.saveLocked(); err != nil {
		delete(r.jobs, jid)
		return nil, dropped, err
	}
	return nj.clone(), dropped, nil
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

// Ack marks a job ACKED, but ONLY if it belongs to tenant o (owner scope). An
// unknown id or a foreign tenant returns false (no cross-tenant ack; no
// enumeration). Terminal jobs are left as-is (idempotent).
func (r *Registry) Ack(jobID, o string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	j, ok := r.jobs[jobID]
	if !ok || j.Tenant != o {
		return false
	}
	if !j.State.terminal() {
		j.State = StateAcked
		j.AckedAt = r.now().UTC()
		_ = r.saveLocked()
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
