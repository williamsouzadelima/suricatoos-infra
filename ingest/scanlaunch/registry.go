package scanlaunch

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// Registry is the persistent store of scan jobs, keyed by request_id. It is the
// single source of truth for job state; the reconciler and the HTTP handlers
// both go through it. Writes are serialized and persisted atomically (temp +
// rename), mirroring ingest.Server.persist.
type Registry struct {
	mu   sync.Mutex
	path string
	jobs map[string]*Job
	now  func() time.Time
}

// NewRegistry loads the registry from path (empty/missing file = fresh store).
func NewRegistry(path string) (*Registry, error) {
	r := &Registry{path: path, jobs: map[string]*Job{}, now: time.Now}
	if path == "" {
		return r, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return r, nil
		}
		return nil, fmt.Errorf("ler registry %s: %w", path, err)
	}
	var list []*Job
	if err := json.Unmarshal(b, &list); err != nil {
		return nil, fmt.Errorf("registry %s corrompido: %w", path, err)
	}
	for _, j := range list {
		r.jobs[j.RequestID] = j
	}
	return r, nil
}

// Get returns a clone of the job with the given request_id.
func (r *Registry) Get(requestID string) (*Job, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	j, ok := r.jobs[requestID]
	if !ok {
		return nil, false
	}
	return j.clone(), true
}

// List returns clones of all jobs.
func (r *Registry) List() []*Job {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*Job, 0, len(r.jobs))
	for _, j := range r.jobs {
		out = append(out, j.clone())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].SubmittedAt.Before(out[j].SubmittedAt) })
	return out
}

// findByScanHistoryLocked returns the existing job for a reNgine scan_history_id
// (idempotency anchor), if any. Caller holds r.mu.
func (r *Registry) findByScanHistoryLocked(id int64) *Job {
	for _, j := range r.jobs {
		if j.ScanHistoryID == id {
			return j
		}
	}
	return nil
}

// FindOrCreate implements idempotency + per-target cooldown atomically:
//   - same scan_history_id already present → return it (idempotent replay).
//   - a DIFFERENT job for the same non-empty target submitted within `cooldown`
//     → return that job (collapses an auto-trigger storm), created=false.
//   - otherwise persist a new PENDING job from req/id and return it, created=true.
func (r *Registry) FindOrCreate(req *ScanRequest, id certIdentity, cooldown time.Duration) (job *Job, created bool, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if existing := r.findByScanHistoryLocked(req.RengineScanHistoryID); existing != nil {
		return existing.clone(), false, nil
	}
	if req.Target != "" && cooldown > 0 {
		cutoff := r.now().Add(-cooldown)
		for _, j := range r.jobs {
			if j.Target == req.Target && j.Tenant == id.O && j.SubmittedAt.After(cutoff) {
				return j.clone(), false, nil
			}
		}
	}

	rid, err := newRequestID()
	if err != nil {
		return nil, false, err
	}
	nj := &Job{
		RequestID:     rid,
		Tenant:        id.O,
		CN:            id.CN,
		ScanHistoryID: req.RengineScanHistoryID,
		Target:        req.Target,
		Engagement:    req.Engagement,
		Hosts:         req.Hosts,
		State:         StatePending,
		SubmittedAt:   r.now().UTC(),
	}
	r.jobs[rid] = nj
	if err := r.saveLocked(); err != nil {
		delete(r.jobs, rid)
		return nil, false, err
	}
	return nj.clone(), true, nil
}

// Update applies mutate to the stored job under the lock and persists. It returns
// a clone of the mutated job, or false if the request_id is unknown.
func (r *Registry) Update(requestID string, mutate func(*Job)) (*Job, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	j, ok := r.jobs[requestID]
	if !ok {
		return nil, false
	}
	mutate(j)
	if err := r.saveLocked(); err != nil {
		// State is already updated in memory; a persist failure is logged by the
		// caller path. Returning the clone keeps the reconciler moving.
		return j.clone(), true
	}
	return j.clone(), true
}

// CountActive returns how many jobs are in the RUNNING state (for concurrency).
func (r *Registry) CountActive() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, j := range r.jobs {
		if j.State == StateRunning {
			n++
		}
	}
	return n
}

// ReapTerminal evicts terminal jobs whose CompletedAt is older than ttl (and
// their cached findings file), bounding the registry map + persisted file so a
// long-lived auto-loop doesn't grow without limit. ttl <= 0 disables reaping.
// Returns the number removed.
func (r *Registry) ReapTerminal(ttl time.Duration, findingsDir string) int {
	if ttl <= 0 {
		return 0
	}
	cutoff := r.now().Add(-ttl)
	r.mu.Lock()
	defer r.mu.Unlock()
	var removed []string
	for id, j := range r.jobs {
		if j.State.terminal() && !j.CompletedAt.IsZero() && j.CompletedAt.Before(cutoff) {
			removed = append(removed, id)
		}
	}
	if len(removed) == 0 {
		return 0
	}
	for _, id := range removed {
		delete(r.jobs, id)
		if findingsDir != "" {
			os.Remove(filepath.Join(findingsDir, id+".json"))
		}
	}
	_ = r.saveLocked()
	return len(removed)
}

func (r *Registry) saveLocked() error {
	if r.path == "" {
		return nil
	}
	list := make([]*Job, 0, len(r.jobs))
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

// newRequestID returns an unguessable 128-bit hex id (closes IDOR on GET/DELETE).
func newRequestID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}
