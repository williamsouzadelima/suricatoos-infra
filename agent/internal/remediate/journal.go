package remediate

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// journalEntry records the outcome of applying a job. Keyed by job_id so a
// redelivered job (e.g. a lost ack) is not applied a second time.
type journalEntry struct {
	Status    string    `json:"status"` // StatusApplied | StatusFailed
	AppliedAt time.Time `json:"applied_at"`
}

// journal is the on-disk idempotency record (stateDir/remediation.journal.json):
// atomic JSON, 0600, read-tolerant — the same durability discipline as
// update.policyState. Only a successful APPLIED entry suppresses a re-apply; a
// FAILED entry leaves the job retriable.
type journal struct {
	mu   sync.Mutex
	path string
	m    map[string]journalEntry
}

func journalPath(stateDir string) string {
	return filepath.Join(stateDir, "remediation.journal.json")
}

func loadJournal(stateDir string) *journal {
	j := &journal{path: journalPath(stateDir), m: map[string]journalEntry{}}
	if b, err := os.ReadFile(j.path); err == nil {
		_ = json.Unmarshal(b, &j.m) // corrupt/absent → empty journal (fail-open to retry, never to double-apply)
	}
	return j
}

// appliedOK reports whether jobID already APPLIED successfully, so the executor
// skips it. A missing or FAILED entry returns false (safe to attempt).
func (j *journal) appliedOK(jobID string) bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	e, ok := j.m[jobID]
	return ok && e.Status == StatusApplied
}

// record persists the outcome for jobID (atomic tmp+rename; best-effort — a write
// failure is non-fatal, at worst re-applying an idempotent handler).
func (j *journal) record(jobID, status string, at time.Time) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.m[jobID] = journalEntry{Status: status, AppliedAt: at}
	if b, err := json.Marshal(j.m); err == nil {
		tmp := j.path + ".tmp"
		if os.WriteFile(tmp, b, 0o600) == nil {
			_ = os.Rename(tmp, j.path)
		}
	}
}
