// Package commands implements the agent command channel: an operator enqueues a
// command (e.g. "scan_now") for an agent, the agent polls for it over its mTLS
// channel, runs it (an immediate local re-collect + report), and acks it.
//
// This is the outbound-only "scan on demand" path: the agent always initiates
// (poll), so no inbound listener is added — consistent with the passive-agent
// design (PLAN.md sec.5 lists rescan as a control-plane command).
//
// The queue holds at most one live command per agent — a fresh request supersedes
// the previous one — and keeps a short per-agent history so an operator can tell
// what became of a request. A command moves PENDING → DELIVERED (a poll handed it
// to the agent) → ACKED (the agent confirmed it ran), or ends SUPERSEDED (replaced
// by a newer request) or EXPIRED (older than the TTL without an ack).
//
// By default the queue lives in memory only: a control-plane restart drops what is
// pending, which is tolerable for an on-demand action but silent. Open with a
// Config.Path makes it durable: every change is written atomically to a JSON file
// (0600, temp+rename) that is reloaded at boot.
package commands

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sync"
	"time"
)

// CmdScanNow re-runs the agent's local inventory collection now (NOT a network
// scan — the agent stays passive/local-only).
const CmdScanNow = "scan_now"

const (
	// DefaultTTL is how long a PENDING/DELIVERED command stays deliverable.
	DefaultTTL = 24 * time.Hour
	// HistoryLimit is how many commands are kept per agent, the live one included.
	HistoryLimit = 20

	// fileVersion is the state file schema version.
	fileVersion = 1
)

// State is a command's place in its lifecycle.
type State string

const (
	// StatePending: queued, not yet handed to the agent.
	StatePending State = "PENDING"
	// StateDelivered: a poll handed it to the agent; no ack yet. It is handed out
	// again on every poll until acked or expired, so an agent that crashed before
	// acking still runs it. Only ACKED proves the agent processed it.
	StateDelivered State = "DELIVERED"
	// StateAcked: the agent confirmed it processed the command.
	StateAcked State = "ACKED"
	// StateSuperseded: replaced by a newer request before it was acked.
	StateSuperseded State = "SUPERSEDED"
	// StateExpired: older than the TTL without an ack; no longer delivered.
	StateExpired State = "EXPIRED"
)

// live reports whether the command can still be delivered or acked.
func (s State) live() bool { return s == StatePending || s == StateDelivered }

func (s State) valid() bool {
	switch s {
	case StatePending, StateDelivered, StateAcked, StateSuperseded, StateExpired:
		return true
	}
	return false
}

// Command is a single queued instruction for an agent. It is exactly what an agent
// receives from GET /v1/commands — the lifecycle lives in Record, not here, so the
// agent contract stays {id,type,created_at}.
type Command struct {
	ID        string    `json:"id"`
	Type      string    `json:"type"`
	CreatedAt time.Time `json:"created_at"`
}

// Record is a Command plus where it is in its lifecycle: one entry of an agent's
// history, and one record of the state file. Times that have not happened yet are
// zero (and omitted from the JSON).
type Record struct {
	Command
	State       State     `json:"state"`
	DeliveredAt time.Time `json:"delivered_at,omitzero"` // first delivery
	AckedAt     time.Time `json:"acked_at,omitzero"`
	// UpdatedAt is when the command entered its current state. For EXPIRED it is the
	// deadline (created_at + TTL) rather than when the expiry was noticed.
	UpdatedAt time.Time `json:"updated_at"`
}

// Config configures a Queue.
type Config struct {
	Path string        // JSON state file; "" keeps the queue in memory only
	TTL  time.Duration // a live command older than this expires; <=0 → DefaultTTL
}

// fileFormat is the state file: every agent's history, oldest first.
type fileFormat struct {
	Version int                 `json:"version"`
	Agents  map[string][]Record `json:"agents"`
}

// Queue is a concurrency-safe per-agent command queue, optionally persisted.
//
// Per agent it keeps a history, oldest first. There is at most one live
// (PENDING/DELIVERED) command and, when there is, it is the newest record. Expiry
// is lazy: every call first closes the agent's commands that outlived the TTL.
type Queue struct {
	mu     sync.Mutex
	path   string // "" = in memory only
	ttl    time.Duration
	agents map[string][]Record
	now    func() time.Time
	logf   func(format string, args ...any)
}

// NewQueue returns an empty in-memory queue (nothing is written to disk).
func NewQueue() *Queue { return newQueue(Config{}) }

func newQueue(cfg Config) *Queue {
	ttl := cfg.TTL
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	return &Queue{
		path:   cfg.Path,
		ttl:    ttl,
		agents: make(map[string][]Record),
		now:    time.Now,
		logf:   log.Printf,
	}
}

// Open returns a queue configured by cfg. With a Path it loads the state file
// (missing = fresh; unreadable or corrupt = error, the file is left untouched) and
// writes it back once, so an unwritable path fails here at boot instead of on the
// first operator request.
func Open(cfg Config) (*Queue, error) {
	q := newQueue(cfg)
	if q.path == "" {
		return q, nil
	}
	if err := q.load(); err != nil {
		return nil, err
	}
	// q is not shared yet, so no lock is needed around the save.
	if err := q.saveLocked(); err != nil {
		return nil, err
	}
	return q, nil
}

// Enqueue records a pending command for agentID, superseding its live one (a fresh
// request replaces a stale one). Returns the created Command.
//
// This is the infallible form: with a durable queue, a failed write is logged and
// the command stays queued in memory (it is still delivered; it would just not
// survive a restart). Use EnqueueDurable when the caller must know.
func (q *Queue) Enqueue(agentID, cmdType string) Command {
	c, _ := q.enqueue(agentID, cmdType, false)
	return c
}

// EnqueueDurable is Enqueue for callers that must not promise what is not safe:
// when the state file cannot be written nothing is queued, the previous state is
// restored and the error is returned. For an in-memory queue it never fails. The
// HTTP handlers use it, so a 202 always means "durably queued".
func (q *Queue) EnqueueDurable(agentID, cmdType string) (Command, error) {
	return q.enqueue(agentID, cmdType, true)
}

func (q *Queue) enqueue(agentID, cmdType string, strict bool) (Command, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	now := q.now().UTC()

	// Copy for rollback; the edits below touch the shared backing array.
	prev := append([]Record(nil), q.agents[agentID]...)

	// A command that already died of age is reported EXPIRED, not SUPERSEDED.
	q.expireLocked(agentID, now)
	h := q.agents[agentID]
	for i := range h {
		if h[i].State.live() {
			h[i].State, h[i].UpdatedAt = StateSuperseded, now
		}
	}
	rec := Record{
		Command:   Command{ID: randID(), Type: cmdType, CreatedAt: now},
		State:     StatePending,
		UpdatedAt: now,
	}
	h = append(h, rec)
	if len(h) > HistoryLimit {
		h = append([]Record(nil), h[len(h)-HistoryLimit:]...)
	}
	q.agents[agentID] = h

	if err := q.saveLocked(); err != nil {
		if !strict {
			q.logf("commands: %v — comando mantido só em memória", err)
			return rec.Command, nil
		}
		if len(prev) == 0 {
			delete(q.agents, agentID)
		} else {
			q.agents[agentID] = prev
		}
		return Command{}, err
	}
	return rec.Command, nil
}

// Pending returns the agent's live command (PENDING or DELIVERED), if any, without
// delivering it. The agent-facing path is Poll.
func (q *Queue) Pending(agentID string) (Command, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.expireLocked(agentID, q.now().UTC()) {
		q.persistLocked()
	}
	if i := q.liveLocked(agentID); i >= 0 {
		return q.agents[agentID][i].Command, true
	}
	return Command{}, false
}

// Poll is what an agent's poll does: it returns the agent's live command, if any,
// and marks it DELIVERED (the first delivery time is kept; later polls hand the
// same command out again until it is acked or expires).
//
// If the DELIVERED mark cannot be persisted the command is delivered anyway and the
// failure is logged: scan_now is idempotent, so the worst case is that after a
// restart the command is handed out once more.
func (q *Queue) Poll(agentID string) (Command, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	now := q.now().UTC()
	changed := q.expireLocked(agentID, now)

	i := q.liveLocked(agentID)
	if i < 0 {
		if changed {
			q.persistLocked()
		}
		return Command{}, false
	}
	rec := &q.agents[agentID][i]
	if rec.State == StatePending {
		rec.State, rec.DeliveredAt, rec.UpdatedAt = StateDelivered, now, now
		changed = true
	}
	if changed {
		q.persistLocked()
	}
	return rec.Command, true
}

// Ack marks the agent's live command ACKED iff its id matches, so a stale ack — for
// a command already superseded, expired or acked — is a no-op. Returns whether this
// call acknowledged it. A failed write is logged (after a restart the command would
// simply be handed out again).
func (q *Queue) Ack(agentID, id string) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	now := q.now().UTC()
	changed := q.expireLocked(agentID, now)

	acked := false
	if i := q.liveLocked(agentID); i >= 0 && q.agents[agentID][i].ID == id {
		rec := &q.agents[agentID][i]
		rec.State, rec.AckedAt, rec.UpdatedAt = StateAcked, now, now
		acked, changed = true, true
	}
	if changed {
		q.persistLocked()
	}
	return acked
}

// History returns a copy of the agent's recent commands, newest first (at most
// HistoryLimit). It is empty, never nil, for an agent that has none.
func (q *Queue) History(agentID string) []Record {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.expireLocked(agentID, q.now().UTC()) {
		q.persistLocked()
	}
	h := q.agents[agentID]
	out := make([]Record, len(h))
	for i, rec := range h {
		out[len(h)-1-i] = rec
	}
	return out
}

// liveLocked returns the index of the agent's live command, or -1. It scans from
// the newest record so the answer is right even for a hand-edited state file.
func (q *Queue) liveLocked(agentID string) int {
	h := q.agents[agentID]
	for i := len(h) - 1; i >= 0; i-- {
		if h[i].State.live() {
			return i
		}
	}
	return -1
}

// expireLocked closes the agent's live commands older than the TTL and reports
// whether anything changed (the caller persists). A command exactly TTL old is not
// yet expired.
func (q *Queue) expireLocked(agentID string, now time.Time) bool {
	h := q.agents[agentID]
	changed := false
	for i := range h {
		if h[i].State.live() && now.Sub(h[i].CreatedAt) > q.ttl {
			h[i].State, h[i].UpdatedAt = StateExpired, h[i].CreatedAt.Add(q.ttl)
			changed = true
		}
	}
	return changed
}

// persistLocked saves after a change the caller cannot fail on (a poll, an ack, an
// expiry): the in-memory state stays authoritative and the error is logged — never
// swallowed, so a full or read-only disk shows up in the logs.
func (q *Queue) persistLocked() {
	if err := q.saveLocked(); err != nil {
		q.logf("commands: %v — estado em memória mantido", err)
	}
}

// load reads the state file into q. A missing file is a fresh start; anything that
// does not parse as a state file we wrote is an error, so a corrupt file is
// noticed at boot rather than silently replaced by an empty queue.
func (q *Queue) load() error {
	b, err := os.ReadFile(q.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("ler fila de comandos %s: %w", q.path, err)
	}
	if err := q.parse(b); err != nil {
		return fmt.Errorf("fila de comandos %s corrompida: %w (corrija ou remova o arquivo para recomeçar com a fila vazia)", q.path, err)
	}
	return nil
}

// parse fills q from the state file content, or says what is wrong with it.
func (q *Queue) parse(b []byte) error {
	var f fileFormat
	if err := json.Unmarshal(b, &f); err != nil {
		return err
	}
	if f.Version != fileVersion {
		return fmt.Errorf("versão %d não suportada (esperada %d)", f.Version, fileVersion)
	}
	for agent, h := range f.Agents {
		for i, rec := range h {
			if rec.ID == "" || !rec.State.valid() {
				return fmt.Errorf("agente %q, registro %d inválido (id=%q estado=%q)", agent, i, rec.ID, rec.State)
			}
		}
		if len(h) > 0 {
			q.agents[agent] = h
		}
	}
	return nil
}

// saveLocked writes the whole queue atomically (temp file + rename), compact and
// 0600. A no-op for an in-memory queue.
func (q *Queue) saveLocked() error {
	if q.path == "" {
		return nil
	}
	b, err := json.Marshal(fileFormat{Version: fileVersion, Agents: q.agents})
	if err == nil {
		err = writeFileAtomic(q.path, b)
	}
	if err != nil {
		return fmt.Errorf("gravar fila de comandos %s: %w", q.path, err)
	}
	return nil
}

// writeFileAtomic replaces path with data: write a fresh 0600 temp file next to it,
// flush it to disk, then rename it over path, so a reader (or a crash) sees the old
// content or the new, never a mix.
func writeFileAtomic(path string, data []byte) (err error) {
	tmp := path + ".tmp"
	_ = os.Remove(tmp) // leftover of a crash mid-save; start from a fresh 0600 file
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = os.Remove(tmp)
		}
	}()
	if _, err = f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func randID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
