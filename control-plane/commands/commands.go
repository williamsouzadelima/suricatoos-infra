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
// The queue is bounded on purpose. Agent ids must satisfy the enrollment rule, and at
// most Config.MaxAgents distinct agents are held (each with at most HistoryLimit
// commands): when the queue is durable every change rewrites the whole state file
// under the lock every agent poll takes, and boot loads all of it, so an unbounded
// queue is an outage waiting for the first client that fills it.
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
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/williamsouzadelima/suricatoos-infra/control-plane/enroll"
)

// CmdScanNow re-runs the agent's local inventory collection now (NOT a network
// scan — the agent stays passive/local-only).
const CmdScanNow = "scan_now"

const (
	// DefaultTTL is how long a PENDING/DELIVERED command stays deliverable.
	DefaultTTL = 24 * time.Hour
	// HistoryLimit is how many commands are kept per agent, the live one included.
	HistoryLimit = 20
	// DefaultMaxAgents is how many distinct agents the queue holds at once
	// (COMMANDS_MAX_AGENTS). With HistoryLimit it bounds the state file to a few tens
	// of MB at worst; a real fleet is a small fraction of it.
	DefaultMaxAgents = 5000

	// fileVersion is the state file schema version.
	fileVersion = 1
)

var (
	// ErrInvalidAgentID: the id is not one an agent could have been enrolled with.
	ErrInvalidAgentID = errors.New("invalid agent id")
	// ErrQueueFull: the agent is new, MaxAgents agents are held already and none of
	// them can be reclaimed (see Enqueue).
	ErrQueueFull = errors.New("command queue is full")
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
	// StateExpired: older than the TTL without an ack; no longer delivered. (An ack
	// that arrives late for a command that WAS delivered still turns it ACKED.)
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
	Path      string        // JSON state file; "" keeps the queue in memory only
	TTL       time.Duration // a live command older than this expires; <=0 → DefaultTTL
	MaxAgents int           // distinct agents held at once; <=0 → DefaultMaxAgents
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
	mu        sync.Mutex
	path      string // "" = in memory only
	ttl       time.Duration
	maxAgents int
	agents    map[string][]Record
	now       func() time.Time
	logf      func(format string, args ...any)
}

// NewQueue returns an empty in-memory queue (nothing is written to disk).
func NewQueue() *Queue { return newQueue(Config{}) }

func newQueue(cfg Config) *Queue {
	ttl := cfg.TTL
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	maxAgents := cfg.MaxAgents
	if maxAgents <= 0 {
		maxAgents = DefaultMaxAgents
	}
	return &Queue{
		path:      cfg.Path,
		ttl:       ttl,
		maxAgents: maxAgents,
		agents:    make(map[string][]Record),
		now:       time.Now,
		logf:      log.Printf,
	}
}

// Open returns a queue configured by cfg. With a Path it loads the state file
// (missing = fresh; unreadable or corrupt = error, the file is left untouched) and
// writes it back once, so an unwritable path fails here at boot instead of on the
// first operator request. Agent keys that fail the id rule are dropped with a log
// line rather than failing the boot.
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

// validAgentID reports whether id is one an agent could have been enrolled with: the
// enrollment rule itself, plus UTF-8 validity. Ids reach the queue from URLs, which
// (unlike the JSON enrollment body) can carry bytes that would not survive the round
// trip through the state file.
func validAgentID(id string) bool {
	return utf8.ValidString(id) && enroll.ValidateAgentID(id) == nil
}

// Enqueue records a pending command for agentID, superseding its live one (a fresh
// request replaces a stale one), and returns it. It queues nothing and fails with:
//
//   - ErrInvalidAgentID, when the id could not belong to an enrolled agent;
//   - ErrQueueFull, when the agent is new and MaxAgents agents are held already. Before
//     giving up it reclaims the agents that have nothing live and have been idle for
//     longer than the TTL; an agent with a live command is never evicted;
//   - the write error, when a durable queue cannot save: the previous state is
//     restored, so a nil error always means "queued, and on disk if the queue is durable".
func (q *Queue) Enqueue(agentID, cmdType string) (Command, error) {
	if !validAgentID(agentID) {
		return Command{}, ErrInvalidAgentID
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	now := q.now().UTC()

	// A new agent at the cap first tries to make room by reclaiming idle ones.
	var reclaimed map[string][]Record
	if _, held := q.agents[agentID]; !held && len(q.agents) >= q.maxAgents {
		reclaimed = q.reclaimLocked(now)
		if len(q.agents) >= q.maxAgents {
			// Still full (possible when the cap was lowered below the current count).
			// What was reclaimed stays reclaimed — it was only idle history — so memory
			// and disk must agree on it even though this request is refused.
			if len(reclaimed) > 0 {
				q.persistLocked()
			}
			return Command{}, ErrQueueFull
		}
	}

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
		// Nothing of this request — nor of the reclaim it triggered — is kept.
		if len(prev) == 0 {
			delete(q.agents, agentID)
		} else {
			q.agents[agentID] = prev
		}
		for id, old := range reclaimed {
			q.agents[id] = old
		}
		return Command{}, err
	}
	return rec.Command, nil
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

// Ack marks the agent's command ACKED iff its id matches one that is still open: a
// live (PENDING/DELIVERED) command, or one that EXPIRED after being delivered — the
// agent got it in time and finished late, so the record must say it ran. A stale ack
// — for a command superseded, already acked, or never delivered — is a no-op.
// Returns whether this call acknowledged it. A failed write is logged (after a
// restart the command would simply be handed out again).
func (q *Queue) Ack(agentID, id string) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	now := q.now().UTC()
	changed := q.expireLocked(agentID, now)

	acked := false
	if i := q.indexLocked(agentID, id); i >= 0 {
		rec := &q.agents[agentID][i]
		if rec.State.live() || (rec.State == StateExpired && !rec.DeliveredAt.IsZero()) {
			rec.State, rec.AckedAt, rec.UpdatedAt = StateAcked, now, now
			acked, changed = true, true
		}
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

// indexLocked returns the index of the agent's command with the given id, or -1.
func (q *Queue) indexLocked(agentID, id string) int {
	h := q.agents[agentID]
	for i := len(h) - 1; i >= 0; i-- {
		if h[i].ID == id {
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

// reclaimLocked drops the agents that have nothing live and have been idle for longer
// than the TTL, and returns what it dropped so the caller can put it back if the
// request it made room for fails. A command past its TTL counts as expired whether or
// not anything has noticed yet, and an agent with a live command is never touched.
func (q *Queue) reclaimLocked(now time.Time) map[string][]Record {
	var dropped map[string][]Record
	for id, h := range q.agents {
		if q.idleLocked(h, now) {
			if dropped == nil {
				dropped = make(map[string][]Record)
			}
			dropped[id] = h
		}
	}
	for id := range dropped {
		delete(q.agents, id)
	}
	return dropped
}

// idleLocked reports whether an agent has nothing live and has been idle for longer
// than the TTL, measured from its last state change. A live command counts as
// changing at its deadline (created_at + TTL), whether or not anything has noticed
// that it expired yet — which also means an agent whose command is still within its
// TTL can never be idle: the deadline is ahead of now.
func (q *Queue) idleLocked(h []Record, now time.Time) bool {
	var last time.Time
	for _, r := range h {
		changed := r.UpdatedAt
		if r.State.live() {
			changed = r.CreatedAt.Add(q.ttl)
		}
		if changed.After(last) {
			last = changed
		}
	}
	return now.Sub(last) > q.ttl
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

// parse fills q from the state file content, or says what is wrong with it. Agent
// keys that fail the id rule cannot come from this code and would only take up room,
// so they are dropped (and counted in the log) instead of failing the boot.
func (q *Queue) parse(b []byte) error {
	var f fileFormat
	if err := json.Unmarshal(b, &f); err != nil {
		return err
	}
	if f.Version != fileVersion {
		return fmt.Errorf("versão %d não suportada (esperada %d)", f.Version, fileVersion)
	}
	dropped, sample := 0, ""
	for agent, h := range f.Agents {
		if !validAgentID(agent) {
			dropped++
			if agent != "" && (sample == "" || agent < sample) {
				sample = agent
			}
			continue
		}
		for i, rec := range h {
			if rec.ID == "" || !rec.State.valid() {
				return fmt.Errorf("agente %q, registro %d inválido (id=%q estado=%q)", agent, i, rec.ID, rec.State)
			}
		}
		if len(h) > 0 {
			q.agents[agent] = h
		}
	}
	if dropped > 0 {
		if len(sample) > 64 {
			sample = sample[:64] + "…"
		}
		q.logf("commands: %d agente(s) com id inválido descartado(s) do arquivo (ex.: %q)", dropped, sample)
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

// syncDir flushes a directory so a rename inside it survives a power loss. It is a
// variable so tests can observe it.
var syncDir = func(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	err = d.Sync()
	if cerr := d.Close(); err == nil {
		err = cerr
	}
	return err
}

// writeFileAtomic replaces path with data: write a fresh 0600 temp file next to it,
// flush it to disk, rename it over path, then flush the directory, so a reader (or a
// crash) sees the old content or the new, never a mix.
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
	if err = os.Rename(tmp, path); err != nil {
		return err
	}
	// Best effort, and deliberately not an error: the new content is already in place,
	// so failing the save now would make memory and disk disagree. A directory that
	// cannot be flushed (Windows, some network filesystems) only loses the guarantee
	// that the rename itself survives a power failure.
	_ = syncDir(filepath.Dir(path))
	return nil
}

func randID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
