// Package commands implements the agent command channel: an operator enqueues a
// command (e.g. "scan_now") for an agent, the agent polls for it over its mTLS
// channel, runs it (an immediate local re-collect + report), and acks it.
//
// This is the outbound-only "scan on demand" path: the agent always initiates
// (poll), so no inbound listener is added — consistent with the passive-agent
// design (PLAN.md sec.5 lists rescan as a control-plane command).
//
// The queue is in-memory and holds at most one pending command per agent: a
// pending "scan_now" is transient — losing it on a control-plane restart just
// means re-triggering, which is acceptable for an on-demand action.
package commands

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

// CmdScanNow re-runs the agent's local inventory collection now (NOT a network
// scan — the agent stays passive/local-only).
const CmdScanNow = "scan_now"

// Command is a single queued instruction for an agent.
type Command struct {
	ID        string    `json:"id"`
	Type      string    `json:"type"`
	CreatedAt time.Time `json:"created_at"`
}

// Queue is a concurrency-safe, in-memory per-agent command queue.
type Queue struct {
	mu      sync.Mutex
	pending map[string]Command // agentID -> the single pending command
	now     func() time.Time
}

// NewQueue returns an empty queue.
func NewQueue() *Queue {
	return &Queue{pending: make(map[string]Command), now: time.Now}
}

// Enqueue records a pending command for agentID, replacing any previous pending
// one (a fresh request supersedes a stale one). Returns the created Command.
func (q *Queue) Enqueue(agentID, cmdType string) Command {
	c := Command{ID: randID(), Type: cmdType, CreatedAt: q.now().UTC()}
	q.mu.Lock()
	q.pending[agentID] = c
	q.mu.Unlock()
	return c
}

// Pending returns the agent's pending command, if any.
func (q *Queue) Pending(agentID string) (Command, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	c, ok := q.pending[agentID]
	return c, ok
}

// Ack removes the agent's pending command iff its id matches (so a stale ack for
// an already-superseded command is a no-op). Returns whether it was removed.
func (q *Queue) Ack(agentID, id string) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	if c, ok := q.pending[agentID]; ok && c.ID == id {
		delete(q.pending, agentID)
		return true
	}
	return false
}

func randID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
