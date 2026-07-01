// Package ingest is the data-plane stub: it receives agent inventories over
// (mTLS) HTTP, validates them minimally against the contract, and hands them to
// a Sink. The full correlation pipeline + persistence land in Fase 2.
package ingest

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"os/exec"
	"sync"
	"time"
)

// SchemaVersion is the inventory contract version this stub accepts (kept in
// lockstep with schema/inventory.schema.json and the agent).
const SchemaVersion = "1.0.0"

// Inventory is the minimal view the ingest needs; the full contract lives in
// schema/inventory.schema.json (produced by the agent).
type Inventory struct {
	SchemaVersion string `json:"schema_version"`
	Agent         struct {
		AgentID  string `json:"agent_id"`
		Hostname string `json:"hostname"`
	} `json:"agent"`
	OS struct {
		Family  string `json:"family"`
		Distro  string `json:"distro"`
		Release string `json:"release"`
	} `json:"os"`
	Packages  []json.RawMessage `json:"packages"`
	CycleHash string            `json:"cycle_hash"`
	// CollectedAt is the agent's collection time (RFC3339), kept as a raw string
	// so a malformed/empty value can't hard-fail JSON decode and reject the whole
	// inventory with 400 (a time.Time field would). It MUST be propagated to the
	// imported gvmd report: an empty/zero value would otherwise become Go's zero
	// time, which gvmd parses to a garbage epoch that breaks the CVE scanner's
	// host-detail matching. Parsing + flooring happens downstream (lenient).
	CollectedAt string `json:"collected_at"`
}

// Sink receives validated inventories.
type Sink interface {
	Put(Inventory) error
}

// MemSink is an in-memory Sink for dev/tests.
type MemSink struct {
	mu   sync.Mutex
	recv []Inventory
}

// Put records an inventory.
func (m *MemSink) Put(inv Inventory) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.recv = append(m.recv, inv)
	return nil
}

// Count returns how many inventories were received.
func (m *MemSink) Count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.recv)
}

// Last returns the most recently received inventory and whether one exists.
func (m *MemSink) Last() (Inventory, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.recv) == 0 {
		return Inventory{}, false
	}
	return m.recv[len(m.recv)-1], true
}

// Server handles inventory submissions and serves the read-only Agents view.
type Server struct {
	sink Sink

	// lastSeen records the last time each agent (by agent_id) POSTed an inventory
	// — updated on EVERY report, including deduplicated ones. It is the source of
	// truth for online/offline: gvmd's last-report timestamp only advances when the
	// inventory CHANGES (dedup skips unchanged cycles), so a healthy but unchanged
	// agent would look stale in gvmd. In-memory: after a restart an agent shows
	// "unknown" until its next check-in (≤ report interval).
	mu           sync.Mutex
	lastSeen     map[string]time.Time
	onlineWindow time.Duration
	now          func() time.Time

	// lastSeenPath persists lastSeen across restarts (AGENT_LASTSEEN_FILE) so an
	// ingest recreate/deploy doesn't reset every agent to "unknown" for up to a
	// report interval. Empty = in-memory only. persistMu serializes the file write.
	lastSeenPath string
	persistMu    sync.Mutex

	// queryAgents returns the gvmd posture list as JSON (default: exec
	// agents_query.py). Injectable so the handler is testable without a process.
	queryAgents func(context.Context) ([]byte, error)
}

// NewServer builds a Server backed by sink.
func NewServer(s Sink) *Server {
	window := 35 * time.Minute // ~2 missed 15m report cycles → offline
	if v := os.Getenv("AGENT_ONLINE_WINDOW"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			window = d
		}
	}
	srv := &Server{
		sink:         s,
		lastSeen:     make(map[string]time.Time),
		onlineWindow: window,
		now:          time.Now,
		queryAgents:  execAgentsQuery,
		lastSeenPath: os.Getenv("AGENT_LASTSEEN_FILE"),
	}
	srv.loadLastSeen()
	return srv
}

// loadLastSeen restores the persisted check-in times on startup (no-op if the
// file is absent — first boot — or AGENT_LASTSEEN_FILE is unset).
func (s *Server) loadLastSeen() {
	if s.lastSeenPath == "" {
		return
	}
	b, err := os.ReadFile(s.lastSeenPath)
	if err != nil {
		return
	}
	var m map[string]string
	if err := json.Unmarshal(b, &m); err != nil {
		log.Printf("agents: ignoring bad lastSeen file: %v", err)
		return
	}
	for k, v := range m {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			s.lastSeen[k] = t
		}
	}
	log.Printf("agents: restored %d agent check-in(s) from %s", len(s.lastSeen), s.lastSeenPath)
}

// persist writes the lastSeen snapshot atomically (temp + rename).
func (s *Server) persist(b []byte) {
	s.persistMu.Lock()
	defer s.persistMu.Unlock()
	tmp := s.lastSeenPath + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		log.Printf("agents: persist lastSeen: %v", err)
		return
	}
	if err := os.Rename(tmp, s.lastSeenPath); err != nil {
		log.Printf("agents: rename lastSeen: %v", err)
	}
}

// execAgentsQuery runs agents_query.py (python-gvm) and returns its JSON stdout.
// The script reads GMP_SOCKET/GMP_USERNAME/GVM_PASSWORD from the inherited env.
func execAgentsQuery(ctx context.Context) ([]byte, error) {
	script := os.Getenv("AGENTS_QUERY_SCRIPT")
	if script == "" {
		script = "/usr/local/share/suricatoos/agents_query.py"
	}
	python := os.Getenv("BRIDGE_PYTHON")
	if python == "" {
		python = "python3"
	}
	return exec.CommandContext(ctx, python, script).Output()
}

// markSeen records that agentID just checked in, and persists the snapshot so
// the status survives an ingest restart.
func (s *Server) markSeen(agentID string) {
	s.mu.Lock()
	s.lastSeen[agentID] = s.now().UTC()
	var snap []byte
	if s.lastSeenPath != "" {
		m := make(map[string]string, len(s.lastSeen))
		for k, v := range s.lastSeen {
			m[k] = v.Format(time.RFC3339)
		}
		snap, _ = json.Marshal(m)
	}
	s.mu.Unlock()
	if snap != nil {
		s.persist(snap)
	}
}

// seen returns the agent's last check-in time, if known.
func (s *Server) seen(agentID string) (time.Time, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.lastSeen[agentID]
	return t, ok
}

// Handler serves POST /v1/inventory and GET /agents.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/inventory", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var inv Inventory
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<20)).Decode(&inv); err != nil {
			http.Error(w, "json inválido", http.StatusBadRequest)
			return
		}
		if inv.SchemaVersion != SchemaVersion {
			http.Error(w, "schema_version não suportada", http.StatusBadRequest)
			return
		}
		if inv.Agent.AgentID == "" || inv.OS.Family == "" {
			http.Error(w, "inventário incompleto", http.StatusBadRequest)
			return
		}
		s.markSeen(inv.Agent.AgentID) // last check-in for online/offline, even if deduped downstream
		if err := s.sink.Put(inv); err != nil {
			http.Error(w, "erro interno", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusAccepted)
	})
	mux.HandleFunc("/agents", s.agentsHandler)
	return mux
}

// agentsHandler serves GET /agents: the endpoint-agent posture list for the
// Agents UI page. It merges accurate posture from gvmd (severity/findings, via
// agents_query.py) with the ingest's own last-check-in tracking (online/offline).
//
// This MUST only be reachable through the session-gated nginx location (which
// sets X-Suricatoos-UI: 1). The mTLS /ingest/ location clears that header, so an
// enrolled agent cannot read the fleet's posture via /ingest/agents.
func (s *Server) agentsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.Header.Get("X-Suricatoos-UI") != "1" {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	out, err := s.queryAgents(ctx)
	if err != nil {
		log.Printf("agents: query failed: %v", err)
		http.Error(w, "erro ao consultar gvmd", http.StatusBadGateway)
		return
	}
	var list []map[string]any
	if err := json.Unmarshal(out, &list); err != nil {
		log.Printf("agents: bad query output: %v", err)
		http.Error(w, "resposta inválida", http.StatusBadGateway)
		return
	}
	now := s.now().UTC()
	for _, a := range list {
		host, _ := a["host"].(string)
		if t, ok := s.seen(host); ok {
			a["last_seen"] = t.Format(time.RFC3339)
			a["online"] = now.Sub(t) <= s.onlineWindow
			if now.Sub(t) <= s.onlineWindow {
				a["status"] = "online"
			} else {
				a["status"] = "offline"
			}
		} else {
			a["last_seen"] = ""
			a["online"] = false
			a["status"] = "unknown" // ingest hasn't seen a check-in since it started
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(list)
}
