// Package ingest is the data-plane stub: it receives agent inventories over
// (mTLS) HTTP, validates them minimally against the contract, and hands them to
// a Sink. The full correlation pipeline + persistence land in Fase 2.
package ingest

import (
	"encoding/json"
	"net/http"
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
	// CollectedAt is the agent's collection time (RFC3339). It MUST be propagated
	// to the imported gvmd report: an empty/zero value serializes as Go's zero
	// time, which gvmd parses to a garbage epoch that breaks the CVE scanner's
	// host-detail matching (the scanner finds 0 even with valid CPEs).
	CollectedAt time.Time `json:"collected_at"`
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

// Server handles inventory submissions.
type Server struct{ sink Sink }

// NewServer builds a Server backed by sink.
func NewServer(s Sink) *Server { return &Server{sink: s} }

// Handler serves POST /v1/inventory.
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
		if err := s.sink.Put(inv); err != nil {
			http.Error(w, "erro interno", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusAccepted)
	})
	return mux
}
