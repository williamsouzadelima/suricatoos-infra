package tokens

import "sync"

// Store persists token Records — the server-side source of truth. Methods use
// value semantics (copies in/out) so callers never share mutable state with the
// store. A production implementation backs this with a database (Fase 2).
type Store interface {
	Put(Record) error
	Get(id string) (Record, bool)
	Update(Record) error
	List() ([]Record, error)

	// HasAgentID reports whether agentID has already been enrolled (by any token).
	// Used to enforce global agent_id uniqueness: first enrollment wins.
	HasAgentID(agentID string) (bool, error)
	// RegisterAgentID marks agentID as enrolled by tokenID. Must be called under
	// the Manager lock after Update so the two writes are logically atomic.
	RegisterAgentID(agentID, tokenID string) error
	// TokenIDByAgentID returns the token id that enrolled agentID (ok=false if
	// unknown). Lets a cert-authenticated renewal find and extend its own token
	// record so a renewed cert's serial stays revocable.
	TokenIDByAgentID(agentID string) (string, bool, error)
}

// MemStore is an in-memory, concurrency-safe Store for dev and tests.
type MemStore struct {
	mu     sync.RWMutex
	rec    map[string]Record
	agents map[string]string // agentID → tokenID
}

// NewMemStore returns an empty in-memory store.
func NewMemStore() *MemStore {
	return &MemStore{rec: make(map[string]Record), agents: make(map[string]string)}
}

// Put inserts or replaces a record.
func (s *MemStore) Put(r Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rec[r.ID] = cloneRecord(r)
	return nil
}

// Get returns a copy of the record and whether it was found.
func (s *MemStore) Get(id string) (Record, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.rec[id]
	if !ok {
		return Record{}, false
	}
	return cloneRecord(r), true
}

// Update replaces an existing record; it errors if the record is unknown.
func (s *MemStore) Update(r Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.rec[r.ID]; !ok {
		return ErrNotFound
	}
	s.rec[r.ID] = cloneRecord(r)
	return nil
}

// List returns copies of all records.
func (s *MemStore) List() ([]Record, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Record, 0, len(s.rec))
	for _, r := range s.rec {
		out = append(out, cloneRecord(r))
	}
	return out, nil
}

// HasAgentID reports whether agentID has been registered.
func (s *MemStore) HasAgentID(agentID string) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.agents[agentID]
	return ok, nil
}

// RegisterAgentID records agentID → tokenID.
func (s *MemStore) RegisterAgentID(agentID, tokenID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.agents[agentID] = tokenID
	return nil
}

// TokenIDByAgentID returns the token id that enrolled agentID.
func (s *MemStore) TokenIDByAgentID(agentID string) (string, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.agents[agentID]
	return id, ok, nil
}

// cloneRecord deep-copies the Enrollments slice so copies never share backing.
func cloneRecord(r Record) Record {
	if r.Enrollments != nil {
		e := make([]Enrollment, len(r.Enrollments))
		copy(e, r.Enrollments)
		r.Enrollments = e
	}
	return r
}
