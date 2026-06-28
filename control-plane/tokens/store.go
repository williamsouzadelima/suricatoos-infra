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
}

// MemStore is an in-memory, concurrency-safe Store for dev and tests.
type MemStore struct {
	mu  sync.RWMutex
	rec map[string]Record
}

// NewMemStore returns an empty in-memory store.
func NewMemStore() *MemStore { return &MemStore{rec: make(map[string]Record)} }

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

// cloneRecord deep-copies the Enrollments slice so copies never share backing.
func cloneRecord(r Record) Record {
	if r.Enrollments != nil {
		e := make([]Enrollment, len(r.Enrollments))
		copy(e, r.Enrollments)
		r.Enrollments = e
	}
	return r
}
