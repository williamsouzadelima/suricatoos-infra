package tokens

import (
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func newBolt(t *testing.T) *BoltStore {
	t.Helper()
	s, err := NewBoltStore(filepath.Join(t.TempDir(), "tokens.db"))
	if err != nil {
		t.Fatalf("NewBoltStore: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestBoltStore_PutGet(t *testing.T) {
	s := newBolt(t)
	r := Record{ID: "abc", Type: SingleHost, MaxUses: 1, ExpiresAt: time.Now().Add(time.Hour)}
	if err := s.Put(r); err != nil {
		t.Fatal(err)
	}
	got, ok := s.Get("abc")
	if !ok {
		t.Fatal("record not found after Put")
	}
	if got.ID != "abc" || got.Type != SingleHost {
		t.Errorf("got %+v", got)
	}
}

func TestBoltStore_GetNotFound(t *testing.T) {
	s := newBolt(t)
	_, ok := s.Get("nonexistent")
	if ok {
		t.Error("expected not found")
	}
}

func TestBoltStore_Update(t *testing.T) {
	s := newBolt(t)
	r := Record{ID: "upd", Type: SingleHost, MaxUses: 1, ExpiresAt: time.Now().Add(time.Hour)}
	if err := s.Put(r); err != nil {
		t.Fatal(err)
	}
	r.UsedCount = 1
	r.Revoked = true
	if err := s.Update(r); err != nil {
		t.Fatal(err)
	}
	got, _ := s.Get("upd")
	if !got.Revoked || got.UsedCount != 1 {
		t.Errorf("update not persisted: %+v", got)
	}
}

func TestBoltStore_UpdateNotFound(t *testing.T) {
	s := newBolt(t)
	err := s.Update(Record{ID: "ghost"})
	if err != ErrNotFound {
		t.Errorf("want ErrNotFound, got %v", err)
	}
}

func TestBoltStore_List(t *testing.T) {
	s := newBolt(t)
	for _, id := range []string{"a", "b", "c"} {
		if err := s.Put(Record{ID: id, Type: SingleHost, MaxUses: 1, ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
			t.Fatal(err)
		}
	}
	recs, err := s.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 3 {
		t.Errorf("want 3, got %d", len(recs))
	}
}

func TestBoltStore_SurvivesReopen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tokens.db")

	s1, _ := NewBoltStore(path)
	s1.Put(Record{ID: "persist", Type: SingleHost, MaxUses: 1, ExpiresAt: time.Now().Add(time.Hour)})
	s1.Close()

	s2, _ := NewBoltStore(path)
	defer s2.Close()
	_, ok := s2.Get("persist")
	if !ok {
		t.Error("record must survive store reopen")
	}
}

// TestBoltStore_FullCycle runs a Mint+Consume cycle through a BoltStore to
// verify the Manager works correctly with the persistent backend.
func TestBoltStore_FullCycle(t *testing.T) {
	s := newBolt(t)
	m := NewManager(s, WithClock(func() time.Time { return time.Unix(1700000000, 0).UTC() }))

	minted, err := m.Mint(MintRequest{
		Type:    SingleHost,
		Scope:   Scope{Tenant: "acme"},
		TTL:     time.Hour,
		MaxUses: 1,
	})
	if err != nil {
		t.Fatal(err)
	}

	rec, err := m.Consume(minted.Token, Enrollment{AgentID: "host-1"})
	if err != nil {
		t.Fatal(err)
	}
	if rec.UsedCount != 1 {
		t.Errorf("UsedCount = %d", rec.UsedCount)
	}

	// Token exhausted — second consume must fail.
	if _, err := m.Consume(minted.Token, Enrollment{AgentID: "host-2"}); err != ErrExhausted {
		t.Errorf("want ErrExhausted, got %v", err)
	}
}

// TestBoltStore_AgentIDUniqueness_SurvivesReopen verifies that the agents bucket
// persists across BoltStore reopen so duplicate agent_id is still rejected.
func TestBoltStore_AgentIDUniqueness_SurvivesReopen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tokens.db")

	// First run: enroll host-X.
	s1, _ := NewBoltStore(path)
	m1 := NewManager(s1, WithClock(func() time.Time { return time.Unix(1700000000, 0).UTC() }))
	mt1, _ := m1.Mint(MintRequest{Type: SingleHost, Scope: Scope{Tenant: "acme"}, TTL: time.Hour})
	if _, err := m1.Consume(mt1.Token, Enrollment{AgentID: "host-X"}); err != nil {
		t.Fatalf("enroll 1: %v", err)
	}
	s1.Close()

	// Second run (new process): same agent_id must be rejected.
	s2, _ := NewBoltStore(path)
	defer s2.Close()
	m2 := NewManager(s2, WithClock(func() time.Time { return time.Unix(1700000000, 0).UTC() }))
	mt2, _ := m2.Mint(MintRequest{Type: SingleHost, Scope: Scope{Tenant: "acme"}, TTL: time.Hour})
	_, err := m2.Consume(mt2.Token, Enrollment{AgentID: "host-X"})
	if !errors.Is(err, ErrAgentAlreadyExists) {
		t.Fatalf("duplicate agent_id across reboots must be ErrAgentAlreadyExists, got %v", err)
	}
}
