package tokens

import (
	"errors"
	"sync"
	"testing"
	"time"
)

func newTestManager(now *time.Time) *Manager {
	return NewManager(NewMemStore(), WithClock(func() time.Time { return *now }))
}

func TestSingleHostConsumeOnce(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	m := newTestManager(&now)
	mint, err := m.Mint(MintRequest{Type: SingleHost, Scope: Scope{Tenant: "acme"}, TTL: time.Hour, CreatedBy: "op"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Consume(mint.Token, Enrollment{AgentID: "a1"}); err != nil {
		t.Fatalf("primeiro consume deve passar: %v", err)
	}
	if _, err := m.Consume(mint.Token, Enrollment{AgentID: "a2"}); !errors.Is(err, ErrExhausted) {
		t.Fatalf("segundo consume deve ser ErrExhausted, got %v", err)
	}
}

func TestDeploymentCap(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	m := newTestManager(&now)
	mint, _ := m.Mint(MintRequest{Type: Deployment, MaxUses: 3, TTL: time.Hour})
	for i := 0; i < 3; i++ {
		if _, err := m.Consume(mint.Token, Enrollment{AgentID: "a"}); err != nil {
			t.Fatalf("consume %d: %v", i, err)
		}
	}
	if _, err := m.Consume(mint.Token, Enrollment{AgentID: "a"}); !errors.Is(err, ErrExhausted) {
		t.Fatalf("4º consume deve ser ErrExhausted, got %v", err)
	}
}

func TestTTLExpiry(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	m := newTestManager(&now)
	mint, _ := m.Mint(MintRequest{Type: SingleHost, TTL: 10 * time.Minute})
	now = now.Add(11 * time.Minute)
	if _, err := m.Validate(mint.Token, Scope{}); !errors.Is(err, ErrExpired) {
		t.Fatalf("deve expirar, got %v", err)
	}
}

func TestRevoke(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	m := newTestManager(&now)
	mint, _ := m.Mint(MintRequest{Type: Deployment, MaxUses: 5, TTL: time.Hour})
	if err := m.Revoke(mint.ID, "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Consume(mint.Token, Enrollment{AgentID: "a"}); !errors.Is(err, ErrRevoked) {
		t.Fatalf("revogado deve recusar, got %v", err)
	}
}

func TestBadSecretAndMalformed(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	m := newTestManager(&now)
	mint, _ := m.Mint(MintRequest{Type: SingleHost, TTL: time.Hour})
	if _, err := m.Validate(mint.Token+"tampered", Scope{}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("secret errado deve ser ErrNotFound, got %v", err)
	}
	if _, err := m.Validate("lixo-sem-ponto", Scope{}); !errors.Is(err, ErrMalformed) {
		t.Fatalf("malformado deve ser ErrMalformed, got %v", err)
	}
}

func TestScopeMismatch(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	m := newTestManager(&now)
	mint, _ := m.Mint(MintRequest{Type: SingleHost, Scope: Scope{Tenant: "acme", OS: "linux"}, TTL: time.Hour})
	if _, err := m.Consume(mint.Token, Enrollment{AgentID: "a", OS: "windows"}); !errors.Is(err, ErrScopeMismatch) {
		t.Fatalf("os divergente deve ser ErrScopeMismatch, got %v", err)
	}
	// OS correto passa.
	if _, err := m.Consume(mint.Token, Enrollment{AgentID: "a", OS: "linux"}); err != nil {
		t.Fatalf("os correto deve passar: %v", err)
	}
}

func TestAuditTrail(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	m := newTestManager(&now)
	mint, _ := m.Mint(MintRequest{Type: Deployment, MaxUses: 2, TTL: time.Hour})
	rec, err := m.Consume(mint.Token, Enrollment{AgentID: "a1", OS: "linux", Arch: "amd64"})
	if err != nil {
		t.Fatal(err)
	}
	if len(rec.Enrollments) != 1 || rec.Enrollments[0].AgentID != "a1" {
		t.Fatalf("trilha de auditoria errada: %+v", rec.Enrollments)
	}
	if rec.Remaining() != 1 {
		t.Fatalf("remaining = %d, want 1", rec.Remaining())
	}
}

func TestConcurrentConsumeRespectsCap(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	m := newTestManager(&now)
	const limit = 10
	mint, _ := m.Mint(MintRequest{Type: Deployment, MaxUses: limit, TTL: time.Hour})
	var wg sync.WaitGroup
	var mu sync.Mutex
	ok := 0
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := m.Consume(mint.Token, Enrollment{AgentID: "a"}); err == nil {
				mu.Lock()
				ok++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if ok != limit {
		t.Fatalf("consumos bem-sucedidos = %d, want %d", ok, limit)
	}
}
