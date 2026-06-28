package tokens

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

func newTestManager(now *time.Time) *Manager {
	return NewManager(NewMemStore(), WithClock(func() time.Time { return *now }))
}

// mint is a helper that defaults a Tenant (required since the hardening pass).
func mint(t *testing.T, m *Manager, req MintRequest) Minted {
	t.Helper()
	if req.Scope.Tenant == "" {
		req.Scope.Tenant = "acme"
	}
	out, err := m.Mint(req)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	return out
}

func TestSingleHostConsumeOnce(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	m := newTestManager(&now)
	mt := mint(t, m, MintRequest{Type: SingleHost, Scope: Scope{Tenant: "acme"}, TTL: time.Hour, CreatedBy: "op"})
	if _, err := m.Consume(mt.Token, Enrollment{AgentID: "a1"}); err != nil {
		t.Fatalf("primeiro consume deve passar: %v", err)
	}
	if _, err := m.Consume(mt.Token, Enrollment{AgentID: "a2"}); !errors.Is(err, ErrExhausted) {
		t.Fatalf("segundo consume deve ser ErrExhausted, got %v", err)
	}
}

func TestDeploymentCap(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	m := newTestManager(&now)
	mt := mint(t, m, MintRequest{Type: Deployment, MaxUses: 3, TTL: time.Hour})
	for i := 0; i < 3; i++ {
		id := fmt.Sprintf("host-%d", i)
		if _, err := m.Consume(mt.Token, Enrollment{AgentID: id}); err != nil {
			t.Fatalf("consume %d: %v", i, err)
		}
	}
	if _, err := m.Consume(mt.Token, Enrollment{AgentID: "host-extra"}); !errors.Is(err, ErrExhausted) {
		t.Fatalf("4º consume deve ser ErrExhausted, got %v", err)
	}
}

func TestTTLExpiry(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	m := newTestManager(&now)
	mt := mint(t, m, MintRequest{Type: SingleHost, TTL: 10 * time.Minute})
	now = now.Add(11 * time.Minute)
	if _, err := m.Validate(mt.Token, Scope{}); !errors.Is(err, ErrExpired) {
		t.Fatalf("deve expirar, got %v", err)
	}
}

func TestRevoke(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	m := newTestManager(&now)
	mt := mint(t, m, MintRequest{Type: Deployment, MaxUses: 5, TTL: time.Hour})
	if err := m.Revoke(mt.ID, "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Consume(mt.Token, Enrollment{AgentID: "a"}); !errors.Is(err, ErrRevoked) {
		t.Fatalf("revogado deve recusar, got %v", err)
	}
}

func TestBadSecretAndMalformed(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	m := newTestManager(&now)
	mt := mint(t, m, MintRequest{Type: SingleHost, TTL: time.Hour})
	if _, err := m.Validate(mt.Token+"tampered", Scope{}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("secret errado deve ser ErrNotFound, got %v", err)
	}
	if _, err := m.Validate("lixo-sem-ponto", Scope{}); !errors.Is(err, ErrMalformed) {
		t.Fatalf("malformado deve ser ErrMalformed, got %v", err)
	}
}

func TestScopeMismatchAndEmptyBypassFixed(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	m := newTestManager(&now)
	mt := mint(t, m, MintRequest{Type: Deployment, MaxUses: 9, Scope: Scope{Tenant: "acme", OS: "linux"}, TTL: time.Hour})
	if _, err := m.Consume(mt.Token, Enrollment{AgentID: "a", OS: "windows"}); !errors.Is(err, ErrScopeMismatch) {
		t.Fatalf("os divergente deve ser ErrScopeMismatch, got %v", err)
	}
	// O bug corrigido: apresentar OS vazio NÃO satisfaz um token pinado.
	if _, err := m.Consume(mt.Token, Enrollment{AgentID: "a", OS: ""}); !errors.Is(err, ErrScopeMismatch) {
		t.Fatalf("os vazio deve ser ErrScopeMismatch (bypass corrigido), got %v", err)
	}
	if _, err := m.Consume(mt.Token, Enrollment{AgentID: "a", OS: "linux"}); err != nil {
		t.Fatalf("os correto deve passar: %v", err)
	}
}

func TestMintRequiresTenant(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	m := newTestManager(&now)
	if _, err := m.Mint(MintRequest{Type: SingleHost, TTL: time.Hour}); err == nil {
		t.Fatal("mint sem Tenant deve falhar")
	}
}

func TestMintCapsMaxUses(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	m := newTestManager(&now)
	if _, err := m.Mint(MintRequest{Type: Deployment, MaxUses: MaxDeploymentUses + 1, Scope: Scope{Tenant: "acme"}, TTL: time.Hour}); err == nil {
		t.Fatal("MaxUses acima do teto deve falhar")
	}
}

func TestAuditTrail(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	m := newTestManager(&now)
	mt := mint(t, m, MintRequest{Type: Deployment, MaxUses: 2, TTL: time.Hour})
	rec, err := m.Consume(mt.Token, Enrollment{AgentID: "a1", OS: "linux", Arch: "amd64"})
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
	mt := mint(t, m, MintRequest{Type: Deployment, MaxUses: limit, TTL: time.Hour})
	var wg sync.WaitGroup
	var mu sync.Mutex
	ok := 0
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			agentID := fmt.Sprintf("host-%d", idx)
			if _, err := m.Consume(mt.Token, Enrollment{AgentID: agentID}); err == nil {
				mu.Lock()
				ok++
				mu.Unlock()
			}
		}(i)
	}
	wg.Wait()
	if ok != limit {
		t.Fatalf("consumos bem-sucedidos = %d, want %d", ok, limit)
	}
}

func TestAgentIDUniqueness(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	m := newTestManager(&now)

	// Dois tokens diferentes — mesmo agent_id no segundo deve falhar.
	t1 := mint(t, m, MintRequest{Type: SingleHost, TTL: time.Hour})
	t2 := mint(t, m, MintRequest{Type: SingleHost, TTL: time.Hour})

	if _, err := m.Consume(t1.Token, Enrollment{AgentID: "srv-01"}); err != nil {
		t.Fatalf("primeiro enroll deve passar: %v", err)
	}
	if _, err := m.Consume(t2.Token, Enrollment{AgentID: "srv-01"}); !errors.Is(err, ErrAgentAlreadyExists) {
		t.Fatalf("mesmo agent_id com outro token deve retornar ErrAgentAlreadyExists, got %v", err)
	}
}

func TestAgentIDUniqueness_DeploymentToken(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	m := newTestManager(&now)
	mt := mint(t, m, MintRequest{Type: Deployment, MaxUses: 5, TTL: time.Hour})

	if _, err := m.Consume(mt.Token, Enrollment{AgentID: "host-A"}); err != nil {
		t.Fatalf("primeiro enroll deve passar: %v", err)
	}
	// Mesmo token, mesmo agent_id — deve falhar (não é re-enroll legítimo).
	if _, err := m.Consume(mt.Token, Enrollment{AgentID: "host-A"}); !errors.Is(err, ErrAgentAlreadyExists) {
		t.Fatalf("duplicate agent_id via deployment token deve ser ErrAgentAlreadyExists, got %v", err)
	}
	// Agent diferente ainda deve funcionar.
	if _, err := m.Consume(mt.Token, Enrollment{AgentID: "host-B"}); err != nil {
		t.Fatalf("agent diferente deve passar: %v", err)
	}
}
