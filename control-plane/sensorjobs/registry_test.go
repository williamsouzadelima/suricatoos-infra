package sensorjobs

import (
	"testing"
	"time"
)

// scopes builds a ScopeLookup from tenant→CIDR-spec.
func scopes(m map[string]string) ScopeLookup {
	return func(tenant string) *Scope {
		spec, ok := m[tenant]
		if !ok {
			return nil
		}
		s, _ := NewScope(spec)
		return s
	}
}

func testReg(t *testing.T) *Registry {
	t.Helper()
	r, err := NewRegistry(Config{
		ScopeOf:  scopes(map[string]string{"acme": "10.20.0.0/16", "globex": "192.168.0.0/16"}),
		Cooldown: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestEnqueueScopeGate(t *testing.T) {
	r := testReg(t)
	job, dropped, err := r.Enqueue(EnqueueRequest{Tenant: "acme", Targets: []string{"10.20.1.1", "8.8.8.8"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(job.Targets) != 1 || job.Targets[0] != "10.20.1.1" {
		t.Fatalf("alvo fora de escopo não foi dropado: %v", job.Targets)
	}
	if len(dropped) != 1 || dropped[0] != "8.8.8.8" {
		t.Fatalf("dropped errado: %v", dropped)
	}
	// Todos fora de escopo → nada é enfileirado.
	if _, _, err := r.Enqueue(EnqueueRequest{Tenant: "acme", Targets: []string{"1.2.3.4"}}); err == nil {
		t.Fatal("alvos totalmente fora de escopo deveriam falhar")
	}
	// Tenant desconhecido → deny-all.
	if _, _, err := r.Enqueue(EnqueueRequest{Tenant: "nobody", Targets: []string{"10.20.1.1"}}); err == nil {
		t.Fatal("tenant desconhecido deveria escanear nada")
	}
}

func TestEnqueueIdempotent(t *testing.T) {
	r := testReg(t)
	j1, _, _ := r.Enqueue(EnqueueRequest{Tenant: "acme", Targets: []string{"10.20.1.1"}, ScanConfig: "full-and-fast"})
	j2, _, _ := r.Enqueue(EnqueueRequest{Tenant: "acme", Targets: []string{"10.20.1.1"}, ScanConfig: "full-and-fast"})
	if j1.JobID != j2.JobID {
		t.Fatal("enqueue idêntico dentro do cooldown deveria colapsar no mesmo job")
	}
}

func TestPollTenantPartition(t *testing.T) {
	r := testReg(t)
	acme, _, _ := r.Enqueue(EnqueueRequest{Tenant: "acme", Targets: []string{"10.20.1.1"}})
	r.Enqueue(EnqueueRequest{Tenant: "globex", Targets: []string{"192.168.1.1"}})

	// O sensor da acme só vê o job da acme.
	got, ok := r.Poll("acme")
	if !ok || got.JobID != acme.JobID {
		t.Fatalf("acme deveria receber seu próprio job, got %+v", got)
	}
	// globex nunca vê o job da acme.
	g, ok := r.Poll("globex")
	if !ok || g.Tenant != "globex" {
		t.Fatalf("globex deveria receber só o seu job, got %+v", g)
	}
	// Um tenant sem jobs → 204.
	if _, ok := r.Poll("acme"); ok {
		t.Fatal("acme não deveria ter mais jobs pendentes (o único já foi entregue)")
	}
}

func TestPollUnguessableAndDelivered(t *testing.T) {
	r := testReg(t)
	r.Enqueue(EnqueueRequest{Tenant: "acme", Targets: []string{"10.20.1.1"}})
	got, _ := r.Poll("acme")
	if len(got.JobID) != 32 || len(got.CorrelationID) != 32 {
		t.Fatalf("ids deveriam ser 32 hex: job=%q corr=%q", got.JobID, got.CorrelationID)
	}
	if got.State != StateDelivered {
		t.Fatalf("poll deveria marcar DELIVERED, got %s", got.State)
	}
}

func TestAckOwnerScope(t *testing.T) {
	r := testReg(t)
	acme, _, _ := r.Enqueue(EnqueueRequest{Tenant: "acme", Targets: []string{"10.20.1.1"}})
	// globex não pode dar ack no job da acme (IDOR).
	if r.Ack(acme.JobID, "globex") {
		t.Fatal("ack cross-tenant deveria falhar")
	}
	if r.Ack(acme.JobID, "acme") != true {
		t.Fatal("ack do próprio tenant deveria funcionar")
	}
	got, _ := r.Get(acme.JobID, "acme")
	if got.State != StateAcked {
		t.Fatalf("estado deveria ser ACKED, got %s", got.State)
	}
	// Get cross-tenant → 404.
	if _, ok := r.Get(acme.JobID, "globex"); ok {
		t.Fatal("Get cross-tenant deveria falhar")
	}
}

func TestRedeliveryAfterCrash(t *testing.T) {
	r := testReg(t)
	r.redeliver = 5 * time.Minute
	now := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	r.now = func() time.Time { return now }
	r.Enqueue(EnqueueRequest{Tenant: "acme", Targets: []string{"10.20.1.1"}})

	first, _ := r.Poll("acme") // DELIVERED, não acked (sensor "crashou")
	// Imediatamente depois: não re-entrega (dentro da janela).
	if _, ok := r.Poll("acme"); ok {
		t.Fatal("não deveria re-entregar dentro da janela de redelivery")
	}
	// Após a janela: re-entrega o mesmo job.
	now = now.Add(6 * time.Minute)
	again, ok := r.Poll("acme")
	if !ok || again.JobID != first.JobID {
		t.Fatal("deveria re-entregar o mesmo job após a janela")
	}
}

func TestExpiry(t *testing.T) {
	r := testReg(t)
	now := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	r.now = func() time.Time { return now }
	r.Enqueue(EnqueueRequest{Tenant: "acme", Targets: []string{"10.20.1.1"}, TTL: time.Hour})
	now = now.Add(2 * time.Hour)
	if _, ok := r.Poll("acme"); ok {
		t.Fatal("job expirado não deveria ser entregue")
	}
}

func TestPersistRoundTrip(t *testing.T) {
	path := t.TempDir() + "/jobs.json"
	r, _ := NewRegistry(Config{Path: path, ScopeOf: scopes(map[string]string{"acme": "10.20.0.0/16"})})
	j, _, _ := r.Enqueue(EnqueueRequest{Tenant: "acme", Targets: []string{"10.20.1.1"}})
	r.Ack(j.JobID, "acme")

	r2, err := NewRegistry(Config{Path: path, ScopeOf: scopes(map[string]string{"acme": "10.20.0.0/16"})})
	if err != nil {
		t.Fatal(err)
	}
	got, ok := r2.Get(j.JobID, "acme")
	if !ok || got.State != StateAcked {
		t.Fatalf("job deveria persistir como ACKED, got %+v ok=%v", got, ok)
	}
}
