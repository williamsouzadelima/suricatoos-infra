package scanlaunch

import (
	"testing"
	"time"
)

func testIdentity() certIdentity {
	return certIdentity{CN: "score-hub-2026", O: "score-hub", OU: "scan-requester"}
}

func testReq(scanID int64, target string) *ScanRequest {
	return &ScanRequest{
		SchemaVersion:        SchemaVersion,
		RengineScanHistoryID: scanID,
		Target:               target,
		Hosts:                []Host{{IP: "203.0.113.10", Ports: []int{80, 443}}},
	}
}

func TestRegistryFindOrCreateIdempotent(t *testing.T) {
	r, _ := NewRegistry("")
	id := testIdentity()
	j1, created1, err := r.FindOrCreate(testReq(1234, "acme.com"), id, time.Hour)
	if err != nil || !created1 {
		t.Fatalf("primeira criação: created=%v err=%v", created1, err)
	}
	// Same scan_history_id → same job, not created again.
	j2, created2, err := r.FindOrCreate(testReq(1234, "acme.com"), id, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if created2 {
		t.Fatal("mesmo scan_history_id deveria ser idempotente (created=false)")
	}
	if j1.RequestID != j2.RequestID {
		t.Fatalf("replay idempotente deveria retornar o mesmo request_id: %s vs %s", j1.RequestID, j2.RequestID)
	}
}

func TestRegistryUnguessableID(t *testing.T) {
	r, _ := NewRegistry("")
	j, _, _ := r.FindOrCreate(testReq(1, "a.com"), testIdentity(), 0)
	if len(j.RequestID) != 32 { // 16 bytes hex
		t.Fatalf("request_id deveria ter 32 hex chars, got %q", j.RequestID)
	}
}

func TestRegistryCooldownCollapsesStorm(t *testing.T) {
	r, _ := NewRegistry("")
	now := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	r.now = func() time.Time { return now }
	id := testIdentity()

	j1, created1, _ := r.FindOrCreate(testReq(1, "acme.com"), id, 6*time.Hour)
	if !created1 {
		t.Fatal("primeiro scan deveria criar")
	}
	// A DIFFERENT scan_history_id for the SAME target within the window → collapse.
	now = now.Add(time.Hour)
	j2, created2, _ := r.FindOrCreate(testReq(2, "acme.com"), id, 6*time.Hour)
	if created2 {
		t.Fatal("rescan do mesmo alvo dentro do cooldown NÃO deveria criar novo job")
	}
	if j1.RequestID != j2.RequestID {
		t.Fatal("cooldown deveria retornar o job existente do alvo")
	}
	// After the window → a new scan is allowed.
	now = now.Add(6 * time.Hour)
	_, created3, _ := r.FindOrCreate(testReq(3, "acme.com"), id, 6*time.Hour)
	if !created3 {
		t.Fatal("após o cooldown um novo scan deveria ser permitido")
	}
}

func TestRegistryCooldownDistinctTargets(t *testing.T) {
	r, _ := NewRegistry("")
	id := testIdentity()
	r.FindOrCreate(testReq(1, "acme.com"), id, 6*time.Hour)
	_, created, _ := r.FindOrCreate(testReq(2, "other.com"), id, 6*time.Hour)
	if !created {
		t.Fatal("alvo diferente não deveria ser bloqueado pelo cooldown")
	}
}

func TestRegistryUpdateAndCountActive(t *testing.T) {
	r, _ := NewRegistry("")
	j, _, _ := r.FindOrCreate(testReq(1, "a.com"), testIdentity(), 0)
	if r.CountActive() != 0 {
		t.Fatal("PENDING não deveria contar como ativo")
	}
	r.Update(j.RequestID, func(job *Job) { job.State = StateRunning })
	if r.CountActive() != 1 {
		t.Fatal("RUNNING deveria contar como ativo")
	}
	got, ok := r.Get(j.RequestID)
	if !ok || got.State != StateRunning {
		t.Fatalf("Update não refletiu: %+v ok=%v", got, ok)
	}
}

func TestRegistryPersistRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/reg.json"
	r, _ := NewRegistry(path)
	j, _, err := r.FindOrCreate(testReq(99, "a.com"), testIdentity(), 0)
	if err != nil {
		t.Fatal(err)
	}
	r.Update(j.RequestID, func(job *Job) { job.State = StateCompleted; job.GVMTaskID = "task-1" })

	// Reload from disk.
	r2, err := NewRegistry(path)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := r2.Get(j.RequestID)
	if !ok {
		t.Fatal("job deveria persistir e recarregar")
	}
	if got.State != StateCompleted || got.GVMTaskID != "task-1" {
		t.Fatalf("estado não persistiu: %+v", got)
	}
}
