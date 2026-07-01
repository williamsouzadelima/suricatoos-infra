package scanlaunch

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"
)

type fakeRunner struct {
	mu     sync.Mutex
	calls  map[string]int
	launch func(*Job) (*bridgeResult, error)
	status func(*Job) (*bridgeResult, error)
	fetch  func(*Job) (*bridgeResult, error)
	stop   func(*Job) (*bridgeResult, error)
}

func newFakeRunner() *fakeRunner { return &fakeRunner{calls: map[string]int{}} }

func (f *fakeRunner) run(_ context.Context, sub string, j *Job) (*bridgeResult, error) {
	f.mu.Lock()
	f.calls[sub]++
	f.mu.Unlock()
	switch sub {
	case "launch":
		if f.launch != nil {
			return f.launch(j)
		}
		return &bridgeResult{TargetID: "tg1", TaskID: "t1", Status: "Requested"}, nil
	case "status":
		if f.status != nil {
			return f.status(j)
		}
		return &bridgeResult{Status: "Running", Progress: 50}, nil
	case "fetch":
		if f.fetch != nil {
			return f.fetch(j)
		}
		return &bridgeResult{Findings: nil}, nil
	case "stop":
		if f.stop != nil {
			return f.stop(j)
		}
		return &bridgeResult{Stopped: true}, nil
	}
	return nil, fmt.Errorf("subcommand desconhecido %q", sub)
}

func testRecCfg(t *testing.T) Config {
	return Config{MaxConcurrent: 2, MaxDuration: 6 * time.Hour, MaxHosts: 256, MaxPorts: 1000,
		FindingsDir: t.TempDir(), TickInterval: time.Hour}
}

func seedPending(r *Registry, scanID int64) *Job {
	j, _, _ := r.FindOrCreate(&ScanRequest{RengineScanHistoryID: scanID, Target: fmt.Sprintf("t%d.com", scanID),
		Hosts: []Host{{IP: "203.0.113.10", Ports: []int{80}}}}, testIdentity(), 0)
	return j
}

func TestReconcilerLaunch(t *testing.T) {
	r, _ := NewRegistry("")
	j := seedPending(r, 1)
	f := newFakeRunner()
	rc := newReconciler(r, testRecCfg(t), f.run)
	rc.tick(context.Background())

	got, _ := r.Get(j.RequestID)
	if got.State != StateRunning || got.GVMTaskID != "t1" {
		t.Fatalf("esperado RUNNING/t1, got %+v", got)
	}
}

func TestReconcilerLaunchError(t *testing.T) {
	r, _ := NewRegistry("")
	j := seedPending(r, 1)
	f := newFakeRunner()
	f.launch = func(*Job) (*bridgeResult, error) { return nil, fmt.Errorf("gvmd down") }
	rc := newReconciler(r, testRecCfg(t), f.run)
	rc.tick(context.Background())

	got, _ := r.Get(j.RequestID)
	if got.State != StateFailed || got.Error == "" {
		t.Fatalf("launch com erro deveria FAILED, got %+v", got)
	}
}

func TestReconcilerConcurrencyCap(t *testing.T) {
	r, _ := NewRegistry("")
	seedPending(r, 1)
	seedPending(r, 2)
	seedPending(r, 3)
	cfg := testRecCfg(t)
	cfg.MaxConcurrent = 1
	f := newFakeRunner()
	// status keeps them Running so they occupy the slot.
	rc := newReconciler(r, cfg, f.run)
	rc.tick(context.Background())

	if n := r.CountActive(); n != 1 {
		t.Fatalf("MaxConcurrent=1 deveria lançar exatamente 1, ativo=%d", n)
	}
}

func TestReconcilerCompleteFetchesFindings(t *testing.T) {
	r, _ := NewRegistry("")
	j := seedPending(r, 1)
	r.Update(j.RequestID, func(job *Job) { job.State = StateRunning; job.StartedAt = time.Now() })

	f := newFakeRunner()
	f.status = func(*Job) (*bridgeResult, error) {
		return &bridgeResult{Status: "Done", Progress: 100, ReportID: "rep1"}, nil
	}
	f.fetch = func(*Job) (*bridgeResult, error) {
		return &bridgeResult{Findings: []Finding{{Host: "203.0.113.10", Port: "443/tcp", OID: "1.2.3", Name: "TLS weak", CVSSBase: 7.5}}}, nil
	}
	rc := newReconciler(r, testRecCfg(t), f.run)
	rc.tick(context.Background())

	got, _ := r.Get(j.RequestID)
	if got.State != StateCompleted || got.Progress != 100 {
		t.Fatalf("esperado COMPLETED, got %+v", got)
	}
	fs := readFindings(rc.findingsDir, j.RequestID)
	if len(fs) != 1 || fs[0].OID != "1.2.3" {
		t.Fatalf("findings não cacheados corretamente: %+v", fs)
	}
	if f.calls["fetch"] != 1 {
		t.Fatalf("fetch deveria ser chamado exatamente 1x, got %d", f.calls["fetch"])
	}
}

func TestReconcilerStop(t *testing.T) {
	r, _ := NewRegistry("")
	j := seedPending(r, 1)
	r.Update(j.RequestID, func(job *Job) { job.State = StateRunning; job.StopRequested = true })
	f := newFakeRunner()
	rc := newReconciler(r, testRecCfg(t), f.run)
	rc.tick(context.Background())

	got, _ := r.Get(j.RequestID)
	if got.State != StateStopped {
		t.Fatalf("stop solicitado deveria STOPPED, got %s", got.State)
	}
	if f.calls["stop"] != 1 {
		t.Fatalf("stop do bridge deveria ser chamado, got %d", f.calls["stop"])
	}
}

func TestReconcilerMaxDurationExpires(t *testing.T) {
	r, _ := NewRegistry("")
	j := seedPending(r, 1)
	now := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	r.Update(j.RequestID, func(job *Job) { job.State = StateRunning; job.StartedAt = now.Add(-7 * time.Hour) })
	f := newFakeRunner()
	rc := newReconciler(r, testRecCfg(t), f.run)
	rc.now = func() time.Time { return now }
	rc.tick(context.Background())

	got, _ := r.Get(j.RequestID)
	if got.State != StateExpired {
		t.Fatalf("scan além de MaxDuration deveria EXPIRED, got %s", got.State)
	}
}
