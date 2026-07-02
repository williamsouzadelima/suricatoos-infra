package supervisor

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"testing"

	"github.com/williamsouzadelima/suricatoos-infra/sensor/internal/cloud"
	"github.com/williamsouzadelima/suricatoos-infra/sensor/internal/scanrun"
)

type fakeCloud struct {
	mu      sync.Mutex
	jobs    []*cloud.Job
	acked   []string
	reports []cloud.Report
	beats   int
	pushErr error
}

func (f *fakeCloud) PollJob(context.Context) (*cloud.Job, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.jobs) == 0 {
		return nil, false, nil
	}
	j := f.jobs[0]
	f.jobs = f.jobs[1:]
	return j, true, nil
}
func (f *fakeCloud) AckJob(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.acked = append(f.acked, id)
	return nil
}
func (f *fakeCloud) PushReport(_ context.Context, r cloud.Report) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.pushErr != nil {
		return f.pushErr
	}
	f.reports = append(f.reports, r)
	return nil
}
func (f *fakeCloud) Heartbeat(context.Context, cloud.Heartbeat) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.beats++
	return nil
}

type fakeScanner struct {
	findings []scanrun.Finding
	dropped  int
	err      error
	gotJob   scanrun.Job
}

func (f *fakeScanner) Run(_ context.Context, job scanrun.Job) ([]scanrun.Finding, int, error) {
	f.gotJob = job
	return f.findings, f.dropped, f.err
}

func newSup(cl CloudClient, sc Scanner) *Supervisor {
	return New(Config{SensorID: "sensor-acme-1", FeedVersion: func() string { return "v42" }}, cl, sc)
}

func TestPollOnceProcessesJob(t *testing.T) {
	cl := &fakeCloud{jobs: []*cloud.Job{{JobID: "j1", CorrelationID: "c1",
		Targets: []string{"10.20.0.0/24"}, Ports: "T:1-1000"}}}
	sc := &fakeScanner{findings: []scanrun.Finding{{Host: "10.20.5.5", OID: "o1"}}}
	newSup(cl, sc).pollOnce(context.Background())

	if len(cl.acked) != 1 || cl.acked[0] != "j1" {
		t.Fatalf("job deveria ser ackado, got %v", cl.acked)
	}
	if len(cl.reports) != 1 {
		t.Fatalf("deveria empurrar 1 report, got %d", len(cl.reports))
	}
	rep := cl.reports[0]
	if rep.CorrelationID != "c1" || rep.SensorID != "sensor-acme-1" || rep.FeedVersion != "v42" {
		t.Fatalf("report errado: %+v", rep)
	}
	var fs []scanrun.Finding
	json.Unmarshal(rep.Findings, &fs)
	if len(fs) != 1 || fs[0].OID != "o1" {
		t.Fatalf("findings do report errados: %s", rep.Findings)
	}
	// O job passado ao scanner preserva correlation/targets/ports.
	if sc.gotJob.CorrelationID != "c1" || sc.gotJob.Ports != "T:1-1000" {
		t.Fatalf("job repassado errado: %+v", sc.gotJob)
	}
}

func TestPollOnceIdle(t *testing.T) {
	cl := &fakeCloud{} // sem jobs
	sc := &fakeScanner{}
	newSup(cl, sc).pollOnce(context.Background())
	if len(cl.reports) != 0 || len(cl.acked) != 0 {
		t.Fatal("sem job, nada deveria acontecer")
	}
}

func TestScanErrorNotAcked(t *testing.T) {
	cl := &fakeCloud{jobs: []*cloud.Job{{JobID: "j1", CorrelationID: "c1", Targets: []string{"10.20.0.0/24"}}}}
	sc := &fakeScanner{err: fmt.Errorf("gvmd down")}
	newSup(cl, sc).pollOnce(context.Background())
	if len(cl.reports) != 0 {
		t.Fatal("scan com erro não deveria empurrar report")
	}
	// Fix #9: um scan que falha NÃO é ackado → a nuvem re-entrega após a janela
	// (scanrun é idempotente via find-or-create). Ackar cedo perdia os achados.
	if len(cl.acked) != 0 {
		t.Fatalf("scan com erro NÃO deveria ackar (mantido p/ redelivery), got %v", cl.acked)
	}
}

func TestPushErrorNotAcked(t *testing.T) {
	cl := &fakeCloud{
		jobs:    []*cloud.Job{{JobID: "j1", CorrelationID: "c1", Targets: []string{"10.20.0.0/24"}}},
		pushErr: fmt.Errorf("ingest 502"),
	}
	sc := &fakeScanner{findings: []scanrun.Finding{{Host: "10.20.5.5", OID: "o1"}}}
	newSup(cl, sc).pollOnce(context.Background())
	// Fix #9: PushReport falhou (transiente) → job NÃO ackado, senão os achados do
	// tenant somem silenciosamente. Fica DELIVERED → re-entregue.
	if len(cl.acked) != 0 {
		t.Fatalf("push falho NÃO deveria ackar (findings seriam perdidos), got %v", cl.acked)
	}
}

func TestEmptyFindingsStillReports(t *testing.T) {
	cl := &fakeCloud{jobs: []*cloud.Job{{JobID: "j1", CorrelationID: "c1", Targets: []string{"10.20.0.0/24"}}}}
	sc := &fakeScanner{findings: nil} // scan limpo, zero achados
	newSup(cl, sc).pollOnce(context.Background())
	if len(cl.reports) != 1 {
		t.Fatal("scan limpo ainda deveria reportar (host coberto, 0 achados)")
	}
	if string(cl.reports[0].Findings) != "[]" {
		t.Fatalf("findings vazio deveria ser [], got %s", cl.reports[0].Findings)
	}
}

func TestHeartbeat(t *testing.T) {
	cl := &fakeCloud{}
	s := newSup(cl, &fakeScanner{})
	s.heartbeat(context.Background())
	if cl.beats != 1 {
		t.Fatalf("heartbeat deveria ter sido enviado, got %d", cl.beats)
	}
}
