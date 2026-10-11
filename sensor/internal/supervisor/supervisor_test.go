package supervisor

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/williamsouzadelima/suricatoos-infra/sensor/internal/cloud"
	"github.com/williamsouzadelima/suricatoos-infra/sensor/internal/scanrun"
)

type fakeCloud struct {
	mu      sync.Mutex
	jobs    []*cloud.Job
	acked   []string
	reports []cloud.Report
	beats   int
	hbs     []cloud.Heartbeat // payload of every heartbeat, in order
	polls   int
	pushErr error
}

func (f *fakeCloud) PollJob(context.Context) (*cloud.Job, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.polls++
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
func (f *fakeCloud) Heartbeat(_ context.Context, hb cloud.Heartbeat) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.beats++
	f.hbs = append(f.hbs, hb)
	return nil
}

// Locked accessors for the tests that run the supervisor in goroutines (the older
// tests drive pollOnce/heartbeat synchronously and read the fields directly).
func (f *fakeCloud) beatPayloads() []cloud.Heartbeat {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]cloud.Heartbeat(nil), f.hbs...)
}
func (f *fakeCloud) pollCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.polls
}
func (f *fakeCloud) ackedIDs() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.acked...)
}
func (f *fakeCloud) reportCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.reports)
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

// --- P1.9a: heartbeat independente do scan -------------------------------------

// slowScanner stands in for an hours-long scan: Run announces itself on `started`
// and then blocks until `release` is closed (or ctx is cancelled, like a real scan).
type slowScanner struct {
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func newSlowScanner() *slowScanner {
	return &slowScanner{started: make(chan struct{}), release: make(chan struct{})}
}

func (s *slowScanner) Run(ctx context.Context, _ scanrun.Job) ([]scanrun.Finding, int, error) {
	s.once.Do(func() { close(s.started) })
	select {
	case <-s.release:
		return []scanrun.Finding{{Host: "10.20.5.5", OID: "o1"}}, 0, nil
	case <-ctx.Done():
		return nil, 0, ctx.Err()
	}
}

// eventually bounds how long a test waits for an asynchronous condition. It is
// deliberately generous: it only limits a HUNG test, never the happy path.
const eventually = 5 * time.Second

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(eventually)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timeout esperando: %s", what)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func waitStarted(t *testing.T, sc *slowScanner) {
	t.Helper()
	select {
	case <-sc.started:
	case <-time.After(eventually):
		t.Fatal("o scan não chegou a iniciar")
	}
}

// fastCfg runs both loops on a few-millisecond cadence.
func fastCfg() Config {
	return Config{
		SensorID:       "sensor-acme-1",
		FeedVersion:    func() string { return "v42" },
		PollInterval:   5 * time.Millisecond,
		HeartbeatEvery: 5 * time.Millisecond,
	}
}

// start runs s.Run in a goroutine. The returned stop cancels the context and
// requires Run to return; it is idempotent and also registered as a cleanup.
func start(t *testing.T, s *Supervisor) (stop func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.Run(ctx); close(done) }()
	var once sync.Once
	stop = func() {
		once.Do(func() {
			cancel()
			select {
			case <-done:
			case <-time.After(eventually):
				t.Error("Run não encerrou após o cancelamento do ctx")
			}
		})
	}
	t.Cleanup(stop)
	return stop
}

func oneJobCloud() *fakeCloud {
	return &fakeCloud{jobs: []*cloud.Job{{JobID: "j1", CorrelationID: "c1", Targets: []string{"10.20.0.0/24"}}}}
}

// Um scan leva horas e roda INLINE no laço de poll. O heartbeat precisa continuar
// saindo durante ele — senão a nuvem vê o sensor "sumido" exatamente quando ele
// está trabalhando.
func TestHeartbeatKeepsBeatingDuringLongScan(t *testing.T) {
	cl := oneJobCloud()
	sc := newSlowScanner()
	stop := start(t, New(fastCfg(), cl, sc))
	waitStarted(t, sc)

	// O scan está BLOQUEADO. Todo heartbeat contado a partir daqui saiu durante ele.
	before := len(cl.beatPayloads())
	waitFor(t, "heartbeats enquanto o scan está em andamento",
		func() bool { return len(cl.beatPayloads())-before >= 3 })

	// Scan ainda em andamento: nem ack nem report.
	if got := cl.ackedIDs(); len(got) != 0 {
		t.Fatalf("job não pode ser ackado com o scan em andamento, got %v", got)
	}
	if n := cl.reportCount(); n != 0 {
		t.Fatalf("não deveria haver report com o scan em andamento, got %d", n)
	}

	// Scan termina: report empurrado e ack, como antes.
	close(sc.release)
	waitFor(t, "ack do job depois do fim do scan", func() bool { return len(cl.ackedIDs()) == 1 })
	if got := cl.ackedIDs(); got[0] != "j1" {
		t.Fatalf("ack do job errado: %v", got)
	}
	if n := cl.reportCount(); n != 1 {
		t.Fatalf("deveria empurrar 1 report, got %d", n)
	}
	stop()
}

// O heartbeat também precisa dizer a verdade sobre o trabalho em curso: active_jobs
// é 1 enquanto há scan em andamento e volta a 0 quando ele termina.
func TestHeartbeatReportsActiveJobs(t *testing.T) {
	cl := oneJobCloud()
	sc := newSlowScanner()
	stop := start(t, New(fastCfg(), cl, sc))
	waitStarted(t, sc)

	activeBeats := func() (n int) {
		for _, hb := range cl.beatPayloads() {
			if hb.ActiveJobs == 1 {
				n++
			}
		}
		return n
	}
	waitFor(t, "heartbeats com active_jobs=1 durante o scan", func() bool { return activeBeats() >= 2 })

	close(sc.release)
	waitFor(t, "ack do job depois do fim do scan", func() bool { return len(cl.ackedIDs()) == 1 })

	// Só vale a partir daqui: um heartbeat já gravado não prova que o contador baixou.
	seen := len(cl.beatPayloads())
	waitFor(t, "heartbeat com active_jobs=0 depois do scan", func() bool {
		for _, hb := range cl.beatPayloads()[seen:] {
			if hb.ActiveJobs == 0 {
				return true
			}
		}
		return false
	})
	stop()

	// Um scan por vez: nenhum heartbeat pode anunciar mais que 1 (nem menos que 0).
	for i, hb := range cl.beatPayloads() {
		if hb.ActiveJobs < 0 || hb.ActiveJobs > 1 {
			t.Fatalf("heartbeat %d com active_jobs=%d (esperado 0 ou 1)", i, hb.ActiveJobs)
		}
	}
}

// Sem job, todo heartbeat leva a identidade do sensor e active_jobs=0.
func TestHeartbeatIdlePayload(t *testing.T) {
	cl := &fakeCloud{} // sem jobs
	stop := start(t, New(fastCfg(), cl, &fakeScanner{}))
	waitFor(t, "alguns heartbeats", func() bool { return len(cl.beatPayloads()) >= 3 })
	stop()

	for i, hb := range cl.beatPayloads() {
		if hb.SensorID != "sensor-acme-1" || hb.FeedVersion != "v42" || !hb.GvmdUp || hb.ActiveJobs != 0 {
			t.Fatalf("heartbeat ocioso %d errado: %+v", i, hb)
		}
	}
}

// Quem sobe o sensor continua sendo anunciado de imediato, sem esperar o 1º tick.
func TestRunAnnouncesPresenceImmediately(t *testing.T) {
	cl := &fakeCloud{}
	cfg := fastCfg()
	cfg.PollInterval = time.Hour
	cfg.HeartbeatEvery = time.Hour
	stop := start(t, New(cfg, cl, &fakeScanner{}))
	waitFor(t, "heartbeat imediato", func() bool { return len(cl.beatPayloads()) >= 1 })
	stop()
	if got := len(cl.beatPayloads()); got != 1 {
		t.Fatalf("com tickers de 1h só o heartbeat imediato deveria ter saído, got %d", got)
	}
}

// ctx cancelado encerra as DUAS goroutines: depois que Run retorna, nem heartbeat
// nem poll podem continuar acontecendo em segundo plano.
func TestCancelStopsPollAndHeartbeatLoops(t *testing.T) {
	cl := &fakeCloud{}
	stop := start(t, New(fastCfg(), cl, &fakeScanner{}))
	waitFor(t, "os dois laços ativos", func() bool {
		return len(cl.beatPayloads()) >= 2 && cl.pollCount() >= 2
	})
	stop() // cancela e exige que Run retorne

	beats, polls := len(cl.beatPayloads()), cl.pollCount()
	time.Sleep(50 * time.Millisecond) // ~10 períodos de cada laço
	if got := len(cl.beatPayloads()); got != beats {
		t.Fatalf("heartbeat continuou depois de Run retornar: %d → %d", beats, got)
	}
	if got := cl.pollCount(); got != polls {
		t.Fatalf("poll continuou depois de Run retornar: %d → %d", polls, got)
	}
}

// Cancelar no meio de um scan: o scanner devolve o erro do ctx, o job NÃO é ackado
// (a nuvem re-entrega) e Run encerra mesmo assim.
func TestCancelDuringScanEndsRunWithoutAck(t *testing.T) {
	cl := oneJobCloud()
	sc := newSlowScanner()
	stop := start(t, New(fastCfg(), cl, sc))
	waitStarted(t, sc)
	stop()

	if got := cl.ackedIDs(); len(got) != 0 {
		t.Fatalf("scan interrompido NÃO deveria ser ackado (re-entrega), got %v", got)
	}
	if n := cl.reportCount(); n != 0 {
		t.Fatalf("scan interrompido não deveria empurrar report, got %d", n)
	}
}
