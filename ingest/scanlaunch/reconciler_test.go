package scanlaunch

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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
	// O consumidor precisa do motivo: EXPIRED sem error não diz por que o scan parou.
	if !strings.Contains(got.Error, "SCAN_MAX_DURATION") {
		t.Fatalf("EXPIRED deveria explicar o motivo em error, got %q", got.Error)
	}
	if f.calls["stop"] != 1 {
		t.Fatalf("scan ainda rodando além do limite deveria ser parado no gvmd, stop=%d", f.calls["stop"])
	}
}

// --- Done só vira COMPLETED quando o relatório mediu algo (D8) ---

// bridgeOut decodifica a saída do scan_bridge.py: os fakes falam o contrato REAL
// (nomes dos campos JSON incluídos), não structs montadas à mão.
func bridgeOut(t *testing.T, stdout string) *bridgeResult {
	t.Helper()
	var res bridgeResult
	if err := json.Unmarshal([]byte(stdout), &res); err != nil {
		t.Fatalf("saída do bridge inválida %q: %v", stdout, err)
	}
	return &res
}

// seedRunning semeia um job já lançado (RUNNING, task t1) iniciado em startedAt.
func seedRunning(r *Registry, scanID int64, startedAt time.Time) *Job {
	j := seedPending(r, scanID)
	got, _ := r.Update(j.RequestID, func(job *Job) {
		job.State = StateRunning
		job.GVMTaskID = "t1"
		job.StartedAt = startedAt
	})
	return got
}

func statusDone(*Job) (*bridgeResult, error) {
	return &bridgeResult{Status: "Done", Progress: 100, ReportID: "rep1"}, nil
}

func cachedFindingsExist(t *testing.T, dir, requestID string) bool {
	t.Helper()
	_, err := os.Stat(filepath.Join(dir, requestID+".json"))
	return err == nil
}

func TestReconcilerDoneSemHostMedidoFalha(t *testing.T) {
	r, _ := NewRegistry("")
	j := seedRunning(r, 1, time.Now())
	f := newFakeRunner()
	f.status = statusDone
	f.fetch = func(*Job) (*bridgeResult, error) {
		return bridgeOut(t, `{"findings": [], "hosts_scanned": 0, "report_missing": false}`), nil
	}
	rc := newReconciler(r, testRecCfg(t), f.run)
	rc.tick(context.Background())

	got, _ := r.Get(j.RequestID)
	if got.State != StateFailed || got.Error != "scan não mediu nenhum host vivo (verifique alive test/alcance)" {
		t.Fatalf("Done sem host medido deveria FAILED explícito (não COMPLETED vazio), got state=%s err=%q", got.State, got.Error)
	}
	if got.GVMReportID != "rep1" || got.CompletedAt.IsZero() {
		t.Fatalf("FAILED deveria guardar o report (p/ inspeção na GSA) e o fim, got report=%q completed=%v", got.GVMReportID, got.CompletedAt)
	}
	if cachedFindingsExist(t, rc.findingsDir, j.RequestID) {
		t.Fatal("scan que não mediu nada NÃO deveria gravar cache de achados")
	}
}

func TestReconcilerDoneSemRelatorioFalha(t *testing.T) {
	r, _ := NewRegistry("")
	j := seedRunning(r, 1, time.Now())
	f := newFakeRunner()
	f.status = statusDone
	f.fetch = func(*Job) (*bridgeResult, error) {
		return bridgeOut(t, `{"findings": [], "hosts_scanned": 0, "report_missing": true}`), nil
	}
	rc := newReconciler(r, testRecCfg(t), f.run)
	rc.tick(context.Background())

	got, _ := r.Get(j.RequestID)
	if got.State != StateFailed || got.Error != "task Done sem relatório" {
		t.Fatalf("task Done sem relatório deveria FAILED com esse motivo, got state=%s err=%q", got.State, got.Error)
	}
	if cachedFindingsExist(t, rc.findingsDir, j.RequestID) {
		t.Fatal("sem relatório NÃO deveria gravar cache de achados")
	}
}

func TestReconcilerDoneComHostLimpoCompleta(t *testing.T) {
	// Host medido sem achado é resultado legítimo: continua COMPLETED.
	r, _ := NewRegistry("")
	j := seedRunning(r, 1, time.Now())
	f := newFakeRunner()
	f.status = statusDone
	f.fetch = func(*Job) (*bridgeResult, error) {
		return bridgeOut(t, `{"findings": [], "hosts_scanned": 2, "report_missing": false}`), nil
	}
	rc := newReconciler(r, testRecCfg(t), f.run)
	rc.tick(context.Background())

	got, _ := r.Get(j.RequestID)
	if got.State != StateCompleted || got.Progress != 100 || got.Error != "" {
		t.Fatalf("hosts>0 com 0 achados deveria COMPLETED, got state=%s progress=%d err=%q", got.State, got.Progress, got.Error)
	}
}

func TestReconcilerBridgeAntigoSemHostsScannedMantemComportamento(t *testing.T) {
	// Bridge anterior a hosts_scanned/report_missing: ausência NÃO é "0 hosts".
	r, _ := NewRegistry("")
	j := seedRunning(r, 1, time.Now())
	f := newFakeRunner()
	f.status = statusDone
	f.fetch = func(*Job) (*bridgeResult, error) { return bridgeOut(t, `{"findings": []}`), nil }
	rc := newReconciler(r, testRecCfg(t), f.run)
	rc.tick(context.Background())

	got, _ := r.Get(j.RequestID)
	if got.State != StateCompleted {
		t.Fatalf("saída sem hosts_scanned deveria manter o comportamento antigo (COMPLETED), got state=%s err=%q", got.State, got.Error)
	}
}

// --- Erros respeitam limites: nada fica RUNNING para sempre ocupando slot ---

func TestReconcilerStatusComErroAlemDoLimiteExpira(t *testing.T) {
	// Registry em arquivo: o contador de falhas de status é persistido (restart no meio).
	path := filepath.Join(t.TempDir(), "scan-requests.json")
	r, _ := NewRegistry(path)
	now := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	j := seedRunning(r, 1, now.Add(-7*time.Hour))
	f := newFakeRunner()
	f.status = func(*Job) (*bridgeResult, error) { return nil, fmt.Errorf("gvmd.sock: connection refused") }
	rc := newReconciler(r, testRecCfg(t), f.run)
	rc.now = func() time.Time { return now }

	// Uma falha isolada (ex.: gvmd reiniciando) não expira um scan que pode estar Done.
	rc.tick(context.Background())
	if got, _ := r.Get(j.RequestID); got.State != StateRunning || f.calls["stop"] != 0 {
		t.Fatalf("1ª falha de status além do limite não deveria expirar, got state=%s stop=%d", got.State, f.calls["stop"])
	}
	r2, err := NewRegistry(path) // restart do ingest
	if err != nil {
		t.Fatal(err)
	}
	rc = newReconciler(r2, testRecCfg(t), f.run)
	rc.now = func() time.Time { return now }
	rc.tick(context.Background())
	if got, _ := r2.Get(j.RequestID); got.State != StateRunning {
		t.Fatalf("2ª falha consecutiva não deveria expirar, got %s", got.State)
	}
	rc.tick(context.Background())

	got, _ := r2.Get(j.RequestID)
	if got.State != StateExpired {
		t.Fatalf("3ª falha consecutiva de status além do MaxDuration deveria EXPIRED, got %s", got.State)
	}
	if !strings.Contains(got.Error, "sem status do gvmd além do limite") || !strings.Contains(got.Error, "connection refused") {
		t.Fatalf("error deveria explicar a expiração e trazer o erro do status, got %q", got.Error)
	}
	if !got.CompletedAt.Equal(now) {
		t.Fatalf("CompletedAt deveria ser o instante da expiração, got %v", got.CompletedAt)
	}
	if f.calls["stop"] != 1 {
		t.Fatalf("deveria tentar parar a task no gvmd (best effort), stop=%d", f.calls["stop"])
	}
}

func TestReconcilerStatusComSucessoZeraAsFalhas(t *testing.T) {
	r, _ := NewRegistry("")
	now := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	j := seedRunning(r, 1, now.Add(-5*time.Hour)) // ainda dentro do limite (6h)
	f := newFakeRunner()
	fail := true
	f.status = func(*Job) (*bridgeResult, error) {
		if fail {
			return nil, fmt.Errorf("gvmd ocupado")
		}
		return &bridgeResult{Status: "Running", Progress: 60}, nil
	}
	rc := newReconciler(r, testRecCfg(t), f.run)
	rc.now = func() time.Time { return now }

	rc.tick(context.Background()) // falha 1
	rc.tick(context.Background()) // falha 2
	fail = false
	rc.tick(context.Background()) // status OK: zera a contagem
	fail = true
	now = now.Add(2 * time.Hour)  // agora além do limite
	rc.tick(context.Background()) // falha 1
	rc.tick(context.Background()) // falha 2
	if got, _ := r.Get(j.RequestID); got.State != StateRunning || f.calls["stop"] != 0 {
		t.Fatalf("o status OK no meio deveria zerar a contagem (2 falhas seguidas não expiram), got state=%s stop=%d", got.State, f.calls["stop"])
	}
	rc.tick(context.Background()) // falha 3 seguida
	if got, _ := r.Get(j.RequestID); got.State != StateExpired {
		t.Fatalf("3 falhas seguidas além do limite deveriam EXPIRED, got %s", got.State)
	}
}

func TestReconcilerStatusComErroDentroDoLimiteRetenta(t *testing.T) {
	r, _ := NewRegistry("")
	now := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	j := seedRunning(r, 1, now.Add(-time.Hour))
	f := newFakeRunner()
	f.status = func(*Job) (*bridgeResult, error) { return nil, fmt.Errorf("gvmd.sock: connection refused") }
	rc := newReconciler(r, testRecCfg(t), f.run)
	rc.now = func() time.Time { return now }
	rc.tick(context.Background())

	got, _ := r.Get(j.RequestID)
	if got.State != StateRunning || f.calls["stop"] != 0 {
		t.Fatalf("erro transitório dentro do limite deveria seguir RUNNING sem parar, got state=%s stop=%d", got.State, f.calls["stop"])
	}
}

func TestReconcilerFetchComErroRetentaAteOLimiteEFalha(t *testing.T) {
	// Registry em arquivo: o contador de falhas é persistido, então um restart do
	// ingest no meio das re-tentativas não zera o limite.
	path := filepath.Join(t.TempDir(), "scan-requests.json")
	r, _ := NewRegistry(path)
	j := seedRunning(r, 1, time.Now())
	f := newFakeRunner()
	f.status = statusDone
	n := 0
	f.fetch = func(*Job) (*bridgeResult, error) { n++; return nil, fmt.Errorf("get_report timeout #%d", n) }
	cfg := testRecCfg(t)
	cfg.FetchRetryLimit = 3

	newReconciler(r, cfg, f.run).tick(context.Background())
	if got, _ := r.Get(j.RequestID); got.State != StateRunning {
		t.Fatalf("1ª falha de fetch (abaixo do limite) deveria seguir RUNNING, got %s", got.State)
	}

	r2, err := NewRegistry(path) // restart do ingest
	if err != nil {
		t.Fatal(err)
	}
	rc2 := newReconciler(r2, cfg, f.run)
	rc2.tick(context.Background())
	if got, _ := r2.Get(j.RequestID); got.State != StateRunning {
		t.Fatalf("2ª falha de fetch (abaixo do limite) deveria seguir RUNNING, got %s", got.State)
	}
	rc2.tick(context.Background())
	got, _ := r2.Get(j.RequestID)
	if got.State != StateFailed || !strings.Contains(got.Error, "get_report timeout #3") {
		t.Fatalf("3ª falha (= limite, contando o restart) deveria FAILED com o último erro, got state=%s err=%q", got.State, got.Error)
	}
	if got.CompletedAt.IsZero() || cachedFindingsExist(t, rc2.findingsDir, j.RequestID) {
		t.Fatalf("FAILED deveria ter CompletedAt e nenhum cache de achados, got completed=%v", got.CompletedAt)
	}
	rc2.tick(context.Background())
	if f.calls["fetch"] != 3 {
		t.Fatalf("job terminal não re-tenta: fetch deveria parar em 3 chamadas, got %d", f.calls["fetch"])
	}
}

func TestConfigFromEnvLeOLimiteDeFetch(t *testing.T) {
	t.Setenv("SCAN_FETCH_RETRY_LIMIT", "5")
	if got := ConfigFromEnv().FetchRetryLimit; got != 5 {
		t.Fatalf("SCAN_FETCH_RETRY_LIMIT=5 deveria configurar o limite, got %d", got)
	}
}

func TestReconcilerFalhaAoCachearAchadosTambemTemLimite(t *testing.T) {
	r, _ := NewRegistry("")
	j := seedRunning(r, 1, time.Now())
	f := newFakeRunner()
	f.status = statusDone
	f.fetch = func(*Job) (*bridgeResult, error) {
		return bridgeOut(t, `{"findings": [{"host": "203.0.113.10", "port": "443/tcp", "oid": "1.2.3"}], "hosts_scanned": 1, "report_missing": false}`), nil
	}
	cfg := testRecCfg(t)
	blocker := filepath.Join(t.TempDir(), "arquivo")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.FindingsDir = filepath.Join(blocker, "findings") // MkdirAll falha: o "pai" é um arquivo
	cfg.FetchRetryLimit = 2
	rc := newReconciler(r, cfg, f.run)

	rc.tick(context.Background())
	if got, _ := r.Get(j.RequestID); got.State != StateRunning {
		t.Fatalf("1ª falha ao cachear (abaixo do limite) deveria seguir RUNNING, got %s", got.State)
	}
	rc.tick(context.Background())
	got, _ := r.Get(j.RequestID)
	if got.State != StateFailed || got.Error == "" {
		t.Fatalf("falha persistente ao cachear deveria FAILED (não RUNNING para sempre), got state=%s err=%q", got.State, got.Error)
	}
}

func TestReconcilerLaunchDaOrcamentoNovoDeFetch(t *testing.T) {
	// Job reaberto (FAILED → PENDING) depois de esgotar as re-tentativas de fetch: o
	// relançamento recomeça a contagem — senão o 1º erro transitório já o derrubaria.
	r, _ := NewRegistry("")
	j := seedPending(r, 1)
	r.Update(j.RequestID, func(job *Job) { job.FetchFailures = 3 })
	f := newFakeRunner()
	f.status = statusDone
	f.fetch = func(*Job) (*bridgeResult, error) { return nil, fmt.Errorf("gvmd ocupado") }
	cfg := testRecCfg(t)
	cfg.FetchRetryLimit = 3
	rc := newReconciler(r, cfg, f.run)

	rc.tick(context.Background()) // launch
	rc.tick(context.Background()) // poll → Done → fetch falha (1ª deste lançamento)
	got, _ := r.Get(j.RequestID)
	if got.State != StateRunning {
		t.Fatalf("relançamento deveria recomeçar a contagem de falhas de fetch, got state=%s err=%q", got.State, got.Error)
	}
}

func TestReconcilerLaunchDaOrcamentoNovoDeStatus(t *testing.T) {
	// Sobra de falhas de status de uma execução anterior não pode antecipar a
	// expiração da nova: ela também recomeça a contagem.
	r, _ := NewRegistry("")
	now := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	j := seedPending(r, 1)
	r.Update(j.RequestID, func(job *Job) { job.StatusFailures = 2 })
	f := newFakeRunner()
	f.status = func(*Job) (*bridgeResult, error) { return nil, fmt.Errorf("gvmd ocupado") }
	rc := newReconciler(r, testRecCfg(t), f.run)
	rc.now = func() time.Time { return now }

	rc.tick(context.Background()) // launch
	now = now.Add(7 * time.Hour)  // a nova execução passa do limite
	rc.tick(context.Background()) // 1ª falha de status desta execução
	if got, _ := r.Get(j.RequestID); got.State != StateRunning {
		t.Fatalf("relançamento deveria recomeçar a contagem de falhas de status, got state=%s err=%q", got.State, got.Error)
	}
}

// --- Re-envio do mesmo scan_history_id (registry reabre o job) ---

// launchRecorder grava uma cópia do Job que cada launch mandou ao bridge.
func launchRecorder(f *fakeRunner) *[]Job {
	var sent []Job
	f.launch = func(j *Job) (*bridgeResult, error) {
		sent = append(sent, *j)
		return &bridgeResult{TargetID: "tg", TaskID: fmt.Sprintf("task-%d", len(sent)), Status: "Requested"}, nil
	}
	return &sent
}

func TestReconcilerReenvioAposNaoMedirNadaUsaTaskNova(t *testing.T) {
	for _, tc := range []struct{ name, fetchOut string }{
		{"sem host vivo", `{"findings": [], "hosts_scanned": 0, "report_missing": false}`},
		{"sem relatorio", `{"findings": [], "hosts_scanned": 0, "report_missing": true}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, _ := NewRegistry("")
			req := testReq(42, "acme.com")
			j, _, _ := r.FindOrCreate(req, testIdentity(), 0)
			f := newFakeRunner()
			sent := launchRecorder(f)
			f.status = statusDone
			f.fetch = func(*Job) (*bridgeResult, error) { return bridgeOut(t, tc.fetchOut), nil }
			rc := newReconciler(r, testRecCfg(t), f.run)

			rc.tick(context.Background()) // launch (tentativa 0)
			rc.tick(context.Background()) // Done sem medir nada → FAILED
			if got, _ := r.Get(j.RequestID); got.State != StateFailed {
				t.Fatalf("pré-condição: deveria FAILED, got %s", got.State)
			}

			reopened, created, _ := r.FindOrCreate(req, testIdentity(), 0) // o reNgine re-envia
			if created || reopened.State != StatePending || reopened.GVMTaskID != "" || reopened.GVMReportID != "" {
				t.Fatalf("re-envio deveria reabrir o job sem os ids da task velha, got created=%v %+v", created, reopened)
			}
			// A marca é consumida: uma falha seguinte de outro tipo (ex.: erro de launch)
			// não pode pular de novo de tentativa (scan duplo).
			if reopened.RetryNewTask {
				t.Fatal("reabrir deveria consumir a marca de task nova")
			}
			rc.tick(context.Background()) // relaunch

			if len(*sent) != 2 {
				t.Fatalf("esperado 2 launches, got %d", len(*sent))
			}
			first, second := (*sent)[0], (*sent)[1]
			if first.Attempt != 0 || second.Attempt != 1 {
				t.Fatalf("relaunch deveria levar attempt=1 ao bridge, got %d → %d", first.Attempt, second.Attempt)
			}
			if second.taskName() == first.taskName() || !strings.HasSuffix(second.taskName(), "-a1") {
				t.Fatalf("relaunch deveria usar task nova, got %q → %q", first.taskName(), second.taskName())
			}
		})
	}
}

func TestReconcilerReenvioAposLimiteDeFetchReusaATask(t *testing.T) {
	// FAILED por limite de fetch: o relatório pronto existe — o re-envio volta à MESMA
	// task (re-lê o relatório), sem gastar outro scan.
	r, _ := NewRegistry("")
	req := testReq(43, "acme.com")
	j, _, _ := r.FindOrCreate(req, testIdentity(), 0)
	f := newFakeRunner()
	sent := launchRecorder(f)
	f.status = statusDone
	f.fetch = func(*Job) (*bridgeResult, error) { return nil, fmt.Errorf("get_report timeout") }
	cfg := testRecCfg(t)
	cfg.FetchRetryLimit = 1
	rc := newReconciler(r, cfg, f.run)

	rc.tick(context.Background()) // launch
	rc.tick(context.Background()) // fetch falha no limite → FAILED
	if got, _ := r.Get(j.RequestID); got.State != StateFailed {
		t.Fatalf("pré-condição: deveria FAILED, got %s", got.State)
	}
	r.FindOrCreate(req, testIdentity(), 0)
	rc.tick(context.Background()) // relaunch

	if len(*sent) != 2 || (*sent)[1].Attempt != 0 || (*sent)[1].taskName() != (*sent)[0].taskName() {
		t.Fatalf("falha de fetch deveria reabrir na mesma task (attempt inalterado), got %+v", *sent)
	}
}

func TestReconcilerReenvioDeJobParadoRelanca(t *testing.T) {
	// DELETE marca stop_requested; o re-envio do mesmo scan_history_id reabre o job — e
	// ele tem de ser lançado, não parado de novo pela marca velha.
	r, _ := NewRegistry("")
	req := testReq(44, "acme.com")
	j, _, _ := r.FindOrCreate(req, testIdentity(), 0)
	r.Update(j.RequestID, func(job *Job) { job.StopRequested = true })
	f := newFakeRunner()
	rc := newReconciler(r, testRecCfg(t), f.run)
	rc.tick(context.Background())
	if got, _ := r.Get(j.RequestID); got.State != StateStopped {
		t.Fatalf("pré-condição: deveria STOPPED, got %s", got.State)
	}

	r.FindOrCreate(req, testIdentity(), 0)
	rc.tick(context.Background())
	got, _ := r.Get(j.RequestID)
	if got.State != StateRunning || f.calls["launch"] != 1 {
		t.Fatalf("job re-enviado depois de DELETE deveria ser lançado, got state=%s launch=%d", got.State, f.calls["launch"])
	}
}

func TestReconcilerDoneAlemDoLimiteAindaEBuscado(t *testing.T) {
	// O limite de duração não descarta relatório pronto — nem quando o fetch falha
	// uma vez. (Config sem FetchRetryLimit usa o default, não "falha na 1ª".)
	r, _ := NewRegistry("")
	now := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	j := seedRunning(r, 1, now.Add(-7*time.Hour))
	f := newFakeRunner()
	f.status = statusDone
	calls := 0
	f.fetch = func(*Job) (*bridgeResult, error) {
		calls++
		if calls == 1 {
			return nil, fmt.Errorf("gvmd ocupado")
		}
		return bridgeOut(t, `{"findings": [{"host": "203.0.113.10", "port": "443/tcp", "oid": "1.2.3"}], "hosts_scanned": 1, "report_missing": false}`), nil
	}
	rc := newReconciler(r, testRecCfg(t), f.run)
	rc.now = func() time.Time { return now }

	rc.tick(context.Background())
	if got, _ := r.Get(j.RequestID); got.State != StateRunning || f.calls["stop"] != 0 {
		t.Fatalf("Done além do limite com fetch falhando deveria seguir RUNNING (re-tenta), got state=%s stop=%d", got.State, f.calls["stop"])
	}
	rc.tick(context.Background())
	got, _ := r.Get(j.RequestID)
	if got.State != StateCompleted {
		t.Fatalf("Done além do limite deveria terminar COMPLETED, got state=%s err=%q", got.State, got.Error)
	}
	if fs := readFindings(rc.findingsDir, j.RequestID); len(fs) != 1 || fs[0].OID != "1.2.3" {
		t.Fatalf("achados do relatório pronto deveriam ser cacheados, got %+v", fs)
	}
}

// --- Contrato com o scan_bridge.py ---

func TestJobJSONLevaAIdentidadeQueOBridgeUsa(t *testing.T) {
	// O execBridge serializa o Job como pedido: o bridge deriva o nome da task de
	// rengine_scan_history_id + request_id + attempt e fixa o fallback legado em gvm_task_id.
	b, err := json.Marshal(&Job{RequestID: "3f9a2c1b7e0d4a5b8c6d9e0f1a2b3c4d", ScanHistoryID: 1234,
		GVMTaskID: "task-velha", Attempt: 1})
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	if m["request_id"] != "3f9a2c1b7e0d4a5b8c6d9e0f1a2b3c4d" || m["rengine_scan_history_id"] != float64(1234) ||
		m["gvm_task_id"] != "task-velha" || m["attempt"] != float64(1) {
		t.Fatalf("pedido ao bridge sem a identidade esperada: %s", b)
	}
}

func TestJobTaskNameEspelhaOBridge(t *testing.T) {
	// Mesmos literais de test_scan_bridge.py (NOME_POR_PEDIDO, NOME_TENTATIVA_1): os
	// dois lados não podem divergir.
	j := &Job{ScanHistoryID: 1234, RequestID: "3f9a2c1b7e0d4a5b8c6d9e0f1a2b3c4d"}
	if got := j.taskName(); got != "suricatoos-rengine-1234-3f9a2c1b7e0d" {
		t.Fatalf("taskName por pedido: got %q", got)
	}
	j.Attempt = 1
	if got := j.taskName(); got != "suricatoos-rengine-1234-3f9a2c1b7e0d-a1" {
		t.Fatalf("taskName da tentativa 1: got %q", got)
	}
	legado := &Job{ScanHistoryID: 1234}
	if got := legado.taskName(); got != "suricatoos-rengine-1234" {
		t.Fatalf("sem request_id vale o nome legado: got %q", got)
	}
}
