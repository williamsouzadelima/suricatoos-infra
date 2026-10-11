package scanrun

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/williamsouzadelima/suricatoos-infra/sensor/internal/scope"
)

func testRunner(t *testing.T, run bridgeExec) *Runner {
	t.Helper()
	sc, _ := scope.New("10.20.0.0/16", "10.20.0.9")
	r := New(Config{Scope: sc, PollInterval: time.Millisecond, MaxDuration: time.Hour})
	r.run = run
	r.sleep = func(time.Duration) {}
	r.now = time.Now
	return r
}

func TestRunHappyPath(t *testing.T) {
	calls := map[string]int{}
	var launchReq string
	run := func(_ context.Context, sub string, reqJSON []byte) (*bridgeResult, error) {
		calls[sub]++
		switch sub {
		case "launch":
			launchReq = string(reqJSON)
			return &bridgeResult{TaskID: "t1", Status: "Requested"}, nil
		case "status":
			// primeiro Running, depois Done
			if calls["status"] == 1 {
				return &bridgeResult{Status: "Running", Progress: 40}, nil
			}
			return &bridgeResult{Status: "Done", Progress: 100}, nil
		case "fetch":
			return &bridgeResult{Findings: []Finding{{Host: "10.20.5.5", OID: "o1", Name: "x"}}}, nil
		}
		return nil, fmt.Errorf("sub inesperado %s", sub)
	}
	r := testRunner(t, run)
	fs, dropped, err := r.Run(context.Background(), Job{CorrelationID: "corr-1",
		Targets: []string{"10.20.5.0/24", "8.8.8.8", "10.20.0.9"}, Ports: "T:1-1000"})
	if err != nil {
		t.Fatal(err)
	}
	// 8.8.8.8 (fora de escopo) e 10.20.0.9 (self-deny) dropados; 10.20.5.0/24 mantido.
	if dropped != 2 {
		t.Fatalf("esperado 2 dropados, got %d", dropped)
	}
	if len(fs) != 1 || fs[0].OID != "o1" {
		t.Fatalf("findings errados: %+v", fs)
	}
	// scan_id = correlation, targets só os em escopo, ports repassado.
	if want := `"scan_id":"corr-1"`; !contains(launchReq, want) {
		t.Fatalf("launch req sem scan_id: %s", launchReq)
	}
	if !contains(launchReq, `"10.20.5.0/24"`) || contains(launchReq, `8.8.8.8`) {
		t.Fatalf("launch req com alvos errados: %s", launchReq)
	}
	if calls["fetch"] != 1 {
		t.Fatalf("fetch deveria ser 1x, got %d", calls["fetch"])
	}
}

func TestRunAllOutOfScope(t *testing.T) {
	run := func(context.Context, string, []byte) (*bridgeResult, error) {
		t.Fatal("bridge NÃO deveria ser chamado quando tudo fora de escopo")
		return nil, nil
	}
	r := testRunner(t, run)
	fs, dropped, err := r.Run(context.Background(), Job{CorrelationID: "c", Targets: []string{"8.8.8.8", "evil.com"}})
	if err != nil || fs != nil || dropped != 2 {
		t.Fatalf("esperado nil/2/nil, got fs=%v dropped=%d err=%v", fs, dropped, err)
	}
}

func TestRunScanInterrupted(t *testing.T) {
	run := func(_ context.Context, sub string, _ []byte) (*bridgeResult, error) {
		if sub == "launch" {
			return &bridgeResult{Status: "Requested"}, nil
		}
		return &bridgeResult{Status: "Interrupted"}, nil
	}
	r := testRunner(t, run)
	if _, _, err := r.Run(context.Background(), Job{CorrelationID: "c", Targets: []string{"10.20.1.1"}}); err == nil {
		t.Fatal("scan Interrupted deveria retornar erro")
	}
}

func TestRunTimeout(t *testing.T) {
	run := func(_ context.Context, sub string, _ []byte) (*bridgeResult, error) {
		if sub == "launch" {
			return &bridgeResult{Status: "Requested"}, nil
		}
		return &bridgeResult{Status: "Running"}, nil // nunca termina
	}
	r := testRunner(t, run)
	now := time.Now()
	r.now = func() time.Time { return now }
	r.cfg.MaxDuration = time.Minute
	// avança o relógio no sleep p/ estourar o deadline.
	r.sleep = func(time.Duration) { now = now.Add(2 * time.Minute) }
	if _, _, err := r.Run(context.Background(), Job{CorrelationID: "c", Targets: []string{"10.20.1.1"}}); err == nil {
		t.Fatal("scan que nunca termina deveria estourar MaxDuration")
	}
}

// runDone roda um scan que termina Done e cujo fetch imprime fetchStdout — a saída
// REAL do scan_bridge.py, decodificada como o execBridge faz.
func runDone(t *testing.T, fetchStdout string) ([]Finding, error) {
	t.Helper()
	run := func(_ context.Context, sub string, _ []byte) (*bridgeResult, error) {
		switch sub {
		case "launch":
			return &bridgeResult{Status: "Requested"}, nil
		case "status":
			return &bridgeResult{Status: "Done", Progress: 100}, nil
		case "fetch":
			var res bridgeResult
			if err := json.Unmarshal([]byte(fetchStdout), &res); err != nil {
				t.Fatalf("saída do bridge inválida %q: %v", fetchStdout, err)
			}
			return &res, nil
		}
		return nil, fmt.Errorf("sub inesperado %s", sub)
	}
	fs, _, err := testRunner(t, run).Run(context.Background(), Job{CorrelationID: "c", Targets: []string{"10.20.1.1"}})
	return fs, err
}

// Um scan que não mediu nada NÃO pode virar relatório "limpo": erro => o supervisor
// não empurra relatório nem dá ack (o job fica para redelivery).
func TestRunDoneSemHostMedidoEErro(t *testing.T) {
	fs, err := runDone(t, `{"findings": [], "hosts_scanned": 0, "report_missing": false}`)
	if err == nil || !contains(err.Error(), "não mediu nenhum host vivo") || fs != nil {
		t.Fatalf("Done sem host medido deveria ser erro, got fs=%v err=%v", fs, err)
	}
}

func TestRunDoneSemRelatorioEErro(t *testing.T) {
	fs, err := runDone(t, `{"findings": [], "hosts_scanned": 0, "report_missing": true}`)
	if err == nil || !contains(err.Error(), "sem relatório") || fs != nil {
		t.Fatalf("Done sem relatório deveria ser erro, got fs=%v err=%v", fs, err)
	}
}

func TestRunDoneComHostLimpoNaoEErro(t *testing.T) {
	fs, err := runDone(t, `{"findings": [], "hosts_scanned": 1, "report_missing": false}`)
	if err != nil || len(fs) != 0 {
		t.Fatalf("host medido sem achado é resultado legítimo, got fs=%v err=%v", fs, err)
	}
}

func TestRunBridgeAntigoSemHostsScannedMantemComportamento(t *testing.T) {
	fs, err := runDone(t, `{"findings": [{"host": "10.20.1.1", "oid": "o1", "name": "x"}]}`)
	if err != nil || len(fs) != 1 || fs[0].OID != "o1" {
		t.Fatalf("saída sem hosts_scanned deveria manter o comportamento antigo, got fs=%v err=%v", fs, err)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
