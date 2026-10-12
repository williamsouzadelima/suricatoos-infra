package audit

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/williamsouzadelima/suricatoos-infra/fleet/contract"
)

// Vários goroutines gravando nos dois fluxos ao mesmo tempo, atravessando rotações, enquanto outro lê a cauda e o
// status (o CI roda com -race): cada fluxo termina com uma cadeia só, sem seq repetido nem pulado, cada cauda
// lida no meio já era uma cadeia válida, nada se perde, e as três linhas de cada comando saem na ordem.
func TestConcorrenciaNosDoisFluxos(t *testing.T) {
	dir := t.TempDir()
	cfg := defaultConfig()
	cfg.exec.maxBytes, cfg.reject.maxBytes = 128<<10, 128<<10
	l, _ := openAt(t, dir, cfg)
	const workers, perWorker = 8, 40

	stop := make(chan struct{})
	var reader sync.WaitGroup
	reader.Add(1)
	go func() {
		defer reader.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			if p := chainProblem(l.Tail()); p != "" {
				t.Errorf("cauda lida durante as gravações quebrada em %s", p)
				return
			}
			_ = l.Status()
		}
	}()

	var writers sync.WaitGroup
	for w := range workers {
		writers.Add(1)
		go func() {
			defer writers.Done()
			c := validCommand()
			for i := range perWorker {
				now := testBoot.Add(time.Duration(w*perWorker+i) * time.Second)
				c.CommandID = fmt.Sprintf("6f1c2a9e-3b7d-4c8a-%04x-%012x", w, i)
				for _, err := range []error{
					l.Received(now, c),
					l.Executed(now, c.Ref),
					l.Result(now, c.Ref, Outcome{Status: contract.StatusSucceeded}),
					l.Rejected(now, c, contract.ReasonReplay, ""),
					l.Unauthenticated(now, contract.ReasonBadEnvelope),
					l.Flush(now),
				} {
					if err != nil {
						t.Error(err)
						return
					}
				}
			}
		}()
	}
	writers.Wait()
	close(stop)
	reader.Wait()

	exec := allLines(t, dir, cfg.exec) // confere a cadeia através dos arquivos girados
	reject := allLines(t, dir, cfg.reject)
	if len(streamFiles(t, dir, ExecFileName)) < 2 {
		t.Fatal("o exec não girou: o teste não cobre a rotação concorrente")
	}
	const commands = workers * perWorker
	st := l.Status()
	if len(exec) != 3*commands || st.Exec.Seq != 3*commands || st.Exec.HeadSHA256 != sha(exec[len(exec)-1]) {
		t.Fatalf("exec: %d linhas, seq %d (esperava %d)", len(exec), st.Exec.Seq, 3*commands)
	}
	if st.Reject.Seq != int64(len(reject)) || st.Reject.HeadSHA256 != sha(reject[len(reject)-1]) {
		t.Fatalf("reject: %d linhas, seq %d", len(reject), st.Reject.Seq)
	}
	// cada comando: received, executed e result, nesta ordem; e cada um rejeitado uma vez
	order := map[string][]contract.AuditEvent{}
	for _, line := range exec {
		var e contract.AuditEntry
		if err := contract.DecodeStrict([]byte(line), &e); err != nil {
			t.Fatal(err)
		}
		order[*e.CommandID] = append(order[*e.CommandID], e.Event)
	}
	want := []contract.AuditEvent{contract.AuditEventReceived, contract.AuditEventExecuted, contract.AuditEventResult}
	for id, evs := range order {
		if fmt.Sprint(evs) != fmt.Sprint(want) {
			t.Fatalf("%s: %v", id, evs)
		}
	}
	rejected := 0
	for _, e := range rejectEntries(t, dir) {
		if e.Event == contract.AuditEventRejected {
			rejected++
		}
	}
	if len(order) != commands || rejected != commands {
		t.Fatalf("%d comandos no exec e %d rejeições, esperava %d", len(order), rejected, commands)
	}
}
