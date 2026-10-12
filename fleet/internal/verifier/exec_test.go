package verifier

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/williamsouzadelima/suricatoos-infra/fleet/contract"
	"github.com/williamsouzadelima/suricatoos-infra/fleet/internal/audit"
	"github.com/williamsouzadelima/suricatoos-infra/fleet/internal/replay"
)

// Begin: o passo "executando" do journal e depois a linha executed (fluxo exec), os dois antes da execução. O journal
// vem primeiro: um comando que o store recusa iniciar não ganha linha executed; e se só a linha falha, o journal já
// diz executando, então o comando também nunca começa depois. Finish: linha result e depois o resultado no journal.
func TestBeginEFinishOrdemDoJournalEDaAuditoria(t *testing.T) {
	n := newNode(t)
	o := n.process(env("a", contract.TypeTaskStart), tv)
	expectAck(t, o, Ack, contract.DecisionAccepted, "")
	j := o.Accepted.Job

	boom := errors.New("falha simulada")
	calls := &[]string{}
	fa := &failingAudit{Auditor: n.d.audit, fail: map[string]error{}}
	fs := &failingStore{Store: n.d.store, calls: calls, journalErr: boom}
	n.d.audit, n.d.store = fa, fs
	n.build()
	// o store recusa: nada de linha executed
	if err := n.v.Begin(j, tv); !errors.Is(err, boom) {
		t.Fatalf("Begin com o journal falhando: %v", err)
	}
	if got := events(n.auditEntries(contract.StreamExec)); !slices.Equal(got, []string{"received"}) {
		t.Fatalf("o journal recusou e mesmo assim saiu linha: %v", got)
	}
	// o journal anda, a linha falha: Begin falha e o comando nunca começa depois (já está executando)
	fs.journalErr, fa.fail["Executed"] = nil, boom
	if err := n.v.Begin(j, tv); !errors.Is(err, boom) {
		t.Fatalf("Begin com a auditoria falhando: %v", err)
	}
	delete(fa.fail, "Executed")
	if err := n.v.Begin(j, tv); !errors.Is(err, replay.ErrJobState) {
		t.Fatalf("depois do journal em executando, o comando não começa de novo: %v", err)
	}
	if !slices.Equal(*calls, []string{"store.MarkExecuting", "store.MarkExecuting", "store.MarkExecuting"}) {
		t.Fatalf("chamadas %v", *calls)
	}
	// um outro aceito segue a ordem toda
	o2 := n.process(env("b", contract.TypeTaskStart), tv)
	expectAck(t, o2, Ack, contract.DecisionAccepted, "")
	j2 := o2.Accepted.Job
	if err := n.v.Begin(j2, tv); err != nil {
		t.Fatal(err)
	}
	res := replay.Result{Status: contract.StatusSucceeded, StartedAt: "2026-10-11T12:30:01Z", FinishedAt: "2026-10-11T12:30:02Z",
		Output: []byte(`{"task_id":"` + taskID + `","status":"Requested"}`)}
	fa.fail["Result"] = boom
	if err := n.v.Finish(j2, res, audit.Outcome{Status: contract.StatusSucceeded}, tv); !errors.Is(err, boom) {
		t.Fatalf("Finish com auditoria falhando: %v", err)
	}
	if err := n.v.Finish(j2, res, audit.Outcome{Status: contract.StatusFailed, ErrorCode: contract.ErrorGVM}, tv); err == nil {
		t.Fatal("Finish com linha e resultado de desfechos diferentes")
	}
	delete(fa.fail, "Result")
	if err := n.v.Finish(j2, res, audit.Outcome{Status: contract.StatusSucceeded}, tv); err != nil {
		t.Fatal(err)
	}
	if got := events(n.auditEntries(contract.StreamExec)); !slices.Equal(got, []string{"received", "received", "executed", "result"}) {
		t.Fatalf("fluxo exec %v", got)
	}
	// a reentrega agora devolve também o resultado gravado
	again := n.process(env("b", contract.TypeTaskStart), tv.Add(time.Minute))
	if again.Kind != Redelivery || again.Result == nil || string(again.Result.Output) != string(res.Output) {
		t.Fatalf("reentrega %+v", again)
	}
}

// Na reentrega de um enroll_token.create aceito e com resultado, só o ack volta: o resultado (com o segredo) nunca
// foi guardado.
func TestReentregaDeEnrollTokenCreateSoComAck(t *testing.T) {
	n := newNode(t)
	raw := env("tok", contract.TypeEnrollTokenCreate)
	o := n.process(raw, tv)
	expectAck(t, o, Ack, contract.DecisionAccepted, "")
	j := o.Accepted.Job
	if err := n.v.Begin(j, tv); err != nil {
		t.Fatal(err)
	}
	out := `{"token_id":"tok01abcd","token":"` + "st_" + "tok01abcd." + "segredo-ficticio" + `","token_type":"deployment","policy":"agent-endpoint","max_uses":50,"expires_at":"2026-10-14T12:30:00Z","ca_pin":"sha256:` + strings.Repeat("cd", 32) + `"}`
	res := replay.Result{Status: contract.StatusSucceeded, StartedAt: "2026-10-11T12:30:01Z", FinishedAt: "2026-10-11T12:30:02Z", Output: []byte(out)}
	if err := n.v.Finish(j, res, audit.Outcome{Status: contract.StatusSucceeded, ObjectIDs: []string{"tok01abcd"}}, tv); err != nil {
		t.Fatal(err)
	}
	again := n.process(raw, tv.Add(time.Minute))
	if again.Kind != Redelivery || again.Ack.Decision != contract.DecisionAccepted || again.Result != nil {
		t.Fatalf("reentrega %+v", again)
	}
	b, err := os.ReadFile(filepath.Join(n.dir, replay.FileName))
	if err != nil || strings.Contains(string(b), "segredo-ficticio") {
		t.Fatalf("o segredo chegou ao store (%v)", err)
	}
	for _, line := range n.st.Audit.Tail().Exec.Lines {
		if strings.Contains(line, "segredo-ficticio") {
			t.Fatal("o segredo chegou à auditoria")
		}
	}
}

// Concorrência: vários envelopes ao mesmo tempo, com nonces e command_ids repetidos entre eles, mais o executor
// andando o journal — exatamente uma forma de cada grupo é aceita, as outras são replay ou reentrega, sem corrida
// (-race no CI).
func TestPipelineSobConcorrencia(t *testing.T) {
	n := newNode(t)
	const groups, per = 8, 6
	type result struct {
		group int
		o     Outcome
	}
	results := make(chan result, groups*per)
	var wg sync.WaitGroup
	for g := range groups {
		for i := range per {
			wg.Add(1)
			go func() {
				defer wg.Done()
				c := command("grupo"+string(rune('a'+g)), contract.TypeTaskStart)
				if i%2 == 1 { // same command_id, another nonce: a re-signed envelope
					c.Nonce = nonceOf("grupo" + string(rune('a'+g)) + "/" + string(rune('0'+i)))
				}
				o := n.process(signed(c, payloads[contract.TypeTaskStart]), tv)
				if o.Accepted != nil {
					if err := n.v.Begin(o.Accepted.Job, tv); err != nil {
						t.Error(err)
					}
				}
				results <- result{g, o}
			}()
		}
	}
	wg.Wait()
	close(results)
	accepted := map[int]int{}
	for r := range results {
		switch {
		case r.o.Kind == Ack && r.o.Ack.Decision == contract.DecisionAccepted:
			accepted[r.group]++
		case r.o.Kind == Ack && reasonOf(r.o) == contract.ReasonReplay, r.o.Kind == Redelivery:
		default:
			t.Errorf("desfecho inesperado %+v", r.o)
		}
	}
	for g := range groups {
		if accepted[g] != 1 {
			t.Errorf("grupo %d: %d aceitos", g, accepted[g])
		}
	}
}

// resultStore is a store that gives back a result for ANY job — the store never does it for enroll_token.create,
// and the pipeline must not rely on that alone.
type resultStore struct{ Store }

func (s resultStore) Result(j replay.Job, t time.Time) (replay.Result, bool, error) {
	return replay.Result{Status: contract.StatusSucceeded, StartedAt: "2026-10-11T12:30:01Z", FinishedAt: "2026-10-11T12:30:02Z"}, true, nil
}

// Defesa em profundidade: mesmo que o store devolvesse um resultado de enroll_token.create, a reentrega desse tipo
// leva só o ack; a de outro tipo leva o resultado.
func TestReentregaDeEnrollTokenCreateNuncaLevaResultado(t *testing.T) {
	n := newNode(t)
	n.d.store = resultStore{n.d.store}
	n.build()
	tok := env("tok", contract.TypeEnrollTokenCreate)
	expectAck(t, n.process(tok, tv), Ack, contract.DecisionAccepted, "")
	if again := n.process(tok, tv.Add(time.Minute)); again.Kind != Redelivery || again.Result != nil {
		t.Fatalf("reentrega do enroll_token.create com resultado: %+v", again)
	}
	start := env("start", contract.TypeTaskStart)
	expectAck(t, n.process(start, tv), Ack, contract.DecisionAccepted, "")
	if again := n.process(start, tv.Add(time.Minute)); again.Kind != Redelivery || again.Result == nil {
		t.Fatalf("reentrega de outro tipo sem o resultado: %+v", again)
	}
}

// boot → Interrupted (recebido) → Begin falha: o executor nunca roda um comando aceito antes do reinício, e nenhuma
// linha executed sai para ele; o resultado interrupted dele vai pelo Finish.
func TestInterrompidoDoBootNuncaPassaPeloBegin(t *testing.T) {
	dir := t.TempDir()
	writePolicy(t, dir, allTypes(), 1000, 3600)
	enroll(t, dir, boot)
	st, err := OpenState(dir, boot, StateOptions{IdentityExists: true})
	if err != nil {
		t.Fatal(err)
	}
	expectAck(t, newNodeOver(t, dir, st).process(env("aceito", contract.TypeTaskStart), tv), Ack, contract.DecisionAccepted, "")
	st.Close()

	st2, err := OpenState(dir, tv.Add(time.Minute), StateOptions{IdentityExists: true})
	if err != nil {
		t.Fatal(err)
	}
	n := newNodeOver(t, dir, st2)
	rec := st2.Store.Recovery()
	if len(rec.Interrupted) != 1 || rec.Interrupted[0].State != replay.StateReceived {
		t.Fatalf("interrompidos %+v", rec.Interrupted)
	}
	j := rec.Interrupted[0]
	if err := n.v.Begin(j, tv.Add(time.Minute)); !errors.Is(err, replay.ErrJobState) {
		t.Fatalf("o Begin de um comando do boot devia falhar com ErrJobState, deu %v", err)
	}
	if got := events(n.auditEntries(contract.StreamExec)); slices.Contains(got, "executed") {
		t.Fatalf("linha executed para um comando que não roda: %v", got)
	}
	res := replay.Result{Status: contract.StatusFailed, StartedAt: "2026-10-11T12:31:00Z", FinishedAt: "2026-10-11T12:31:00Z",
		Error: &contract.ResultError{Code: contract.ErrorInterrupted, Message: "o conector reiniciou antes da execução"}}
	if err := n.v.Finish(j, res, audit.Outcome{Status: contract.StatusFailed, ErrorCode: contract.ErrorInterrupted}, tv.Add(time.Minute)); err != nil {
		t.Fatalf("Finish do interrompido: %v", err)
	}
}
