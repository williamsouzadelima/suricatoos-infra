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

// Begin: linha executed (fluxo exec) e depois o passo "executando" do journal, os dois antes da execução; se a
// auditoria falha, o journal não anda e o executor não roda. Finish: linha result e depois o resultado no journal.
func TestBeginEFinishGravamAuditoriaAntesDoJournal(t *testing.T) {
	n := newNode(t)
	o := n.process(env("a", contract.TypeTaskStart), tv)
	expectAck(t, o, Ack, contract.DecisionAccepted, "")
	j := o.Accepted.Job

	boom := errors.New("auditoria envenenada (simulado)")
	calls := &[]string{}
	fa := &failingAudit{Auditor: n.d.audit, fail: map[string]error{"Executed": boom}}
	n.d.audit = fa
	n.d.store = &failingStore{Store: n.d.store, calls: calls}
	n.build()
	if err := n.v.Begin(j, tv); !errors.Is(err, boom) || len(*calls) != 0 {
		t.Fatalf("Begin com auditoria falhando: %v, chamadas %v", err, *calls)
	}
	delete(fa.fail, "Executed")
	if err := n.v.Begin(j, tv); err != nil || !slices.Equal(*calls, []string{"store.MarkExecuting"}) {
		t.Fatalf("Begin: %v, chamadas %v", err, *calls)
	}
	res := replay.Result{Status: contract.StatusSucceeded, StartedAt: "2026-10-11T12:30:01Z", FinishedAt: "2026-10-11T12:30:02Z",
		Output: []byte(`{"task_id":"` + taskID + `","status":"Requested"}`)}
	fa.fail["Result"] = boom
	if err := n.v.Finish(j, res, audit.Outcome{Status: contract.StatusSucceeded}, tv); !errors.Is(err, boom) {
		t.Fatalf("Finish com auditoria falhando: %v", err)
	}
	if err := n.v.Finish(j, res, audit.Outcome{Status: contract.StatusFailed, ErrorCode: contract.ErrorGVM}, tv); err == nil {
		t.Fatal("Finish com linha e resultado de desfechos diferentes")
	}
	delete(fa.fail, "Result")
	if err := n.v.Finish(j, res, audit.Outcome{Status: contract.StatusSucceeded}, tv); err != nil {
		t.Fatal(err)
	}
	if got := events(n.auditEntries(contract.StreamExec)); !slices.Equal(got, []string{"received", "executed", "result"}) {
		t.Fatalf("fluxo exec %v", got)
	}
	// a reentrega agora devolve também o resultado gravado
	again := n.process(env("a", contract.TypeTaskStart), tv.Add(time.Minute))
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
