package verifier

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/williamsouzadelima/suricatoos-infra/fleet/contract"
	"github.com/williamsouzadelima/suricatoos-infra/fleet/internal/budget"
	"github.com/williamsouzadelima/suricatoos-infra/fleet/internal/fsutil"
	"github.com/williamsouzadelima/suricatoos-infra/fleet/internal/policy"
	"github.com/williamsouzadelima/suricatoos-infra/fleet/internal/replay"
)

// traced wraps the ledger, the audit and the store of n so that every call is recorded in order; the returned
// pointers let a test make one of them fail.
func traced(n *node) (*[]string, *orderedLedger, *failingStore) {
	calls := &[]string{}
	led := &orderedLedger{Ledger: n.d.ledger, calls: calls}
	st := &failingStore{Store: n.d.store, calls: calls}
	n.d.ledger, n.d.store = led, st
	n.d.audit = &orderedAudit{Auditor: n.d.audit, calls: calls}
	n.build()
	return calls, led, st
}

// No aceite, o orçamento é consumido ANTES de gravar accepted, e a linha received sai entre os dois; se a gravação
// da decisão falha, a resposta é unavailable e a vaga do orçamento fica perdida (fail-closed).
func TestOrcamentoConsumidoAntesDaGravacaoDoAceite(t *testing.T) {
	n := newNode(t)
	writePolicy(t, n.dir, allTypes(), 1000, 1)
	calls, _, st := traced(n)
	st.recordErr = fmt.Errorf("replay: gravar: %w", fsutil.ErrNotDurable)
	o := n.process(env("a", contract.TypeTaskStart), tv)
	expectAck(t, o, Ack, contract.DecisionDeferred, contract.ReasonUnavailable)
	if o.Accepted != nil {
		t.Fatal("sem gravação confirmada não há aceite")
	}
	want := []string{"ledger.Consume", "audit.Received", "store.Record:accepted", "audit.Deferred:unavailable"}
	if !slices.Equal(*calls, want) {
		t.Fatalf("ordem %v, esperava %v", *calls, want)
	}
	if r, _ := n.st.Ledger.Fits(tv, contract.TypeTaskStart, budgetLimits(1, 1000)); r.Total {
		t.Fatal("a vaga consumida antes da gravação que falhou fica perdida")
	}
}

// O comando executa se e só se Consume devolveu nil: um consumo com ErrNotDurable (gravado, mas não confirmado)
// não aceita, não grava e não ack-a o aceite — a resposta é unavailable, sem linha received.
func TestConsumoNaoConfirmadoNaoAceita(t *testing.T) {
	n := newNode(t)
	calls, led, _ := traced(n)
	led.consumeErr = fmt.Errorf("budget: gravar budget.json: %w", fsutil.ErrNotDurable)
	before := n.storeBytes()
	o := n.process(env("a", contract.TypeTaskStart), tv)
	expectAck(t, o, Ack, contract.DecisionDeferred, contract.ReasonUnavailable)
	if o.Accepted != nil || !bytes.Equal(n.storeBytes(), before) {
		t.Fatal("consumo não confirmado virou aceite")
	}
	if want := []string{"ledger.Consume", "audit.Deferred:unavailable"}; !slices.Equal(*calls, want) {
		t.Fatalf("ordem %v", *calls)
	}
}

// ErrOverBudget no consumo (o Consume reconfere sob o lock) é rate_limited, final e gravado.
func TestConsumoAcimaDoOrcamentoERateLimited(t *testing.T) {
	n := newNode(t)
	calls, led, _ := traced(n)
	led.consumeErr = budget.ErrOverBudget
	o := n.process(env("a", contract.TypeTaskStart), tv)
	expectAck(t, o, Ack, contract.DecisionRejected, contract.ReasonRateLimited)
	want := []string{"ledger.Consume", "audit.Rejected:rate_limited", "store.Record:rejected"}
	if !slices.Equal(*calls, want) || o.PolicyEvent == nil {
		t.Fatalf("ordem %v, evento %v", *calls, o.PolicyEvent)
	}
}

// Rejeição das linhas 4–9: a linha rejected sai ANTES da gravação, e a gravação antes do ack. Se a gravação falha,
// a resposta é unavailable (com a linha deferred), sem evento.
func TestRejeicaoGravadaDepoisDaAuditoriaEAntesDoAck(t *testing.T) {
	n := newNode(t)
	calls, _, st := traced(n)
	c := command("outro nó", contract.TypeTaskStart)
	c.NodeID = "node-lab-0002"
	expectAck(t, n.process(signed(c, payloads[contract.TypeTaskStart]), tv), Ack, contract.DecisionRejected, contract.ReasonWrongNode)
	if want := []string{"audit.Rejected:wrong_node", "store.Record:rejected"}; !slices.Equal(*calls, want) {
		t.Fatalf("ordem %v", *calls)
	}
	*calls = nil
	st.recordErr = replay.ErrFull // store no teto
	tu := command("tenant", contract.TypeTaskStart)
	tu.Tenant = "desconhecido"
	o := n.process(signed(tu, payloads[contract.TypeTaskStart]), tv)
	expectAck(t, o, Ack, contract.DecisionDeferred, contract.ReasonUnavailable)
	if o.PolicyEvent != nil {
		t.Fatal("rejeição não gravada não vira evento")
	}
	if want := []string{"audit.Rejected:tenant_unknown", "store.Record:rejected", "audit.Deferred:unavailable"}; !slices.Equal(*calls, want) {
		t.Fatalf("ordem %v", *calls)
	}
}

// Auditoria antes do ack: se a linha não se grava, não há ack — em todo destino.
func TestAuditoriaQueFalhaNaoDaAck(t *testing.T) {
	boom := errors.New("auditoria envenenada (simulado)")
	tu := command("tenant", contract.TypeTaskStart)
	tu.Tenant = "desconhecido"
	cases := []struct {
		name   string
		method string
		raw    []byte
		at     time.Time
	}{
		{"rejeição gravável", "Rejected", signed(tu, payloads[contract.TypeTaskStart]), tv},
		{"linha 3", "Rejected", env("vencido", contract.TypeTaskStart), t0.Add(time.Hour + skew + time.Second)},
		{"adiado", "Deferred", env("cedo", contract.TypeTaskStart), t0.Add(-skew - time.Second)},
		{"aceite", "Received", env("aceito", contract.TypeTaskStart), tv},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			n := newNode(t)
			n.d.audit = &failingAudit{Auditor: n.d.audit, fail: map[string]error{c.method: boom}}
			n.build()
			before := n.storeBytes()
			o := n.process(c.raw, c.at)
			if o.Kind != NoAck || !errors.Is(o.Err, boom) || o.Ack.CommandID != "" || o.Accepted != nil {
				t.Fatalf("desfecho %+v", o)
			}
			if !bytes.Equal(n.storeBytes(), before) {
				t.Fatal("sem linha de auditoria, nada se grava no store")
			}
		})
	}
	// e a linha deferred do unavailable também: sem ela, sem ack
	n := newNode(t)
	n.d.audit = &failingAudit{Auditor: n.d.audit, fail: map[string]error{"Deferred": boom}}
	n.scope.readErr = errors.New("gvmd fora do ar (simulado)")
	n.build()
	if o := n.process(env("leitura", contract.TypeTaskStart), tv); o.Kind != NoAck {
		t.Fatalf("unavailable sem linha deferred: %+v", o)
	}
}

// Linha 3 (não gravada): a marca d'água tem de estar durável antes do ack; se não se grava, unavailable.
func TestLinha3SemMarcaDaguaDuravelEUnavailable(t *testing.T) {
	long := command("longa", contract.TypeTaskStart)
	long.NotAfter = contract.FormatUTCTime(t0.Add(25 * time.Hour))
	for name, c := range map[string]struct {
		raw []byte
		at  time.Time
	}{
		"expired":    {env("vencido", contract.TypeTaskStart), t0.Add(time.Hour + skew + time.Second)},
		"bad_window": {signed(long, payloads[contract.TypeTaskStart]), tv},
	} {
		n := newNode(t)
		n.d.clock = &failingClock{Clock: n.d.clock, err: errors.New("EIO na marca d'água (simulado)")}
		n.build()
		o := n.process(c.raw, c.at)
		expectAck(t, o, Ack, contract.DecisionDeferred, contract.ReasonUnavailable)
		if got := events(n.auditEntries(contract.StreamReject)); !slices.Equal(got, []string{"deferred:unavailable"}) {
			t.Fatalf("%s: auditoria %v", name, got)
		}
	}
}

// Toda dependência local que falha na releitura ou na leitura é unavailable: adiado, nada gravado, linha deferred.
func TestDependenciaLocalQueFalhaEUnavailable(t *testing.T) {
	cases := map[string]struct {
		breakIt func(n *node)
		typ     contract.CommandType
	}{
		"registro de tenants ilegível": {func(n *node) {
			p := filepath.Join(n.dir, "tenants.json")
			os.Remove(p)
			os.Mkdir(p, 0o700)
		}, contract.TypeTaskStart},
		"arquivo de segredos malformado numa escrita": {func(n *node) {
			os.WriteFile(filepath.Join(n.dir, "segredos.json"), []byte("{"), 0o600)
		}, contract.TypeTaskCreate},
		"política ilegível": {func(n *node) {
			os.WriteFile(filepath.Join(n.dir, policy.FileName), []byte("{"), 0o600)
		}, contract.TypeTaskStart},
		"orçamentos sem resposta": {func(n *node) {
			n.d.ledger = &fitsErrLedger{Ledger: n.d.ledger}
		}, contract.TypeTaskStart},
		"capacidades de relatório": {func(n *node) { n.fmtErr = errors.New("gvmd sem resposta") }, contract.TypeReportExport},
		"portão de escopo":         {func(n *node) { n.scope.gateErr = errors.New("escopo do tenant ilegível") }, contract.TypeTargetCreate},
		"leitura no gvmd":          {func(n *node) { n.scope.readErr = errors.New("gvmd fora do ar") }, contract.TypeTaskStart},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			n := newNode(t)
			c.breakIt(n)
			n.build()
			before := n.storeBytes()
			o := n.process(env("x", c.typ), tv)
			expectAck(t, o, Ack, contract.DecisionDeferred, contract.ReasonUnavailable)
			if !bytes.Equal(n.storeBytes(), before) || o.Accepted != nil {
				t.Fatal("unavailable não grava nem aceita")
			}
			if got := events(n.auditEntries(contract.StreamReject)); !slices.Equal(got, []string{"deferred:unavailable"}) {
				t.Fatalf("auditoria %v", got)
			}
			if bytes.Contains([]byte(*o.Ack.Detail), []byte("gvmd fora")) || bytes.Contains([]byte(*o.Ack.Detail), []byte(n.dir)) {
				t.Fatalf("o detalhe não leva a mensagem do erro: %q", *o.Ack.Detail)
			}
		})
	}
}

// fitsErrLedger is a ledger that cannot answer Fits (its state could not be read).
type fitsErrLedger struct{ Ledger }

func (l *fitsErrLedger) Fits(time.Time, contract.CommandType, budget.Limits) (budget.Room, error) {
	return budget.Room{}, errors.New("orçamentos ilegíveis (simulado)")
}

// budget.json ausente num nó com certificado: perda de estado, a janela conta como cheia por 1 h (rate_limited),
// como no arquivo corrompido.
func TestBudgetAusenteComCertificadoEJanelaCheia(t *testing.T) {
	dir := t.TempDir()
	st, err := OpenState(dir, boot, StateOptions{IdentityExists: true})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if st.Ledger.Lost() == nil {
		t.Fatal("budget.json ausente com identidade é perda")
	}
	writePolicy(t, dir, allTypes(), 1000, 3600)
	n := newNodeOver(t, dir, st)
	c := command("cedo", contract.TypeTaskStart) // emitido depois do piso + skew, dentro da hora do bloqueio
	c.IssuedAt, c.NotAfter = contract.FormatUTCTime(boot.Add(20*time.Minute)), contract.FormatUTCTime(boot.Add(80*time.Minute))
	expectAck(t, n.process(signed(c, payloads[contract.TypeTaskStart]), boot.Add(30*time.Minute)), Ack, contract.DecisionRejected, contract.ReasonRateLimited)
	c2 := command("depois", contract.TypeTaskStart)
	c2.IssuedAt, c2.NotAfter = contract.FormatUTCTime(boot.Add(55*time.Minute)), contract.FormatUTCTime(boot.Add(115*time.Minute))
	expectAck(t, n.process(signed(c2, payloads[contract.TypeTaskStart]), boot.Add(time.Hour+time.Minute)), Ack, contract.DecisionAccepted, "")
}

// unconfirmedStore is a store whose boot could not confirm on disk what it read.
type unconfirmedStore struct {
	Store
	err error
}

func (s unconfirmedStore) Lookup(*contract.Verified, time.Time) replay.Lookup {
	return replay.Lookup{Unconfirmed: s.err}
}

// Um store que ainda não confirmou no disco o que o boot leu não serve nada dele: nem a reentrega leva o ack gravado
// — a resposta é unavailable (adiado), com a linha deferred —, e um envelope novo também espera.
func TestStoreNaoConfirmadoEUnavailableAteNaReentrega(t *testing.T) {
	n := newNode(t)
	raw := env("a", contract.TypeTaskStart)
	expectAck(t, n.process(raw, tv), Ack, contract.DecisionAccepted, "")
	n.d.store = unconfirmedStore{Store: n.d.store, err: errors.New("o boot não confirmou o store (simulado)")}
	n.build()
	expectAck(t, n.process(raw, tv.Add(time.Minute)), Ack, contract.DecisionDeferred, contract.ReasonUnavailable)
	expectAck(t, n.process(env("b", contract.TypeTaskStart), tv.Add(time.Minute)), Ack, contract.DecisionDeferred, contract.ReasonUnavailable)
	if got := events(n.auditEntries(contract.StreamReject)); !slices.Equal(got, []string{"deferred:unavailable", "deferred:unavailable"}) {
		t.Fatalf("auditoria %v", got)
	}
	if _, r := n.v.Counters(); r != 0 {
		t.Fatal("não houve reentrega servida")
	}
}

// staleStore answers Lookup as it was BEFORE any recording: a second verifier whose look at the store predates the
// first one's decision.
type staleStore struct{ Store }

func (staleStore) Lookup(*contract.Verified, time.Time) replay.Lookup { return replay.Lookup{} }

// Dois verificadores sobre o mesmo estado (um New de novo num reload, com o antigo ainda processando): mesmo que o
// segundo tenha consultado o store antes de o primeiro gravar, o par re-assinado sob o mesmo command_id não é aceito
// duas vezes — o store recusa e o segundo responde unavailable.
func TestDoisVerificadoresNuncaAceitamOParReassinado(t *testing.T) {
	a := newNode(t)
	b := &node{t: t, st: a.st, dir: a.dir, scope: a.scope, formats: a.formats, logs: a.logs, cfg: a.cfg, d: a.d}
	b.d.store = staleStore{a.d.store}
	b.build()
	expectAck(t, a.process(env("original", contract.TypeTaskStart), tv), Ack, contract.DecisionAccepted, "")
	c := command("original", contract.TypeTaskStart)
	c.Nonce = nonceOf("re-assinado")
	o := b.process(signed(c, payloads[contract.TypeTaskStart]), tv)
	expectAck(t, o, Ack, contract.DecisionDeferred, contract.ReasonUnavailable)
	if o.Accepted != nil {
		t.Fatal("o par re-assinado foi aceito")
	}
}
