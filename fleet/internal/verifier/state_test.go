package verifier

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/williamsouzadelima/suricatoos-infra/fleet/contract"
	"github.com/williamsouzadelima/suricatoos-infra/fleet/internal/fsutil"
)

// enroll simulates what the connector's enroll does on the first start: the state is opened BEFORE the identity
// exists (store, watermark and budget.json created empty), the replay floor is set, and only then the identity is
// persisted (a fictitious certificate file here).
func enroll(t *testing.T, dir string, at time.Time) {
	t.Helper()
	st, err := OpenState(dir, at, StateOptions{IdentityExists: false})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Store.SetFloor(st.Clock().Now(at)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "node.crt"), []byte("certificado fictício"), 0o600); err != nil {
		t.Fatal(err)
	}
	st.Close()
}

// inscrição → primeira subida → comando aceito: a primeira subida depois do enroll encontra o store, a marca d'água e
// o budget.json, então não há perda (nem piso novo, nem janela cheia), e um comando emitido depois do piso + skew é
// aceito.
func TestInscricaoPrimeiraSubidaComandoAceito(t *testing.T) {
	dir := t.TempDir()
	writePolicy(t, dir, allTypes(), 1000, 3600)
	enroll(t, dir, boot)
	st, err := OpenState(dir, boot.Add(time.Minute), StateOptions{IdentityExists: true})
	if err != nil {
		t.Fatal(err)
	}
	s := st.Status()
	if s.StoreRecovery.FloorReason != "" || s.BudgetLost != nil || s.ClockLost != nil || s.ReplayFloor != "2026-10-11T10:00:00Z" {
		t.Fatalf("primeira subida depois do enroll: %+v", s)
	}
	if !s.FloorUnannounced {
		t.Fatal("o piso do enroll ainda não foi anunciado: heartbeat antes do primeiro poll")
	}
	n := newNodeOver(t, dir, st)
	expectAck(t, n.process(env("primeiro", contract.TypeTaskStart), tv), Ack, contract.DecisionAccepted, "")
}

// Reinício de um nó parado, sem comando: nada se perde — o piso não muda, o orçamento não bloqueia, a auditoria segue
// a cadeia — e o comando seguinte é aceito.
func TestReinicioDeNoParadoSemComandoSemPerda(t *testing.T) {
	dir := t.TempDir()
	writePolicy(t, dir, allTypes(), 1000, 3600)
	enroll(t, dir, boot)
	for i := range 3 {
		st, err := OpenState(dir, boot.Add(time.Duration(i+1)*time.Minute), StateOptions{IdentityExists: true})
		if err != nil {
			t.Fatal(err)
		}
		s := st.Status()
		if s.StoreRecovery.FloorReason != "" || s.BudgetLost != nil || s.ReplayFloor != "2026-10-11T10:00:00Z" ||
			s.Audit.Exec.Recovery.Breaks != 0 || s.StoreRecovery.Corrupt != 0 {
			t.Fatalf("reinício %d: %+v", i, s)
		}
		st.Close()
	}
	st, err := OpenState(dir, tv, StateOptions{IdentityExists: true})
	if err != nil {
		t.Fatal(err)
	}
	expectAck(t, newNodeOver(t, dir, st).process(env("depois", contract.TypeTaskStart), tv), Ack, contract.DecisionAccepted, "")
}

// Sem a ordem certa — a identidade persistida antes de o estado existir —, a primeira subida é perda: piso novo e
// orçamento cheio por 1 h. É o que o enroll() acima evita.
func TestIdentidadeAntesDoEstadoEPerda(t *testing.T) {
	dir := t.TempDir()
	st, err := OpenState(dir, boot, StateOptions{IdentityExists: true})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if s := st.Status(); s.StoreRecovery.FloorReason == "" || s.BudgetLost == nil {
		t.Fatalf("estado ausente com identidade devia ser perda: %+v", s)
	}
}

// Um só processo por FLEET_STATE_DIR: o segundo OpenState falha com a trava, sem tocar o estado.
func TestSegundoProcessoNoMesmoDiretorioNaoSobe(t *testing.T) {
	dir := t.TempDir()
	st, err := OpenState(dir, boot, StateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err := OpenState(dir, boot, StateOptions{}); !errors.Is(err, fsutil.ErrLocked) {
		t.Fatalf("o segundo OpenState devia falhar com ErrLocked, deu %v", err)
	}
}

// O boot da auditoria é o relógio de verificação, não o relógio de parede: com o relógio de parede 1 h atrás no
// reinício, as linhas já gravadas não parecem "do futuro".
func TestAuditoriaDatadaPeloRelogioDeVerificacao(t *testing.T) {
	n := newNode(t)
	expectAck(t, n.process(env("x", contract.TypeTaskStop), tv), Ack, contract.DecisionAccepted, "")
	if _, u := n.v.Counters(); u != 0 {
		t.Fatal("nada de reentrega aqui")
	}
	// uma linha do anti-enchente às 12:30 (contagem de não autenticado)
	n.process([]byte(`{}`), tv)
	n.st.Close()
	st, err := OpenState(n.dir, tv.Add(-time.Hour), StateOptions{IdentityExists: true})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if fut := st.Status().Audit.Reject.Recovery.FutureAt; len(fut) != 0 {
		t.Fatalf("o boot da auditoria usou o relógio de parede: FutureAt %v", fut)
	}
}

// Relógio que volta no reboot não reabre janela vencida: o expired dado antes do reboot continua expired depois,
// mesmo com o relógio de parede de volta para dentro da janela.
func TestRelogioQueVoltaNoRebootNaoReabreJanela(t *testing.T) {
	dir := t.TempDir()
	writePolicy(t, dir, allTypes(), 1000, 3600)
	enroll(t, dir, boot)
	st, err := OpenState(dir, boot, StateOptions{IdentityExists: true})
	if err != nil {
		t.Fatal(err)
	}
	raw := env("vencido", contract.TypeTaskStart)
	late := t0.Add(time.Hour + skew + time.Second)
	expectAck(t, newNodeOver(t, dir, st).process(raw, late), Ack, contract.DecisionRejected, contract.ReasonExpired)
	st.Close()
	st2, err := OpenState(dir, tv, StateOptions{IdentityExists: true}) // relógio de parede de volta às 12:30
	if err != nil {
		t.Fatal(err)
	}
	expectAck(t, newNodeOver(t, dir, st2).process(raw, tv), Ack, contract.DecisionRejected, contract.ReasonExpired)
}
