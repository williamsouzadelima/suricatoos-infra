package replay

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/williamsouzadelima/suricatoos-infra/fleet/contract"
	"github.com/williamsouzadelima/suricatoos-infra/fleet/internal/clock"
	"github.com/williamsouzadelima/suricatoos-infra/fleet/internal/fsutil"
)

// O primeiro boot de um nó (sem identidade) cria o store já com o cabeçalho, sem piso: a próxima subida, depois do
// enroll, encontra o arquivo e não o confunde com perda.
func TestPrimeiroBootCriaOStoreSemPiso(t *testing.T) {
	s, dir := firstBoot(t)
	if got := kinds(t, dir); !slices.Equal(got, []string{kindHead}) {
		t.Fatalf("registros %v", got)
	}
	if _, ok := s.Floor(); ok || s.ReplayFloor() != "" {
		t.Fatal("primeiro boot não tem piso")
	}
	rec := s.Recovery()
	if !rec.Absent || rec.FloorReason != "" || rec.RewriteErr != nil {
		t.Fatalf("recovery %+v", rec)
	}
}

// Decisão gravada é achada pela própria forma canônica (linha 2a); outra forma sob o mesmo nonce ou o mesmo
// command_id aparece em Recorded (linha 5).
func TestRecordELookup(t *testing.T) {
	s, _ := firstBoot(t)
	v := env(t, "a")
	if l := s.Lookup(v, t0); l.Same != nil || len(l.Recorded) != 0 {
		t.Fatalf("store vazio: %+v", l)
	}
	e := mustRecord(t, s.Store, v, rejected(contract.ReasonTenantUnknown), t0.Add(time.Minute))
	if e.CanonicalSHA256 != v.CanonicalSHA256() || e.Decision != contract.DecisionRejected ||
		e.Reason != contract.ReasonTenantUnknown || !e.DecidedAt.Equal(t0.Add(time.Minute)) || e.Job != nil {
		t.Fatalf("entrada %+v", e)
	}
	if want := time.Date(2026, 10, 18, 13, 0, 0, 0, time.UTC); !e.Expires.Equal(want) {
		t.Fatalf("vida até %v, esperava not_after + 7 dias = %v", e.Expires, want)
	}
	l := s.Lookup(v, t0.Add(time.Hour))
	if l.Same == nil || l.Same.Reason != contract.ReasonTenantUnknown || !slices.Equal(l.Recorded, []string{v.CanonicalSHA256()}) {
		t.Fatalf("lookup %+v", l)
	}
	if got := contract.ClassifyReplay(v.CanonicalSHA256(), l.Recorded); got != contract.ReplayRedelivery {
		t.Fatalf("ClassifyReplay = %v", got)
	}
}

// Replay pelo command_id (outro nonce) e pelo nonce (outro command_id): o Recorded traz a forma gravada, e o
// ClassifyReplay do contrato responde conflito.
func TestReplayPorNonceEPorCommandID(t *testing.T) {
	s, _ := firstBoot(t)
	first := env(t, "original")
	mustRecord(t, s.Store, first, accepted, t0)

	sameCmd := command("original")
	sameCmd.Nonce = nonceOf("outro nonce")
	sameNonce := command("original")
	sameNonce.CommandID = uuidOf("outro command_id")
	for name, c := range map[string]contract.Command{"command_id": sameCmd, "nonce": sameNonce} {
		v := verified(t, c, taskPayload)
		l := s.Lookup(v, t0)
		if l.Same != nil || !slices.Equal(l.Recorded, []string{first.CanonicalSHA256()}) {
			t.Fatalf("%s: lookup %+v", name, l)
		}
		if got := contract.ClassifyReplay(v.CanonicalSHA256(), l.Recorded); got != contract.ReplayConflict {
			t.Fatalf("%s: ClassifyReplay = %v", name, got)
		}
	}
}

// Um replay fica gravado pela própria forma canônica (a reentrega dele recebe o replay gravado), e os índices
// continuam apontando para a primeira entrada: uma terceira forma sob o mesmo command_id vê as duas.
func TestReplayGravadoPelaPropriaFormaEIndicesNaPrimeira(t *testing.T) {
	s, dir := firstBoot(t)
	first := env(t, "primeira")
	mustRecord(t, s.Store, first, accepted, t0)
	c := command("primeira")
	c.Nonce = nonceOf("segunda")
	second := verified(t, c, taskPayload)
	mustRecord(t, s.Store, second, rejected(contract.ReasonReplay), t0)

	if l := s.Lookup(second, t0); l.Same == nil || l.Same.Reason != contract.ReasonReplay {
		t.Fatalf("a reentrega do replay devia achar o replay gravado: %+v", l)
	}
	c.Nonce = nonceOf("terceira")
	third := verified(t, c, taskPayload)
	l := s.Lookup(third, t0)
	if l.Same != nil || !slices.Equal(l.Recorded, []string{first.CanonicalSHA256(), second.CanonicalSHA256()}) {
		t.Fatalf("lookup da terceira %+v", l)
	}
	cmd := cmdKey(first.Command().CommandID)
	s.mu.Lock()
	head := s.byCmd[cmd]
	s.mu.Unlock()
	if s.entries[head].canon != canonKey(first.CanonicalSHA256()) {
		t.Fatal("o índice do command_id deixou de apontar para a primeira entrada")
	}
	// o novo nonce da segunda também é um nonce gravado
	c = command("quarta")
	c.Nonce = nonceOf("segunda")
	if l := s.Lookup(verified(t, c, taskPayload), t0); !slices.Equal(l.Recorded, []string{second.CanonicalSHA256()}) {
		t.Fatalf("o nonce do replay gravado também conta: %+v", l)
	}
	if got := kinds(t, dir); !slices.Equal(got, []string{kindHead, kindEntry, kindEntry}) {
		t.Fatalf("registros %v", got)
	}
}

// Entrada gravada nunca é sobrescrita: gravar de novo a mesma forma canônica é ErrRecorded e nada muda no arquivo.
func TestEntradaGravadaNuncaESobrescrita(t *testing.T) {
	s, dir := firstBoot(t)
	v := env(t, "a")
	mustRecord(t, s.Store, v, rejected(contract.ReasonScopeDenied), t0)
	before := storeBytes(t, dir)
	if _, err := s.Record(v, accepted, t0.Add(time.Minute)); !errors.Is(err, ErrRecorded) {
		t.Fatalf("esperava ErrRecorded, deu %v", err)
	}
	if after := storeBytes(t, dir); string(after) != string(before) {
		t.Fatal("o arquivo mudou")
	}
	if l := s.Lookup(v, t0); l.Same.Reason != contract.ReasonScopeDenied {
		t.Fatalf("a decisão gravada mudou: %+v", l.Same)
	}
}

// Só decisão final das linhas 4–9 (gravável) ou accepted entra no store; nada de bad_window/expired, adiamento ou
// motivo das linhas 0–2, e nem envelope com janela inválida.
func TestRecordSoComDecisaoGravavel(t *testing.T) {
	s, dir := firstBoot(t)
	v := env(t, "a")
	bad := []Decision{
		{Decision: contract.DecisionAccepted, Reason: contract.ReasonReplay},
		{Decision: contract.DecisionDeferred, Reason: contract.ReasonUnavailable},
		{Decision: contract.DecisionDeferred, Reason: contract.ReasonNotYetValid},
		rejected(contract.ReasonExpired), rejected(contract.ReasonBadWindow), rejected(contract.ReasonUnavailable),
		rejected(contract.ReasonBadSignature), rejected(""), {Decision: "talvez"},
	}
	for _, d := range bad {
		if _, err := s.Record(v, d, t0); !errors.Is(err, ErrInvalid) {
			t.Errorf("%+v: esperava ErrInvalid, deu %v", d, err)
		}
	}
	c := command("janela")
	c.NotAfter = "2026-10-12T12:00:01Z" // janela de 24 h + 1 s: bad_window, que nunca se grava
	if _, err := s.Record(verified(t, c, taskPayload), rejected(contract.ReasonWrongNode), t0); !errors.Is(err, ErrInvalid) {
		t.Errorf("janela inválida: esperava ErrInvalid, deu %v", err)
	}
	if _, err := s.Record(&contract.Verified{}, accepted, t0); !errors.Is(err, ErrInvalid) {
		t.Errorf("Verified que o Verify não fez: esperava ErrInvalid, deu %v", err)
	}
	if _, err := s.Record(nil, accepted, t0); !errors.Is(err, ErrInvalid) {
		t.Errorf("nil: esperava ErrInvalid, deu %v", err)
	}
	if got := kinds(t, dir); !slices.Equal(got, []string{kindHead}) {
		t.Fatalf("registros %v", got)
	}
}

// A entrada vive até not_after + 7 dias, inclusive; um segundo depois ela não existe mais para o lookup (nem para a
// linha 2a nem para a linha 5).
func TestVidaDaEntrada(t *testing.T) {
	s, _ := firstBoot(t)
	v := env(t, "a")
	mustRecord(t, s.Store, v, accepted, t0)
	end := time.Date(2026, 10, 18, 13, 0, 0, 0, time.UTC)
	if l := s.Lookup(v, end); l.Same == nil {
		t.Fatal("no último instante da vida a entrada ainda vale")
	}
	if l := s.Lookup(v, end.Add(time.Second)); l.Same != nil || len(l.Recorded) != 0 {
		t.Fatalf("depois da vida a entrada não vale mais: %+v", l)
	}
}

// O que foi gravado sobrevive ao reinício, com decisão, motivo e instante; e o boot sobe o relógio de verificação
// até a última decisão gravada, mesmo com o clock.json mais antigo.
func TestEntradaSobreviveAoReinicioESobeORelogio(t *testing.T) {
	s, dir := firstBoot(t)
	if err := s.Clock().Persist(); err != nil { // marca d'água de t0
		t.Fatal(err)
	}
	if err := s.SetFloor(t0.Add(-time.Hour)); err != nil { // o enroll grava o piso antes da identidade
		t.Fatal(err)
	}
	v := env(t, "a")
	at := t0.Add(30 * time.Minute)
	s.Clock().Now(at)
	mustRecord(t, s.Store, v, rejected(contract.ReasonTypeNotAllowed), at)
	s.Close()

	s2 := openAt(t, dir, t0.Add(-time.Hour)) // relógio de parede 1 h ANTES do t0
	if got := s2.Clock().Now(t0.Add(-time.Hour)); !got.Equal(at) {
		t.Fatalf("relógio %v, esperava a última decisão gravada %v", got, at)
	}
	l := s2.Lookup(v, at)
	if l.Same == nil || l.Same.Reason != contract.ReasonTypeNotAllowed || !l.Same.DecidedAt.Equal(at) {
		t.Fatalf("depois do reinício: %+v", l.Same)
	}
	if rec := s2.Recovery(); rec.FloorReason != "" || rec.Corrupt != 0 || rec.Absent {
		t.Fatalf("reinício limpo: %+v", rec)
	}
}

// Dois "processos" no mesmo FLEET_STATE_DIR: o segundo Open falha com a trava (erro claro), e volta a abrir depois
// que o primeiro fecha.
func TestDoisOpensNoMesmoDiretorio(t *testing.T) {
	s, dir := firstBoot(t)
	_, err := Open(dir, t0, Options{})
	if !errors.Is(err, fsutil.ErrLocked) || !strings.Contains(err.Error(), "outro conector") {
		t.Fatalf("o segundo Open devia falhar com ErrLocked e dizer por quê, deu %v", err)
	}
	s.Close()
	if _, err := s.Record(env(t, "depois do close"), accepted, t0); err == nil {
		t.Fatal("um store fechado (sem a trava) não grava")
	}
	s2, err := Open(dir, t0, Options{})
	if err != nil {
		t.Fatalf("depois do Close a trava volta: %v", err)
	}
	s2.Close()
}

// Uma escrita que falha (write ou fsync) não conta: Record devolve erro, nada muda na memória e o arquivo volta ao
// tamanho de antes; a próxima gravação sai normalmente.
func TestFalhaNaGravacaoNaoConta(t *testing.T) {
	for _, mode := range []string{"write", "sync"} {
		t.Run(mode, func(t *testing.T) {
			fl := &faults{}
			dir := t.TempDir()
			s := openWith(t, dir, t0, Options{}, fl.config())
			before := storeBytes(t, dir)
			v := env(t, "a")
			if mode == "write" {
				fl.failWrite = errors.New("ENOSPC simulado")
			} else {
				fl.failSync = errors.New("EIO simulado")
			}
			if _, err := s.Record(v, accepted, t0); err == nil {
				t.Fatal("a gravação devia falhar")
			}
			if l := s.Lookup(v, t0); l.Same != nil {
				t.Fatal("a memória registrou uma decisão que não foi gravada")
			}
			if after := storeBytes(t, dir); string(after) != string(before) {
				t.Fatalf("o arquivo não voltou ao tamanho de antes: %q", after)
			}
			fl.failWrite, fl.failSync = nil, nil
			mustRecord(t, s.Store, v, accepted, t0)
		})
	}
}

// Se nem o corte de volta der certo, o arquivo tem bytes que o store não garante: a próxima gravação reescreve o
// arquivo A PARTIR DA MEMÓRIA (temp + rename) antes de acrescentar — a decisão que falhou não volta, mesmo que os
// bytes dela tenham chegado ao disco — e nunca decide "já gravado" relendo o arquivo.
func TestCorteQueFalhaReescreveDaMemoria(t *testing.T) {
	fl := &faults{}
	dir := t.TempDir()
	s := openWith(t, dir, t0, Options{}, fl.config())
	ok := env(t, "confirmada")
	mustRecord(t, s.Store, ok, accepted, t0)
	failed := env(t, "falhou")
	fl.failSync, fl.failTruncate = errors.New("EIO simulado"), errors.New("EIO no corte")
	if _, err := s.Record(failed, accepted, t0); err == nil {
		t.Fatal("a gravação devia falhar")
	}
	if !strings.Contains(string(storeBytes(t, dir)), failed.CanonicalSHA256()) {
		t.Fatal("o teste precisa da linha da gravação que falhou visível no arquivo")
	}
	if l := s.Lookup(failed, t0); l.Same != nil {
		t.Fatal("a linha visível, mas não confirmada, foi tratada como gravada")
	}
	if st := s.Stats(); st.Writable == nil {
		t.Fatal("Stats devia dizer que o store precisa ser reescrito")
	}
	fl.failSync, fl.failTruncate = nil, nil
	other := env(t, "depois")
	mustRecord(t, s.Store, other, accepted, t0)
	content := string(storeBytes(t, dir))
	if strings.Contains(content, failed.CanonicalSHA256()) {
		t.Fatal("a reescrita a partir da memória devia tirar a linha não confirmada")
	}
	for _, v := range []*contract.Verified{ok, other} {
		if !strings.Contains(content, v.CanonicalSHA256()) {
			t.Fatal("a reescrita perdeu uma decisão confirmada")
		}
	}
	s.Close()
	s2 := openAt(t, dir, t0)
	if l := s2.Lookup(failed, t0); l.Same != nil {
		t.Fatal("no reboot a decisão que falhou não pode aparecer")
	}
	if l := s2.Lookup(ok, t0); l.Same == nil {
		t.Fatal("no reboot a decisão confirmada tem de estar lá")
	}
}

// Um arquivo que mudou por fora (outro tamanho, outro arquivo no lugar) não recebe acréscimo: o store o reescreve
// a partir da memória e só então grava.
func TestArquivoQueMudouPorForaEReescrito(t *testing.T) {
	s, dir := firstBoot(t)
	a := env(t, "a")
	mustRecord(t, s.Store, a, accepted, t0)
	path := filepath.Join(dir, FileName)
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("lixo de fora\n"); err != nil {
		t.Fatal(err)
	}
	f.Close()
	b := env(t, "b")
	mustRecord(t, s.Store, b, accepted, t0)
	if strings.Contains(string(storeBytes(t, dir)), "lixo de fora") {
		t.Fatal("o acréscimo foi feito depois de bytes de fora")
	}
	if got := kinds(t, dir); !slices.Equal(got, []string{kindHead, kindEntry, kindEntry}) {
		t.Fatalf("registros %v", got)
	}
}

// O arquivo do store nasce 0600 (modos POSIX), e continua 0600 depois de reescrito.
func TestArquivoDoStoreE0600(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("modos POSIX não existem no Windows")
	}
	s, dir := firstBoot(t)
	check := func(when string) {
		fi, err := os.Stat(filepath.Join(dir, FileName))
		if err != nil || fi.Mode().Perm() != 0o600 {
			t.Fatalf("%s: modo %v (%v), esperava 0600", when, fi.Mode().Perm(), err)
		}
	}
	check("criado")
	mustRecord(t, s.Store, env(t, "a"), accepted, t0)
	if err := s.Compact(t0.Add(30 * 24 * time.Hour)); err != nil {
		t.Fatal(err)
	}
	check("compactado")
}

// O relógio que o store abre é o do diretório (clock.json), o mesmo que o pipeline usa.
func TestStoreAbreORelogioDoDiretorio(t *testing.T) {
	s, dir := firstBoot(t)
	s.Clock().Now(t0.Add(time.Hour))
	if err := s.Clock().Persist(); err != nil {
		t.Fatal(err)
	}
	c, err := clock.Open(dir)
	if err != nil || !c.Mark().Equal(t0.Add(time.Hour)) {
		t.Fatalf("clock.json %v, %v", c.Mark(), err)
	}
}

// O arquivo que o próprio store reescreveu (criação, compactação) não parece "mudado por fora" no acréscimo
// seguinte: a identidade guardada depois da reescrita confere com a do arquivo aberto para acrescentar, e nenhuma
// reescrita espúria acontece (nem o WARN dela).
func TestReescritaPropriaNaoPareceMudancaPorFora(t *testing.T) {
	s, dir := firstBoot(t) // o arquivo nasceu por reescrita
	for i := range 3 {
		mustRecord(t, s.Store, env(t, "a"+string(rune('0'+i))), accepted, t0)
	}
	later := t0.Add(30 * 24 * time.Hour)
	if err := s.Compact(later); err != nil {
		t.Fatal(err)
	}
	mustRecord(t, s.Store, env(t, "depois da compactação"), accepted, later)
	for _, l := range s.sink.lines() {
		if strings.Contains(l, "mudou por fora") {
			t.Fatalf("reescrita espúria: %s", l)
		}
	}
	if got := kinds(t, dir); !slices.Equal(got, []string{kindHead, kindEntry}) {
		t.Fatalf("registros %v", got)
	}
}

// Logo depois de uma reescrita, outro arquivo do MESMO tamanho no lugar (uma cópia com um byte trocado) também é
// "mudado por fora": a identidade do arquivo, não só o tamanho, decide, e o store o reescreve da memória antes de
// acrescentar.
func TestArquivoTrocadoPorOutroDoMesmoTamanhoDepoisDaReescrita(t *testing.T) {
	s, dir := firstBoot(t)
	mustRecord(t, s.Store, expiringEnv(t, "vence", "2026-10-11T12:30:00Z"), accepted, t0)
	mustRecord(t, s.Store, env(t, "fica"), accepted, t0)
	later := time.Date(2026, 10, 18, 12, 30, 1, 0, time.UTC)
	if err := s.Compact(later); err != nil { // reescrita: a vencida sai
		t.Fatal(err)
	}
	path := filepath.Join(dir, FileName)
	b := storeBytes(t, dir)
	other := []byte(strings.Replace(string(b), `"version":1`, `"version":2`, 1)) // mesmo tamanho, outro conteúdo
	if len(other) != len(b) || string(other) == string(b) {
		t.Fatal("a cópia precisa ter o mesmo tamanho e outro conteúdo")
	}
	tmp := path + ".outro"
	if err := os.WriteFile(tmp, other, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}
	mustRecord(t, s.Store, env(t, "depois"), accepted, later)
	if got := kinds(t, dir); !slices.Equal(got, []string{kindHead, kindEntry, kindEntry}) { // kinds falha em linha ruim
		t.Fatalf("registros %v", got)
	}
	warned := false
	for _, l := range s.sink.lines() {
		warned = warned || strings.Contains(l, "mudou por fora")
	}
	if !warned {
		t.Fatal("a troca devia ser vista e o arquivo reescrito da memória")
	}
}

func expiringEnv(t *testing.T, name, notAfter string) *contract.Verified {
	t.Helper()
	c := command(name)
	c.NotAfter = notAfter
	return verified(t, c, taskPayload)
}

// O store mesmo garante "nunca dois aceitos sob uma chave": um accepted sob um nonce ou um command_id que outra forma
// canônica viva já ocupa é recusado (ErrKeyTaken), seja qual for a ordem em que os chamadores consultaram o store.
// Gravar o replay (rejected) sob a chave ocupada continua normal, e depois da vida da primeira a chave é livre.
func TestRecordAcceptedNuncaDivideAChave(t *testing.T) {
	s, dir := firstBoot(t)
	first := env(t, "original")
	mustRecord(t, s.Store, first, accepted, t0)
	sameCmd := command("original")
	sameCmd.Nonce = nonceOf("outro nonce")
	sameNonce := command("outro command_id")
	sameNonce.Nonce = nonceOf("original")
	before := storeBytes(t, dir)
	for name, c := range map[string]contract.Command{"command_id": sameCmd, "nonce": sameNonce} {
		if _, err := s.Record(verified(t, c, taskPayload), accepted, t0); !errors.Is(err, ErrKeyTaken) {
			t.Fatalf("%s: esperava ErrKeyTaken, deu %v", name, err)
		}
	}
	if string(storeBytes(t, dir)) != string(before) {
		t.Fatal("a recusa gravou")
	}
	mustRecord(t, s.Store, verified(t, sameCmd, taskPayload), rejected(contract.ReasonReplay), t0)
	// depois da vida da primeira (13:00 + 7 dias), o command_id está livre
	later := time.Date(2026, 10, 18, 13, 0, 1, 0, time.UTC)
	c := command("original")
	c.Nonce, c.IssuedAt, c.NotAfter = nonceOf("bem depois"), "2026-10-18T12:00:00Z", "2026-10-18T14:00:00Z"
	mustRecord(t, s.Store, verified(t, c, taskPayload), accepted, later)
}
