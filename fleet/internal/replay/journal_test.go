package replay

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/williamsouzadelima/suricatoos-infra/fleet/contract"
)

// acceptedJob records an accepted command of type typ and returns its job.
func acceptedJob(t *testing.T, s *Store, name string, typ contract.CommandType, payload string) Job {
	t.Helper()
	c := command(name)
	c.Type = typ
	e := mustRecord(t, s, verified(t, c, payload), accepted, t0)
	if e.Job == nil || e.Job.State != StateReceived || e.Job.Type != typ || e.Job.Tenant != "acme" {
		t.Fatalf("job %+v", e.Job)
	}
	return *e.Job
}

func succeeded(output string) Result {
	return Result{Status: contract.StatusSucceeded, StartedAt: "2026-10-11T12:00:05Z", FinishedAt: "2026-10-11T12:00:09Z",
		Output: []byte(output)}
}

func failed(code contract.ErrorCode) Result {
	return Result{Status: contract.StatusFailed, StartedAt: "2026-10-11T12:00:05Z", FinishedAt: "2026-10-11T12:00:09Z",
		Error: &contract.ResultError{Code: code, Message: "falhou (texto do conector)"}}
}

func jobOf(t *testing.T, s *Store, j Job) Job {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	e, err := s.findJobLocked(j, t0)
	if err != nil {
		t.Fatal(err)
	}
	return s.jobViewLocked(e)
}

// recebido → executando → resultado → entregue, cada passo durável e no arquivo, com a contagem de resultados
// pendentes; o reinício reconstrói o journal e relê o resultado gravado byte a byte.
func TestJournalRecebidoExecutandoResultadoEntregue(t *testing.T) {
	s, dir := firstBoot(t)
	j := acceptedJob(t, s.Store, "a", contract.TypeTaskStart, taskPayload)
	if err := s.MarkExecuting(j, t0.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	res := succeeded(`{"task_id":"2d5b8f0e-1c4a-4e6b-9a3d-7f0c5e1b2a49","status":"Requested"}`)
	if err := s.RecordResult(j, res, t0.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	if got := jobOf(t, s.Store, j); got.State != StateResult || got.Status != contract.StatusSucceeded || s.Stats().PendingResults != 1 {
		t.Fatalf("job %+v, pendentes %d", got, s.Stats().PendingResults)
	}
	got, ok, err := s.Result(j, t0)
	if err != nil || !ok || !reflect.DeepEqual(got, res) {
		t.Fatalf("Result = %+v, %v, %v", got, ok, err)
	}
	if err := s.MarkDelivered(j, t0.Add(3*time.Second)); err != nil {
		t.Fatal(err)
	}
	if s.Stats().PendingResults != 0 {
		t.Fatal("entregue não é mais pendente")
	}
	want := []string{kindHead, kindEntry, kindExec, kindResult, kindDelivered}
	if k := kinds(t, dir); !reflect.DeepEqual(k, want) {
		t.Fatalf("registros %v", k)
	}
	s.Close()
	s2 := openWith(t, dir, t0, Options{}, defaultConfig())
	if got := jobOf(t, s2.Store, j); got.State != StateDelivered {
		t.Fatalf("depois do reinício: %+v", got)
	}
	if got, ok, err := s2.Result(j, t0); err != nil || !ok || !reflect.DeepEqual(got, res) {
		t.Fatalf("Result depois do reinício = %+v, %v, %v", got, ok, err)
	}
}

// Passo fora de ordem é ErrJobState e nada vai ao arquivo; job de rejeição ou desconhecido é ErrNoJob.
func TestJournalForaDeOrdemEErro(t *testing.T) {
	s, dir := firstBoot(t)
	j := acceptedJob(t, s.Store, "a", contract.TypeTaskStart, taskPayload)
	before := storeBytes(t, dir)
	if err := s.MarkDelivered(j, t0); !errors.Is(err, ErrJobState) {
		t.Fatalf("entregue antes do resultado: %v", err)
	}
	if err := s.MarkExecuting(j, t0); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkExecuting(j, t0); !errors.Is(err, ErrJobState) {
		t.Fatalf("executando duas vezes: %v", err)
	}
	if err := s.RecordResult(j, failed(contract.ErrorGVM), t0); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordResult(j, failed(contract.ErrorGVM), t0); !errors.Is(err, ErrJobState) {
		t.Fatalf("resultado duas vezes: %v", err)
	}
	if err := s.MarkExecuting(j, t0); !errors.Is(err, ErrJobState) {
		t.Fatalf("executando depois do resultado: %v", err)
	}
	rej := mustRecord(t, s.Store, env(t, "rejeitado"), rejected(contract.ReasonScopeDenied), t0)
	for _, other := range []Job{{CanonicalSHA256: rej.CanonicalSHA256, CommandID: rej.CommandID}, {CanonicalSHA256: strings.Repeat("0", 64), CommandID: uuidOf("x")}} {
		if err := s.MarkExecuting(other, t0); !errors.Is(err, ErrNoJob) {
			t.Fatalf("job de rejeição ou desconhecido: %v", err)
		}
	}
	if k := kinds(t, dir); len(k) != 5 { // head, entry, exec, result, entry da rejeição
		t.Fatalf("registros %v (antes: %d bytes)", k, len(before))
	}
}

// Resultado fora do contrato é ErrInvalid, sem gravar nada.
func TestResultadoForaDoContratoERecusado(t *testing.T) {
	s, dir := firstBoot(t)
	j := acceptedJob(t, s.Store, "a", contract.TypeTaskStart, taskPayload)
	tok := acceptedJob(t, s.Store, "tok", contract.TypeEnrollTokenCreate, `{"token_type":"single_host","policy":"agent-endpoint","ttl_hours":1}`)
	before := storeBytes(t, dir)
	bad := map[string]Result{
		"status estranho":    {Status: "talvez", StartedAt: "2026-10-11T12:00:05Z", FinishedAt: "2026-10-11T12:00:09Z"},
		"failed sem erro":    {Status: contract.StatusFailed, StartedAt: "2026-10-11T12:00:05Z", FinishedAt: "2026-10-11T12:00:09Z"},
		"succeeded com erro": {Status: contract.StatusSucceeded, StartedAt: "2026-10-11T12:00:05Z", FinishedAt: "2026-10-11T12:00:09Z", Error: &contract.ResultError{Code: contract.ErrorGVM}},
		"código estranho":    {Status: contract.StatusFailed, StartedAt: "2026-10-11T12:00:05Z", FinishedAt: "2026-10-11T12:00:09Z", Error: &contract.ResultError{Code: "outro"}},
		"instante ruim":      {Status: contract.StatusSucceeded, StartedAt: "2026-10-11 12:00:05", FinishedAt: "2026-10-11T12:00:09Z"},
		"output não é json":  {Status: contract.StatusSucceeded, StartedAt: "2026-10-11T12:00:05Z", FinishedAt: "2026-10-11T12:00:09Z", Output: []byte("{")},
	}
	for name, r := range bad {
		if err := s.RecordResult(j, r, t0); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: esperava ErrInvalid, deu %v", name, err)
		}
	}
	if err := s.RecordResult(tok, succeeded(`{"token_type":"single_host"}`), t0); !errors.Is(err, ErrInvalid) {
		t.Errorf("enroll_token.create sem token_id: esperava ErrInvalid, deu %v", err)
	}
	if string(storeBytes(t, dir)) != string(before) {
		t.Fatal("um resultado recusado mudou o arquivo")
	}
}

// fakeToken is the shape of a token, built here: a FICTITIOUS value that must never reach a file.
const fakeToken = "st_" + "tok01abcd." + "segredo-ficticio-do-teste"

func enrollOutput() string {
	return `{"token_id":"tok01abcd","token":"` + fakeToken + `","token_type":"single_host","policy":"agent-endpoint","max_uses":1,"expires_at":"2026-10-12T12:00:00Z","ca_pin":"sha256:` + strings.Repeat("ab", 32) + `"}`
}

// O segredo (o token da saída do enroll_token.create) nunca entra no store: nem no registro, nem depois de
// compactar; o store guarda só status e token_id, e não devolve esse resultado para reenvio.
func TestSegredoNuncaEntraNoStore(t *testing.T) {
	s, dir := firstBoot(t)
	j := acceptedJob(t, s.Store, "tok", contract.TypeEnrollTokenCreate, `{"token_type":"single_host","policy":"agent-endpoint","ttl_hours":1}`)
	if err := s.MarkExecuting(j, t0); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordResult(j, succeeded(enrollOutput()), t0); err != nil {
		t.Fatal(err)
	}
	check := func(when string) {
		b := string(storeBytes(t, dir))
		if strings.Contains(b, "segredo-ficticio") || strings.Contains(b, `"token"`) || strings.Contains(b, "ca_pin") {
			t.Fatalf("%s: o segredo (ou a saída) chegou ao store: %s", when, b)
		}
		if !strings.Contains(b, `"token_id":"tok01abcd"`) {
			t.Fatalf("%s: o token_id (não secreto) devia estar lá para a revogação", when)
		}
	}
	check("gravado")
	if _, ok, err := s.Result(j, t0); ok || err != nil {
		t.Fatalf("o resultado do enroll_token.create não se reenvia: ok=%v err=%v", ok, err)
	}
	// força uma reescrita a partir da memória (uma entrada morta para compactar)
	c := command("vence")
	c.NotAfter = "2026-10-11T12:01:00Z"
	mustRecord(t, s.Store, verified(t, c, taskPayload), accepted, t0)
	if err := s.Compact(time.Date(2026, 10, 18, 12, 30, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	check("compactado")
}

// No boot: comando aceito sem resultado (recebido ou executando) é exposto como interrompido — reportar failed com
// interrupted, nunca rodar de novo —; o resultado gravado e o entregue não.
func TestBootExpoeInterrompidos(t *testing.T) {
	s, dir := firstBoot(t)
	recv := acceptedJob(t, s.Store, "recebido", contract.TypeTaskStart, taskPayload)
	exec := acceptedJob(t, s.Store, "executando", contract.TypeTaskStop, taskPayload)
	done := acceptedJob(t, s.Store, "resultado", contract.TypeTaskResume, taskPayload)
	deliv := acceptedJob(t, s.Store, "entregue", contract.TypeTaskStart, taskPayload)
	for _, j := range []Job{exec, done, deliv} {
		if err := s.MarkExecuting(j, t0); err != nil {
			t.Fatal(err)
		}
	}
	for _, j := range []Job{done, deliv} {
		if err := s.RecordResult(j, failed(contract.ErrorGVM), t0); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.MarkDelivered(deliv, t0); err != nil {
		t.Fatal(err)
	}
	s.Close()
	s2 := openWith(t, dir, t0.Add(time.Minute), Options{}, defaultConfig())
	rec := s2.Recovery()
	if len(rec.Interrupted) != 2 || rec.Interrupted[0].CommandID != recv.CommandID || rec.Interrupted[0].State != StateReceived ||
		rec.Interrupted[1].CommandID != exec.CommandID || rec.Interrupted[1].State != StateExecuting || len(rec.SecretLost) != 0 {
		t.Fatalf("interrompidos %+v, segredo perdido %+v", rec.Interrupted, rec.SecretLost)
	}
	if s2.Stats().PendingResults != 1 {
		t.Fatalf("pendentes %d", s2.Stats().PendingResults)
	}
}

// No boot: enroll_token.create com resultado succeeded que o hub ainda não aceitou = segredo perdido (o token só
// existia na memória): exposto com o token_id, para revogar só o token e reportar secret_lost. Entregue, ou failed
// (sem token), não.
func TestBootExpoeSegredoPerdido(t *testing.T) {
	payload := `{"token_type":"single_host","policy":"agent-endpoint","ttl_hours":1}`
	s, dir := firstBoot(t)
	lost := acceptedJob(t, s.Store, "perdido", contract.TypeEnrollTokenCreate, payload)
	deliv := acceptedJob(t, s.Store, "entregue", contract.TypeEnrollTokenCreate, payload)
	fail := acceptedJob(t, s.Store, "falhou", contract.TypeEnrollTokenCreate, payload)
	for _, j := range []Job{lost, deliv} {
		if err := s.RecordResult(j, succeeded(enrollOutput()), t0); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.RecordResult(fail, failed(contract.ErrorUnavailable), t0); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkDelivered(deliv, t0); err != nil {
		t.Fatal(err)
	}
	s.Close()
	s2 := openWith(t, dir, t0, Options{}, defaultConfig())
	rec := s2.Recovery()
	if len(rec.SecretLost) != 1 || rec.SecretLost[0].CommandID != lost.CommandID || rec.SecretLost[0].TokenID != "tok01abcd" ||
		len(rec.Interrupted) != 0 {
		t.Fatalf("segredo perdido %+v, interrompidos %+v", rec.SecretLost, rec.Interrupted)
	}
	// a F2.6 revoga o token e reporta secret_lost: o resultado succeeded não entregue pode ser substituído por esse
	if err := s2.RecordResult(rec.SecretLost[0], failed(contract.ErrorSecretLost), t0); err != nil {
		t.Fatal(err)
	}
	if got := jobOf(t, s2.Store, lost); got.Status != contract.StatusFailed || got.ErrorCode != contract.ErrorSecretLost || got.TokenID != "tok01abcd" {
		t.Fatalf("depois do secret_lost: %+v", got)
	}
	// nenhuma outra substituição: nem de outro tipo, nem outro código, nem depois de entregue
	if err := s2.RecordResult(deliv, failed(contract.ErrorSecretLost), t0); !errors.Is(err, ErrJobState) {
		t.Fatalf("substituir resultado entregue: %v", err)
	}
	if err := s2.RecordResult(lost, failed(contract.ErrorSecretLost), t0); !errors.Is(err, ErrJobState) {
		t.Fatalf("substituir duas vezes: %v", err)
	}
	s2.Close()
	s3 := openWith(t, dir, t0, Options{}, defaultConfig())
	if rec := s3.Recovery(); len(rec.SecretLost) != 0 {
		t.Fatalf("depois do secret_lost gravado, não há mais segredo perdido: %+v", rec.SecretLost)
	}
}

// O resultado relido tem de ser o que foi confirmado: bytes que mudaram no disco depois (mesmo tamanho) são erro,
// nunca um resultado reenviado.
func TestResultadoRelidoConfereOChecksumGuardado(t *testing.T) {
	s, dir := firstBoot(t)
	j := acceptedJob(t, s.Store, "a", contract.TypeTaskStart, taskPayload)
	if err := s.RecordResult(j, succeeded(`{"task_id":"2d5b8f0e-1c4a-4e6b-9a3d-7f0c5e1b2a49","status":"Requested"}`), t0); err != nil {
		t.Fatal(err)
	}
	// troca a linha do resultado por OUTRA linha válida, de mesmo tamanho e com o próprio checksum certo: só o
	// checksum que a memória guardou na confirmação a denuncia
	path := filepath.Join(dir, FileName)
	lines := storeLines(t, dir)
	i := len(lines) - 1
	js := strings.Replace(lines[i][9:], "Requested", "Requestex", 1)
	lines[i] = checksum([]byte(js)) + " " + js
	if _, err := decodeLine([]byte(lines[i])); err != nil {
		t.Fatalf("a linha trocada devia ser válida por si só: %v", err)
	}
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := s.Result(j, t0); err == nil || ok {
		t.Fatalf("resultado trocado foi devolvido: ok=%v err=%v", ok, err)
	}
}
