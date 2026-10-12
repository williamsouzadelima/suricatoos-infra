package replay

import (
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/williamsouzadelima/suricatoos-infra/fleet/contract"
	"github.com/williamsouzadelima/suricatoos-infra/fleet/internal/fsutil"
)

// expiring is an envelope whose window ends at notAfter (its entry lives until notAfter + 7 days).
func expiring(t *testing.T, name, notAfter string) *contract.Verified {
	t.Helper()
	c := command(name)
	c.NotAfter = notAfter
	return verified(t, c, taskPayload)
}

// No teto de entradas a gravação de uma entrada nova falha (ErrFull ⇒ unavailable no pipeline) e nada vai ao
// arquivo; o alerta acende antes, a 80 %. Quando entradas vencem, o próprio Record compacta e volta a gravar.
func TestTetoDeEntradasEAlerta(t *testing.T) {
	cfg := defaultConfig()
	cfg.maxEntries = 5
	dir := t.TempDir()
	s := openWith(t, dir, t0, Options{}, cfg)
	for i := range 4 {
		mustRecord(t, s.Store, expiring(t, fmt.Sprint(i), "2026-10-11T12:30:00Z"), accepted, t0)
		if got := s.Stats().Alert; got != (i+1 >= 4) {
			t.Fatalf("com %d de 5 entradas, alerta = %v", i+1, got)
		}
	}
	mustRecord(t, s.Store, env(t, "quinta"), accepted, t0)
	if st := s.Stats(); !st.Full || !st.Alert || st.Entries != 5 {
		t.Fatalf("stats %+v", st)
	}
	before := storeBytes(t, dir)
	if _, err := s.Record(env(t, "sexta"), accepted, t0); !errors.Is(err, ErrFull) {
		t.Fatalf("esperava ErrFull, deu %v", err)
	}
	if string(storeBytes(t, dir)) != string(before) {
		t.Fatal("o store cheio mudou o arquivo")
	}
	// as 4 primeiras vencem em 12:30 + 7 dias; depois disso há lugar outra vez
	later := time.Date(2026, 10, 18, 12, 30, 1, 0, time.UTC)
	c := command("sétima")
	c.IssuedAt, c.NotAfter = "2026-10-18T12:00:00Z", "2026-10-18T13:00:00Z"
	mustRecord(t, s.Store, verified(t, c, taskPayload), accepted, later)
	if st := s.Stats(); st.Entries != 2 || st.Full {
		t.Fatalf("depois da compactação: %+v", st)
	}
}

// No teto de bytes, idem; o journal de um comando já aceito ainda cabe na folga (não fica sem registrar o desfecho).
func TestTetoDeBytesEFolgaDoJournal(t *testing.T) {
	cfg := defaultConfig()
	dir := t.TempDir()
	s := openWith(t, dir, t0, Options{}, cfg)
	j := acceptedJob(t, s.Store, "aceito", contract.TypeTaskStart, taskPayload)
	s.mu.Lock()
	s.cfg.maxBytes = s.size + 10 // a próxima entrada não cabe
	s.mu.Unlock()
	if _, err := s.Record(env(t, "outra"), accepted, t0); !errors.Is(err, ErrFull) {
		t.Fatalf("esperava ErrFull, deu %v", err)
	}
	if !s.Stats().Full {
		t.Fatal("Stats.Full")
	}
	if err := s.MarkExecuting(j, t0); err != nil {
		t.Fatalf("o journal de um aceito cabe na folga: %v", err)
	}
	if err := s.RecordResult(j, failed(contract.ErrorTimeout), t0); err != nil {
		t.Fatalf("o resultado de um aceito cabe na folga: %v", err)
	}
}

// A compactação descarta as entradas vencidas (e o journal delas) por temp + rename e mantém o resto — resultados
// inclusive, relidos depois; o arquivo compactado é um store válido que reabre igual.
func TestCompactacaoDescartaVencidos(t *testing.T) {
	s, dir := firstBoot(t)
	if err := s.SetFloor(t0.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	old := expiring(t, "velha", "2026-10-11T12:30:00Z")
	mustRecord(t, s.Store, old, rejected(contract.ReasonScopeDenied), t0)
	oldJob := acceptedJob(t, s.Store, "velha-aceita", contract.TypeTaskStart, taskPayload)
	keep := expiring(t, "nova", "2026-10-12T11:00:00Z")
	mustRecord(t, s.Store, keep, rejected(contract.ReasonWrongNode), t0)
	c := command("nova-aceita")
	c.NotAfter = "2026-10-12T11:00:00Z"
	e := mustRecord(t, s.Store, verified(t, c, taskPayload), accepted, t0)
	j := *e.Job
	res := succeeded(`{"task_id":"2d5b8f0e-1c4a-4e6b-9a3d-7f0c5e1b2a49","status":"Requested"}`)
	for _, step := range []error{s.MarkExecuting(j, t0), s.RecordResult(j, res, t0), s.MarkExecuting(oldJob, t0)} {
		if step != nil {
			t.Fatal(step)
		}
	}
	at := time.Date(2026, 10, 18, 13, 0, 1, 0, time.UTC) // a velha (12:30 e 13:00 + 7 d) já venceu; a nova não
	size := s.Stats().Bytes
	if err := s.Compact(at); err != nil {
		t.Fatal(err)
	}
	if got := kinds(t, dir); !slices.Equal(got, []string{kindHead, kindFloor, kindEntry, kindEntry, kindExec, kindResult}) {
		t.Fatalf("registros depois da compactação: %v", got)
	}
	if st := s.Stats(); st.Entries != 2 || st.Bytes >= size {
		t.Fatalf("stats %+v (antes %d bytes)", st, size)
	}
	if s.Lookup(old, at).Same != nil || s.Lookup(keep, at).Same == nil {
		t.Fatal("a compactação devia tirar só a vencida")
	}
	if got, ok, err := s.Result(j, at); err != nil || !ok || !reflect.DeepEqual(got, res) {
		t.Fatalf("resultado depois da compactação: %+v %v %v", got, ok, err)
	}
	if err := s.Compact(at); err != nil { // nada a descartar: nada se reescreve
		t.Fatal(err)
	}
	s.Close()
	s2 := openAt(t, dir, at)
	if rec := s2.Recovery(); rec.Corrupt != 0 || rec.FloorReason != "" {
		t.Fatalf("o compactado reabre limpo: %+v", rec)
	}
	if got, ok, err := s2.Result(j, at); err != nil || !ok || !reflect.DeepEqual(got, res) {
		t.Fatalf("resultado depois de reabrir: %+v %v %v", got, ok, err)
	}
}

// Compactação que falha antes do rename não muda nada (arquivo e memória). Com ErrNotDurable (rename no lugar, sync
// do diretório não confirmado), a memória descreve o arquivo novo e nada se acrescenta antes de o diretório
// sincronizar.
func TestCompactacaoQueFalhaOuNaoConfirma(t *testing.T) {
	fl := &faults{}
	dir := t.TempDir()
	s := openWith(t, dir, t0, Options{}, fl.config())
	old := expiring(t, "velha", "2026-10-11T12:30:00Z")
	mustRecord(t, s.Store, old, accepted, t0)
	before := storeBytes(t, dir)
	at := time.Date(2026, 10, 18, 12, 30, 1, 0, time.UTC)

	fl.failRewrite = errors.New("ENOSPC simulado")
	if err := s.Compact(at); err == nil {
		t.Fatal("a compactação devia falhar")
	}
	if string(storeBytes(t, dir)) != string(before) || s.Stats().Entries != 1 {
		t.Fatal("compactação que falhou mudou o arquivo ou a memória")
	}
	fl.failRewrite = nil

	fl.failRewriteAfter = fsutil.ErrNotDurable
	if err := s.Compact(at); !errors.Is(err, fsutil.ErrNotDurable) {
		t.Fatalf("esperava ErrNotDurable, deu %v", err)
	}
	fl.failRewriteAfter = nil
	if s.Stats().Entries != 0 {
		t.Fatal("o arquivo novo está no lugar: a memória tem de descrevê-lo")
	}
	fl.failSyncDir = errors.New("EIO no diretório")
	n := fl.syncDirs
	if _, err := s.Record(env(t, "depois"), accepted, at.Add(-24*time.Hour*6)); err == nil {
		t.Fatal("nada se acrescenta antes de o diretório da reescrita sincronizar")
	}
	if fl.syncDirs != n+1 {
		t.Fatalf("o sync do diretório devia vir antes do acréscimo (%d chamadas)", fl.syncDirs-n)
	}
	fl.failSyncDir = nil
	mustRecord(t, s.Store, env(t, "depois"), accepted, at.Add(-24*time.Hour*6))
}

// Uso concorrente (o pipeline grava, o executor anda o journal, o timer compacta): sem corrida (-race), sem decisão
// duplicada, e o arquivo reabre com tudo.
func TestStoreSobConcorrencia(t *testing.T) {
	s, dir := firstBoot(t)
	const workers, each = 6, 20
	var wg sync.WaitGroup
	for w := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range each {
				v := env(t, fmt.Sprintf("w%d-%d", w, i))
				e, err := s.Record(v, accepted, t0)
				if err != nil {
					t.Error(err)
					return
				}
				if _, err := s.Record(v, accepted, t0); !errors.Is(err, ErrRecorded) {
					t.Errorf("gravar de novo: %v", err)
				}
				if err := s.MarkExecuting(*e.Job, t0); err != nil {
					t.Error(err)
				}
				if s.Lookup(v, t0).Same == nil {
					t.Error("gravada e não achada")
				}
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for range 30 {
			if err := s.Compact(t0); err != nil {
				t.Error(err)
			}
			_ = s.Stats()
		}
	}()
	wg.Wait()
	if st := s.Stats(); st.Entries != workers*each {
		t.Fatalf("entradas %d", st.Entries)
	}
	s.Close()
	s2 := openWith(t, dir, t0, Options{}, defaultConfig())
	if rec := s2.Recovery(); rec.Corrupt != 0 || len(rec.Interrupted) != workers*each {
		t.Fatalf("recovery: corrupt %d, interrompidos %d", rec.Corrupt, len(rec.Interrupted))
	}
}

// entryLineMax é mesmo um teto da linha de uma entrada: com todo membro no seu máximo a linha cabe.
func TestEntryLineMaxCobreAMaiorEntrada(t *testing.T) {
	r := record{K: kindEntry, At: 1<<63 - 1, Canon: strings.Repeat("f", 64), Nonce: strings.Repeat("f", 64),
		Cmd: "ffffffff-ffff-4fff-bfff-ffffffffffff", Type: strings.Repeat("a", 31) + "." + strings.Repeat("b", 32),
		Tenant: strings.Repeat("t", 64), Decision: string(contract.DecisionRejected),
		Reason: string(contract.ReasonUnsupportedReportVariant), Expires: 1<<63 - 1}
	line, err := encodeLine(r)
	if err != nil {
		t.Fatal(err)
	}
	if len(line) > entryLineMax {
		t.Fatalf("a maior entrada tem %d bytes, acima de entryLineMax = %d", len(line), entryLineMax)
	}
}
