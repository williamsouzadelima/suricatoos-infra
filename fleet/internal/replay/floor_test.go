package replay

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/williamsouzadelima/suricatoos-infra/fleet/contract"
	"github.com/williamsouzadelima/suricatoos-infra/fleet/internal/clock"
)

// enrolled leaves dir as an enroll leaves it: store and watermark present, a floor recorded, before the identity.
func enrolled(t *testing.T) string {
	t.Helper()
	s, dir := firstBoot(t)
	if err := s.SetFloor(t0.Add(-2 * time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := s.Clock().Persist(); err != nil {
		t.Fatal(err)
	}
	s.Close()
	return dir
}

func floorOf(t *testing.T, s opened) time.Time {
	t.Helper()
	f, ok := s.Floor()
	if !ok {
		t.Fatal("sem piso")
	}
	return f
}

// Store ausente num nó que já tem identidade: perda de estado. O boot grava o piso = t (o relógio de verificação),
// durável no arquivo novo antes de qualquer decisão, e o sinal "piso novo ainda não anunciado" acende.
func TestAusenteComIdentidadeGravaPiso(t *testing.T) {
	dir := enrolled(t) // marca d'água presente: só o store some
	if err := os.Remove(filepath.Join(dir, FileName)); err != nil {
		t.Fatal(err)
	}
	at := t0.Add(5 * time.Minute)
	s := openAt(t, dir, at)
	if got := floorOf(t, s); !got.Equal(at) {
		t.Fatalf("piso %v, esperava t = %v", got, at)
	}
	rec := s.Recovery()
	if !rec.Absent || !strings.HasPrefix(rec.FloorReason, "store ausente") || !s.FloorUnannounced() {
		t.Fatalf("recovery %+v, não anunciado %v", rec, s.FloorUnannounced())
	}
	if got := kinds(t, dir); !slices.Equal(got, []string{kindHead, kindFloor}) {
		t.Fatalf("o piso tem de estar no arquivo antes de qualquer decisão: %v", got)
	}
	s.Close()
	s2 := openAt(t, dir, at.Add(time.Minute)) // reinício normal: o piso continua o mesmo, sem piso novo
	if got := floorOf(t, s2); !got.Equal(at) || s2.Recovery().FloorReason != "" {
		t.Fatalf("depois do reinício: piso %v, recovery %+v", got, s2.Recovery())
	}
}

// Store corrompido (um registro completo que falha o checksum): o boot aproveita o resto, grava o piso e reescreve
// o arquivo sem o registro ruim — o boot seguinte não vê corrupção nem grava piso novo.
func TestStoreCorrompidoGravaPisoEAproveitaORestante(t *testing.T) {
	dir := enrolled(t)
	s := openAt(t, dir, t0)
	a, b, c := env(t, "a"), env(t, "b"), env(t, "c")
	for _, v := range []*contract.Verified{a, b, c} {
		mustRecord(t, s.Store, v, rejected(contract.ReasonTenantUnknown), t0)
	}
	s.Close()
	path := filepath.Join(dir, FileName)
	lines := storeLines(t, dir)
	i := slices.IndexFunc(lines, func(l string) bool { return strings.Contains(l, b.CanonicalSHA256()) })
	lines[i] = strings.Replace(lines[i], `"reason":"tenant_unknown"`, `"reason":"tenant_unknowm"`, 1) // mesmo tamanho
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	at := t0.Add(10 * time.Minute)
	s2 := openAt(t, dir, at)
	rec := s2.Recovery()
	if rec.Corrupt != 1 || rec.FirstCorrupt == nil || rec.FirstCorrupt.Line != i+1 || !strings.Contains(rec.FloorReason, "corrompido") {
		t.Fatalf("recovery %+v (first %+v)", rec, rec.FirstCorrupt)
	}
	if got := floorOf(t, s2); !got.Equal(at) {
		t.Fatalf("piso %v, esperava %v", got, at)
	}
	if s2.Lookup(a, at).Same == nil || s2.Lookup(c, at).Same == nil || s2.Lookup(b, at).Same != nil {
		t.Fatal("o boot devia aproveitar a e c e perder só b")
	}
	if strings.Contains(string(storeBytes(t, dir)), "tenant_unknowm") {
		t.Fatal("o arquivo devia ter sido reescrito sem o registro corrompido")
	}
	s2.Close()
	s3 := openAt(t, dir, at.Add(time.Minute))
	if rec := s3.Recovery(); rec.Corrupt != 0 || rec.FloorReason != "" {
		t.Fatalf("o boot seguinte não vê corrupção: %+v", rec)
	}
	if got := floorOf(t, s3); !got.Equal(at) {
		t.Fatalf("o piso do boot anterior ficou gravado: %v", got)
	}
}

// Lixo puro, arquivo sem cabeçalho, linha longa demais: tudo é corrupção, com piso e reescrita.
func TestStoreSemCabecalhoOuComLixoECorrompido(t *testing.T) {
	for name, content := range map[string]string{
		"lixo":          "isto não é um store\n",
		"sem cabeçalho": mustLine(t, record{K: kindFloor, At: 1}),
		"linha longa":   mustLine(t, record{K: kindHead, Version: fileVersion}) + strings.Repeat("x", maxLineBytes+1) + "\n",
		"cabeçalho 2x":  mustLine(t, record{K: kindHead, Version: fileVersion}) + mustLine(t, record{K: kindHead, Version: fileVersion}),
		"outra versão":  mustLine(t, record{K: kindHead, Version: 2}),
		"tipo estranho": mustLine(t, record{K: kindHead, Version: fileVersion}) + mustLine(t, record{K: "outro", At: 1}),
		"journal órfão": mustLine(t, record{K: kindHead, Version: fileVersion}) + mustLine(t, record{K: kindExec, Canon: strings.Repeat("a", 64), At: 1}),
	} {
		t.Run(name, func(t *testing.T) {
			dir := enrolled(t)
			if err := os.WriteFile(filepath.Join(dir, FileName), []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			s := openAt(t, dir, t0)
			if rec := s.Recovery(); rec.Corrupt == 0 || rec.FloorReason == "" || rec.RewriteErr != nil {
				t.Fatalf("recovery %+v", rec)
			}
			if got := kinds(t, dir); got[0] != kindHead || !slices.Contains(got, kindFloor) {
				t.Fatalf("o arquivo reescrito: %v", got)
			}
		})
	}
}

func mustLine(t *testing.T, r record) string {
	t.Helper()
	b, err := encodeLine(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// Store ilegível (um diretório no lugar do arquivo): piso de replay, nada do que estava lá é usado, e — como o
// arquivo não pode ser trocado — o store não grava nada (unavailable) até uma reescrita dar certo.
func TestStoreIlegivelGravaPisoENaoGrava(t *testing.T) {
	dir := enrolled(t)
	path := filepath.Join(dir, FileName)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(path, "dentro"), 0o700); err != nil {
		t.Fatal(err)
	}
	s := openAt(t, dir, t0)
	rec := s.Recovery()
	if rec.Unreadable == nil || !strings.Contains(rec.FloorReason, "ilegível") || rec.RewriteErr == nil {
		t.Fatalf("recovery %+v", rec)
	}
	if _, ok := s.Floor(); !ok {
		t.Fatal("o piso vale na memória mesmo sem poder ser gravado")
	}
	if _, err := s.Record(env(t, "a"), accepted, t0); err == nil {
		t.Fatal("sem store gravável nenhuma decisão pode ser gravada")
	}
	if s.Stats().Writable == nil {
		t.Fatal("Stats devia dizer que o store não está gravável")
	}
}

// Registro final parcial (queda no meio de um acréscimo): descartado no boot, sem piso (ninguém viu o ack dele) e
// sem perder o que veio antes.
func TestRegistroFinalParcialEDescartadoSemPiso(t *testing.T) {
	dir := enrolled(t)
	s := openAt(t, dir, t0)
	a := env(t, "a")
	mustRecord(t, s.Store, a, rejected(contract.ReasonWrongNode), t0)
	s.Close()
	before := storeBytes(t, dir)
	half := mustLine(t, record{K: kindEntry, At: 1, Canon: strings.Repeat("b", 64)})
	half = half[:len(half)/2]
	f, err := os.OpenFile(filepath.Join(dir, FileName), os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString(half)
	f.Close()

	s2 := openAt(t, dir, t0)
	rec := s2.Recovery()
	if rec.DiscardedBytes != int64(len(half)) || rec.Corrupt != 0 || rec.FloorReason != "" {
		t.Fatalf("recovery %+v", rec)
	}
	if string(storeBytes(t, dir)) != string(before) {
		t.Fatal("o arquivo devia voltar ao que era antes do registro parcial")
	}
	if s2.Lookup(a, t0).Same == nil {
		t.Fatal("o registro anterior ao parcial se perdeu")
	}
	mustRecord(t, s2.Store, env(t, "c"), accepted, t0) // e o store segue gravando
}

// O piso é publicado arredondado PARA CIMA ao segundo (contract.FormatReplayFloor), e Floor guarda a precisão toda.
func TestPisoArredondadoParaCima(t *testing.T) {
	s, _ := firstBoot(t)
	at := t0.Add(400 * time.Millisecond)
	if err := s.SetFloor(at); err != nil {
		t.Fatal(err)
	}
	if got := s.ReplayFloor(); got != "2026-10-11T12:00:01Z" {
		t.Fatalf("ReplayFloor %q", got)
	}
	if got := floorOf(t, s); !got.Equal(at) {
		t.Fatalf("Floor %v", got)
	}
	if err := s.SetFloor(t0.Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if got := s.ReplayFloor(); got != "2026-10-11T12:00:02Z" {
		t.Fatalf("segundo inteiro não sobe: %q", got)
	}
}

// Todo (re)enroll grava um piso novo, que fica "não anunciado" até um heartbeat que o leve dar certo; um heartbeat
// que levou um piso mais antigo não apaga o sinal. No boot o sinal volta (conservador: heartbeat antes do 1º poll).
func TestReEnrollGravaPisoNovoAteOHeartbeat(t *testing.T) {
	dir := enrolled(t)
	s := openAt(t, dir, t0)
	old := s.ReplayFloor()
	if !s.FloorUnannounced() {
		t.Fatal("no boot o piso conta como não anunciado")
	}
	s.MarkFloorAnnounced(old)
	if s.FloorUnannounced() {
		t.Fatal("o heartbeat com o piso atual anuncia")
	}
	at := t0.Add(3 * time.Hour)
	if err := s.SetFloor(at); err != nil {
		t.Fatal(err)
	}
	if !s.FloorUnannounced() || s.ReplayFloor() == old {
		t.Fatal("re-enroll: piso novo e não anunciado")
	}
	s.MarkFloorAnnounced(old)
	if !s.FloorUnannounced() {
		t.Fatal("um heartbeat com o piso antigo não anuncia o novo")
	}
	if err := s.SetFloor(t0); err != nil { // o piso só avança
		t.Fatal(err)
	}
	if got := floorOf(t, s); !got.Equal(at) {
		t.Fatalf("o piso voltou: %v", got)
	}
	s.Close()
	s2 := openAt(t, dir, at)
	if got := floorOf(t, s2); !got.Equal(at) || !s2.FloorUnannounced() || s2.Recovery().FloorReason != "" {
		t.Fatalf("depois do reboot: piso %v, não anunciado %v, recovery %+v", got, s2.FloorUnannounced(), s2.Recovery())
	}
}

// Marca d'água inutilizável (clock.json corrompido), ou ausente num nó com identidade: um relógio que voltou poderia
// reabrir janela vencida, então o boot trata como perda de estado e grava o piso.
func TestMarcaDaguaPerdidaGravaPiso(t *testing.T) {
	for name, damage := range map[string]func(path string) error{
		"corrompida": func(p string) error { return os.WriteFile(p, []byte("{"), 0o600) },
		"ausente":    os.Remove,
	} {
		t.Run(name, func(t *testing.T) {
			dir := enrolled(t)
			if err := damage(filepath.Join(dir, clock.FileName)); err != nil {
				t.Fatal(err)
			}
			at := t0.Add(time.Hour)
			s := openAt(t, dir, at)
			if got := floorOf(t, s); !got.Equal(at) || !strings.Contains(s.Recovery().FloorReason, "marca d'água") {
				t.Fatalf("piso %v, recovery %+v", got, s.Recovery())
			}
		})
	}
	// sem identidade (primeiro boot), clock.json ausente é normal
	s, _ := firstBoot(t)
	if _, ok := s.Floor(); ok {
		t.Fatal("primeiro boot sem clock.json não é perda")
	}
}

// Um nó com identidade cujo store não tem piso nenhum (o piso do enroll não chegou ao disco): o boot grava um.
func TestIdentidadeSemPisoGravaPiso(t *testing.T) {
	s, dir := firstBoot(t)
	if err := s.Clock().Persist(); err != nil {
		t.Fatal(err)
	}
	s.Close()
	s2 := openAt(t, dir, t0)
	if _, ok := s2.Floor(); !ok || !strings.Contains(s2.Recovery().FloorReason, "sem piso") {
		t.Fatalf("recovery %+v", s2.Recovery())
	}
	if got := kinds(t, dir); !slices.Equal(got, []string{kindHead, kindFloor}) {
		t.Fatalf("registros %v", got)
	}
}

// O piso que não se grava fica valendo na memória e PENDENTE: nada se grava antes dele, e a próxima gravação o
// grava primeiro.
func TestPisoQueNaoSeGravaFicaPendente(t *testing.T) {
	fl := &faults{}
	dir := t.TempDir()
	s := openWith(t, dir, t0, Options{}, fl.config())
	fl.failSync = errors.New("EIO simulado")
	if err := s.SetFloor(t0); err == nil {
		t.Fatal("SetFloor devia devolver o erro da gravação")
	}
	if _, ok := s.Floor(); !ok {
		t.Fatal("o piso vale na memória")
	}
	if _, err := s.Record(env(t, "a"), accepted, t0); err == nil {
		t.Fatal("nada se grava antes do piso")
	}
	fl.failSync = nil
	mustRecord(t, s.Store, env(t, "a"), accepted, t0)
	if got := kinds(t, dir); !slices.Equal(got, []string{kindHead, kindFloor, kindEntry}) {
		t.Fatalf("o piso tem de ir antes da entrada: %v", got)
	}
}

// Um replay.log existente sem nenhum registro completo — 0 byte, ou só os bytes de um registro parcial — conta como
// AUSENTE (sonda P1 da revisão): é reescrito com o cabeçalho na hora, nunca vira "store corrompido", e o piso só vem
// quando o nó já tem identidade, como para o arquivo que não existe.
func TestStoreSemRegistroCompletoContaComoAusente(t *testing.T) {
	for name, content := range map[string]string{"0 byte": "", "só parcial": `9f8e7d6c {"k":"entry","at":1`} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, FileName), []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			s := openWith(t, dir, t0, Options{}, defaultConfig()) // primeiro boot: sem identidade
			rec := s.Recovery()
			if !rec.Absent || rec.Corrupt != 0 || rec.FloorReason != "" || rec.RewriteErr != nil || rec.DiscardedBytes != int64(len(content)) {
				t.Fatalf("recovery %+v", rec)
			}
			if got := kinds(t, dir); !slices.Equal(got, []string{kindHead}) {
				t.Fatalf("o arquivo devia ser reescrito com o cabeçalho: %v", got)
			}
			if err := s.SetFloor(t0); err != nil { // o enroll
				t.Fatal(err)
			}
			mustRecord(t, s.Store, env(t, "a"), accepted, t0)
			s.Close()
			s2 := openAt(t, dir, t0.Add(time.Minute))
			if rec := s2.Recovery(); rec.Corrupt != 0 || rec.FloorReason != "" {
				t.Fatalf("o boot seguinte achou um store corrompido: %+v", rec)
			}
			s2.Close()

			// num nó com identidade, o mesmo arquivo é perda de estado (ausente), nunca corrupção
			dir2 := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir2, FileName), []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			s3 := openAt(t, dir2, t0)
			if rec := s3.Recovery(); rec.Corrupt != 0 || !strings.HasPrefix(rec.FloorReason, "store ausente") {
				t.Fatalf("com identidade: %+v", rec)
			}
		})
	}
}

// O boot confirma no disco o log que mantém como está (um fsync do arquivo e um do diretório) antes de confiar nele:
// depois de uma queda do PROCESSO, o page cache ainda pode ter um acréscimo cujo fsync nunca voltou. Um boot que
// reescreve o arquivo não precisa disso (a reescrita já confirma).
func TestBootConfirmaNoDiscoOLogQueMantem(t *testing.T) {
	dir := enrolled(t)
	s := openAt(t, dir, t0)
	mustRecord(t, s.Store, env(t, "a"), accepted, t0)
	s.Close()
	fl := &faults{}
	s2 := openWith(t, dir, t0, Options{IdentityExists: true}, fl.config())
	if fl.syncFiles != 1 || fl.syncDirs < 1 || fl.rewrites != 0 {
		t.Fatalf("syncs do arquivo %d, do diretório %d, reescritas %d", fl.syncFiles, fl.syncDirs, fl.rewrites)
	}
	if l := s2.Lookup(env(t, "a"), t0); l.Same == nil || l.Unconfirmed != nil {
		t.Fatalf("lookup %+v", l)
	}
	fl2 := &faults{}
	openWith(t, t.TempDir(), t0, Options{}, fl2.config()) // ausente: a reescrita confirma
	if fl2.syncFiles != 0 || fl2.rewrites != 1 {
		t.Fatalf("store novo: syncs do arquivo %d, reescritas %d", fl2.syncFiles, fl2.rewrites)
	}
}

// Se o fsync do log lido falha, o boot o reescreve a partir da memória (temp + rename, que confirma) e segue.
func TestBootQueNaoConfirmaOLogReescreveDaMemoria(t *testing.T) {
	dir := enrolled(t)
	s := openAt(t, dir, t0)
	mustRecord(t, s.Store, env(t, "a"), rejected(contract.ReasonScopeDenied), t0)
	s.Close()
	fl := &faults{failSyncFile: errors.New("EIO simulado")}
	s2 := openWith(t, dir, t0, Options{IdentityExists: true}, fl.config())
	if fl.rewrites != 1 || s2.Recovery().RewriteErr != nil {
		t.Fatalf("reescritas %d, recovery %+v", fl.rewrites, s2.Recovery())
	}
	if l := s2.Lookup(env(t, "a"), t0); l.Same == nil || l.Unconfirmed != nil {
		t.Fatalf("lookup %+v", l)
	}
}

// Se nem o fsync nem a reescrita confirmam o que o boot leu, nada disso é confiável ainda: o Lookup não devolve
// entrada nenhuma (Unconfirmed — o pipeline responde unavailable, nem a reentrega leva o ack gravado), o resultado
// gravado não se relê e nada se grava. Quando o disco volta, a próxima consulta confirma (reescreve) e tudo volta.
func TestBootSemConfirmacaoNaoConfiaNoQueLeu(t *testing.T) {
	dir := enrolled(t)
	s := openAt(t, dir, t0)
	j := acceptedJob(t, s.Store, "a", contract.TypeTaskStart, taskPayload)
	if err := s.RecordResult(j, succeeded(`{"task_id":"2d5b8f0e-1c4a-4e6b-9a3d-7f0c5e1b2a49","status":"Requested"}`), t0); err != nil {
		t.Fatal(err)
	}
	s.Close()
	boom := errors.New("EIO simulado")
	fl := &faults{failSyncFile: boom, failRewrite: boom}
	s2 := openWith(t, dir, t0, Options{IdentityExists: true}, fl.config())
	if s2.Recovery().RewriteErr == nil || s2.Stats().Writable == nil {
		t.Fatalf("recovery %+v, stats %+v", s2.Recovery(), s2.Stats())
	}
	v := env(t, "a")
	if l := s2.Lookup(v, t0); l.Same != nil || len(l.Recorded) != 0 || l.Unconfirmed == nil {
		t.Fatalf("o que o boot não confirmou foi servido: %+v", l)
	}
	if _, ok, err := s2.Result(j, t0); ok || err == nil {
		t.Fatalf("resultado não confirmado relido: ok=%v err=%v", ok, err)
	}
	if _, err := s2.Record(env(t, "b"), accepted, t0); err == nil {
		t.Fatal("gravou num store não confirmado")
	}
	fl.failSyncFile, fl.failRewrite = nil, nil
	l := s2.Lookup(v, t0)
	if l.Unconfirmed != nil || l.Same == nil {
		t.Fatalf("depois de o disco voltar: %+v", l)
	}
	if _, ok, err := s2.Result(j, t0); !ok || err != nil {
		t.Fatalf("resultado depois de confirmar: ok=%v err=%v", ok, err)
	}
	if s2.Stats().Writable != nil {
		t.Fatalf("stats %+v", s2.Stats())
	}
}

// SetFloor, Compact e MarkDelivered — as chamadas que o conector faz direto no store — usam o relógio de
// verificação por construção: recebem a leitura do relógio de parede e decidem com t = max(agora, marca). Um relógio
// de parede atrás da marca não dá um piso mais baixo, não salva da compactação uma entrada já vencida na marca, e não
// data o passo do journal no passado.
func TestChamadasDiretasUsamORelogioDeVerificacao(t *testing.T) {
	s, dir := firstBoot(t)
	mark := t0.Add(2 * time.Hour)
	s.Clock().Now(mark)
	behind := t0.Add(-time.Hour) // relógio de parede cru, atrás da marca

	if err := s.SetFloor(behind); err != nil {
		t.Fatal(err)
	}
	if got := floorOf(t, s); !got.Equal(mark) {
		t.Fatalf("piso %v, esperava a marca %v", got, mark)
	}

	j := acceptedJob(t, s.Store, "a", contract.TypeTaskStart, taskPayload)
	if err := s.RecordResult(j, failed(contract.ErrorGVM), mark); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkDelivered(j, behind); err != nil {
		t.Fatal(err)
	}
	lines := storeLines(t, dir)
	r, err := decodeLine([]byte(lines[len(lines)-1]))
	if err != nil || r.K != kindDelivered || r.At != mark.UnixNano() {
		t.Fatalf("passo delivered %+v (%v), esperava at = marca", r, err)
	}

	mustRecord(t, s.Store, expiringEnv(t, "vence", "2026-10-11T12:30:00Z"), accepted, mark)
	later := time.Date(2026, 10, 18, 12, 30, 1, 0, time.UTC) // a "vence" já venceu aqui
	s.Clock().Now(later)
	if err := s.Compact(behind); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(storeBytes(t, dir)), expiringEnv(t, "vence", "2026-10-11T12:30:00Z").CanonicalSHA256()) {
		t.Fatal("a compactação decidiu pelo relógio de parede cru: a entrada vencida na marca ficou")
	}
}
