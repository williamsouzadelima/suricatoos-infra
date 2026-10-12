package audit

import (
	"errors"
	"math/rand/v2"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/williamsouzadelima/suricatoos-infra/fleet/contract"
)

// rejectEntries reads the reject stream of dir (checking its chain) and decodes every line.
func rejectEntries(t *testing.T, dir string) []contract.AuditEntry {
	t.Helper()
	var out []contract.AuditEntry
	for _, line := range allLines(t, dir, defaultConfig().reject) {
		var e contract.AuditEntry
		if err := contract.DecodeStrict([]byte(line), &e); err != nil {
			t.Fatal(err)
		}
		out = append(out, e)
	}
	return out
}

func ofEvent(es []contract.AuditEntry, ev contract.AuditEvent) []contract.AuditEntry {
	var out []contract.AuditEntry
	for _, e := range es {
		if e.Event == ev {
			out = append(out, e)
		}
	}
	return out
}

func boot(d time.Duration) time.Time { return testBoot.Add(d) }

func utcAt(d time.Duration) string { return contract.FormatUTCTime(testBoot.Add(d)) }

// Os envelopes recusados nas linhas 0–2 só viram contagem: o período começa no Open (ou na linha anterior do
// tipo); a contagem vai para o fluxo, com since = o começo do período, na primeira ocorrência (ou Flush) depois
// de o período durar um minuto; as do meio somam na próxima linha.
func TestUnauthenticatedViraContagemNoMaximoUmaPorMinuto(t *testing.T) {
	dir := t.TempDir()
	l, _ := openAt(t, dir, defaultConfig())
	steps := []struct {
		d      time.Duration
		reason contract.RejectReason
	}{
		{10 * time.Second, contract.ReasonBadEnvelope},
		{20 * time.Second, contract.ReasonBadSignature},
		{59 * time.Second, contract.ReasonPayloadMismatch},
	}
	for _, s := range steps {
		if err := l.Unauthenticated(boot(s.d), s.reason); err != nil {
			t.Fatal(err)
		}
	}
	if es := rejectEntries(t, dir); len(es) != 0 {
		t.Fatalf("dentro do primeiro minuto nenhuma linha: %v", es)
	}
	if err := l.Unauthenticated(boot(70*time.Second), contract.ReasonBadSignature); err != nil {
		t.Fatal(err)
	}
	for _, d := range []time.Duration{80 * time.Second, 100 * time.Second} {
		if err := l.Unauthenticated(boot(d), contract.ReasonBadEnvelope); err != nil {
			t.Fatal(err)
		}
	}
	if err := l.Flush(boot(129 * time.Second)); err != nil { // 59 s depois da linha anterior: ainda não
		t.Fatal(err)
	}
	if err := l.Flush(boot(130 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := l.Flush(boot(400 * time.Second)); err != nil { // nada pendente: nada a gravar
		t.Fatal(err)
	}
	es := rejectEntries(t, dir)
	want := []contract.AuditUnauthenticated{
		{Since: utcAt(0), BadEnvelope: 1, PayloadMismatch: 1, BadSignature: 2},
		{Since: utcAt(70 * time.Second), BadEnvelope: 2},
	}
	ats := []string{utcAt(70 * time.Second), utcAt(130 * time.Second)}
	if len(es) != len(want) {
		t.Fatalf("%d linhas: %v", len(es), es)
	}
	for i, e := range es {
		if e.Event != contract.AuditEventUnauthenticated || e.At != ats[i] || *e.Unauthenticated != want[i] {
			t.Errorf("linha %d: %s %s %+v, esperava em %s %+v", i, e.Event, e.At, *e.Unauthenticated, ats[i], want[i])
		}
	}
}

func TestRedeliveredViraContagemNoMaximoUmaPorMinuto(t *testing.T) {
	dir := t.TempDir()
	l, _ := openAt(t, dir, defaultConfig())
	for _, d := range []time.Duration{5 * time.Second, 30 * time.Second, 61 * time.Second, 90 * time.Second} {
		if err := l.Redelivered(boot(d)); err != nil {
			t.Fatal(err)
		}
	}
	if err := l.Flush(boot(120 * time.Second)); err != nil { // 59 s depois da linha das 61 s
		t.Fatal(err)
	}
	if err := l.Flush(boot(121 * time.Second)); err != nil {
		t.Fatal(err)
	}
	es := ofEvent(rejectEntries(t, dir), contract.AuditEventRedelivered)
	want := []struct {
		at string
		r  contract.AuditRedelivered
	}{
		{utcAt(61 * time.Second), contract.AuditRedelivered{Since: utcAt(0), Count: 3}},
		{utcAt(121 * time.Second), contract.AuditRedelivered{Since: utcAt(61 * time.Second), Count: 1}},
	}
	if len(es) != len(want) {
		t.Fatalf("%d linhas: %v", len(es), es)
	}
	for i, e := range es {
		if e.At != want[i].at || *e.Redelivered != want[i].r {
			t.Errorf("linha %d: %s %+v, esperava %s %+v", i, e.At, *e.Redelivered, want[i].at, want[i].r)
		}
	}
}

// version_mismatch não tem contagem: no máximo uma linha a cada 10 minutos, e as do meio não deixam rastro.
func TestVersionMismatchNoMaximoUmaA10Minutos(t *testing.T) {
	dir := t.TempDir()
	l, _ := openAt(t, dir, defaultConfig())
	calls := []struct {
		d    time.Duration
		node string
	}{
		{1 * time.Minute, "1.0"}, {5 * time.Minute, "1.1"}, {10*time.Minute + 59*time.Second, "1.0"},
		{11 * time.Minute, "1.0"}, {20 * time.Minute, "1.0"}, {21 * time.Minute, "1.0"},
	}
	for _, c := range calls {
		if err := l.VersionMismatch(boot(c.d), []string{c.node}, []string{"2.0"}); err != nil {
			t.Fatal(err)
		}
	}
	es := ofEvent(rejectEntries(t, dir), contract.AuditEventVersionMismatch)
	want := []string{utcAt(time.Minute), utcAt(11 * time.Minute), utcAt(21 * time.Minute)}
	if len(es) != len(want) {
		t.Fatalf("%d linhas", len(es))
	}
	for i, e := range es {
		if e.At != want[i] {
			t.Errorf("linha %d em %s, esperava %s", i, e.At, want[i])
		}
	}
	if err := l.VersionMismatch(boot(40*time.Minute), nil, []string{"2.0"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("versões inválidas: esperava ErrInvalid, deu %v", err)
	}
}

// O limite vale através de um reinício: o Open retoma do próprio fluxo o instante da última linha de cada tipo.
func TestAntiEnchenteAtravessaOReinicio(t *testing.T) {
	dir := t.TempDir()
	l, _ := openAt(t, dir, defaultConfig())
	if err := l.VersionMismatch(boot(time.Minute), []string{"1.0"}, []string{"2.0"}); err != nil {
		t.Fatal(err)
	}
	for _, d := range []time.Duration{10 * time.Second, 70 * time.Second} {
		if err := l.Redelivered(boot(d)); err != nil {
			t.Fatal(err)
		}
	}
	// reinício com o relógio de verificação mal parado (anterior às linhas gravadas): o fluxo manda
	sink := &logSink{}
	l2, err := open(dir, boot(30*time.Second), Options{Logger: sink.logger()}, defaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	if err := l2.VersionMismatch(boot(10*time.Minute), []string{"1.0"}, []string{"2.0"}); err != nil {
		t.Fatal(err)
	}
	if err := l2.Redelivered(boot(129 * time.Second)); err != nil { // 59 s depois da linha de antes do reinício
		t.Fatal(err)
	}
	es := rejectEntries(t, dir)
	if got := ofEvent(es, contract.AuditEventVersionMismatch); len(got) != 1 {
		t.Fatalf("version_mismatch: %d linhas depois do reinício", len(got))
	}
	if got := ofEvent(es, contract.AuditEventRedelivered); len(got) != 1 {
		t.Fatalf("redelivered: %d linhas depois do reinício", len(got))
	}
	if err := l2.Flush(boot(130 * time.Second)); err != nil {
		t.Fatal(err)
	}
	got := ofEvent(rejectEntries(t, dir), contract.AuditEventRedelivered)
	if len(got) != 2 || got[1].Redelivered.Since != utcAt(70*time.Second) || got[1].Redelivered.Count != 1 {
		t.Fatalf("redelivered depois do reinício: %+v", got)
	}
}

// Uma linha de contagem que não se grava não perde a contagem: ela fica pendente e sai, com o mesmo since, na
// próxima linha.
func TestContagemQueNaoSeGravaFicaPendente(t *testing.T) {
	dir := t.TempDir()
	fl := &faults{}
	l, _ := openAt(t, dir, testConfig(fl.ops()))
	if err := l.Unauthenticated(boot(10*time.Second), contract.ReasonBadSignature); err != nil {
		t.Fatal(err)
	}
	fl.failSync = errors.New("EIO simulado")
	if err := l.Unauthenticated(boot(70*time.Second), contract.ReasonBadSignature); !errors.Is(err, fl.failSync) {
		t.Fatalf("esperava o erro da gravação, deu %v", err)
	}
	fl.failSync = nil
	if err := l.Flush(boot(75 * time.Second)); err != nil {
		t.Fatal(err)
	}
	es := rejectEntries(t, dir)
	if len(es) != 1 || es[0].At != utcAt(75*time.Second) ||
		*es[0].Unauthenticated != (contract.AuditUnauthenticated{Since: utcAt(0), BadSignature: 2}) {
		t.Fatalf("linhas %+v", es)
	}
}

func TestUnauthenticatedSoComMotivoDasLinhas0a2(t *testing.T) {
	dir := t.TempDir()
	l, _ := openAt(t, dir, defaultConfig())
	for _, r := range contract.RejectReasons() {
		err := l.Unauthenticated(boot(time.Second), r)
		if (r.Class() == contract.ClassUnauthenticated) != (err == nil) {
			t.Errorf("%s: %v", r, err)
		}
		if err != nil && !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: esperava ErrInvalid, deu %v", r, err)
		}
	}
	if err := l.Flush(boot(time.Hour)); err != nil {
		t.Fatal(err)
	}
	es := rejectEntries(t, dir)
	if len(es) != 1 || *es[0].Unauthenticated != (contract.AuditUnauthenticated{Since: utcAt(0), BadEnvelope: 1, PayloadMismatch: 1, BadSignature: 1}) {
		t.Fatalf("só os três motivos das linhas 0–2 contam: %+v", es)
	}
}

// appendChained appends to the stream file of dir a line made from e, chained right after the file's last line (a
// forged line the chain does not tell apart).
func appendChained(t *testing.T, dir string, spec streamSpec, e *entry) {
	t.Helper()
	path := filepath.Join(dir, spec.file)
	e.Stream, e.Seq, e.PrevSHA256 = spec.name, 1, zeroSHA256
	if lines := fileLines(t, path); len(lines) > 0 {
		var last contract.AuditEntry
		if err := contract.DecodeStrict([]byte(lines[len(lines)-1]), &last); err != nil {
			t.Fatal(err)
		}
		e.Seq, e.PrevSHA256 = last.Seq+1, sha(lines[len(lines)-1])
	}
	b, err := encode(e)
	if err != nil {
		t.Fatal(err)
	}
	appendRaw(t, path, append(b, '\n'))
}

// O boot guarda, das linhas que leu, só o que o anti-enchente usa: os três eventos dele, do fluxo reject. Um
// fluxo adulterado com cem nomes de evento diferentes não faz essa memória crescer.
func TestBootGuardaSoOsTresEventosDoAntiEnchente(t *testing.T) {
	dir := t.TempDir()
	cfg := defaultConfig()
	if err := os.WriteFile(filepath.Join(dir, RejectFileName), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ExecFileName), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for i := range 100 {
		appendChained(t, dir, cfg.reject, &entry{At: testAt, Event: contract.AuditEvent("evento_" + strconv.Itoa(i))})
	}
	appendChained(t, dir, cfg.reject, newUnauthenticated(testAt, contract.AuditUnauthenticated{Since: testAt, BadSignature: 1}))
	appendChained(t, dir, cfg.reject, newRedelivered(testAt, contract.AuditRedelivered{Since: testAt, Count: 1}))
	vm, err := newVersionMismatch(testAt, []string{"1.0"}, []string{"2.0"})
	if err != nil {
		t.Fatal(err)
	}
	appendChained(t, dir, cfg.reject, vm)
	// no exec, os mesmos eventos não são do anti-enchente
	appendChained(t, dir, cfg.exec, &entry{At: testAt, Event: contract.AuditEventVersionMismatch})
	sink := &logSink{}
	for _, c := range []struct {
		spec streamSpec
		want int
	}{{cfg.reject, 3}, {cfg.exec, 0}} {
		s := newStream(dir, c.spec, cfg.ops, sink.logger())
		sc, err := s.recover(testBoot)
		if err != nil {
			t.Fatal(err)
		}
		if len(sc.last) != c.want {
			t.Fatalf("%s: o boot guardou %d eventos, esperava %d", c.spec.name, len(sc.last), c.want)
		}
	}
}

// A sonda da revisão: uma linha do anti-enchente com at no futuro, forjada mas bem encadeada, não silencia o tipo
// dela até essa data. O relógio de verificação nunca volta, então nenhuma linha deste nó passa de boot + 10 min: o
// Open não retoma os limites dela, expõe o fato no Status (indício de adulteração) e loga um WARN.
func TestAtNoFuturoNaoSilenciaOAntiEnchente(t *testing.T) {
	dir := t.TempDir()
	cfg := defaultConfig()
	if err := os.WriteFile(filepath.Join(dir, RejectFileName), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	const future = "2099-01-01T00:00:00Z"
	appendChained(t, dir, cfg.reject, newUnauthenticated(future, contract.AuditUnauthenticated{Since: future, BadSignature: 1}))
	vm, err := newVersionMismatch(future, []string{"1.0"}, []string{"2.0"})
	if err != nil {
		t.Fatal(err)
	}
	appendChained(t, dir, cfg.reject, vm)

	l, sink := openAt(t, dir, cfg)
	rec := l.Status().Reject.Recovery
	want := []FutureLine{
		{Event: contract.AuditEventUnauthenticated, At: at(t, future)},
		{Event: contract.AuditEventVersionMismatch, At: at(t, future)},
	}
	if rec.Breaks != 0 || !slices.Equal(rec.FutureAt, want) {
		t.Fatalf("recovery %+v, esperava FutureAt %v", rec, want)
	}
	if logs := sink.lines(); len(logs) != 1 || !strings.Contains(logs[0], "level=WARN") || !strings.Contains(logs[0], "futuro") {
		t.Fatalf("esperava um WARN sobre o futuro, veio %v", logs)
	}
	for i := range 48 * 60 / 7 { // 48 h, uma rodada a cada 7 min
		now := testBoot.Add(time.Duration(i) * 7 * time.Minute)
		for _, err := range []error{
			l.Unauthenticated(now, contract.ReasonBadSignature),
			l.VersionMismatch(now, []string{"1.0"}, []string{"2.0"}),
			l.Flush(now),
		} {
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	es := rejectEntries(t, dir)
	// tirando as duas forjadas: uma linha de contagem por rodada depois da 1ª, e um version_mismatch a cada 14 min
	if n := len(ofEvent(es, contract.AuditEventUnauthenticated)) - 1; n < 400 {
		t.Fatalf("só %d linhas unauthenticated em 48 h", n)
	}
	if n := len(ofEvent(es, contract.AuditEventVersionMismatch)) - 1; n < 200 {
		t.Fatalf("só %d linhas version_mismatch em 48 h", n)
	}
}

// A fronteira exata do clamp: um at de boot + 10 min ainda conta (os limites são retomados dele, nada no FutureAt);
// boot + 10 min + 1 s já é do futuro, para os três eventos do anti-enchente. Uma janela mais larga ou mais estreita
// que 10 min falha aqui.
func TestFronteiraDoAtNoFuturoEDezMinutos(t *testing.T) {
	kinds := []contract.AuditEvent{contract.AuditEventUnauthenticated, contract.AuditEventRedelivered, contract.AuditEventVersionMismatch}
	write := func(t *testing.T, at string) string {
		t.Helper()
		dir := t.TempDir()
		cfg := defaultConfig()
		if err := os.WriteFile(filepath.Join(dir, RejectFileName), nil, 0o600); err != nil {
			t.Fatal(err)
		}
		appendChained(t, dir, cfg.reject, newUnauthenticated(at, contract.AuditUnauthenticated{Since: at, BadEnvelope: 1}))
		appendChained(t, dir, cfg.reject, newRedelivered(at, contract.AuditRedelivered{Since: at, Count: 1}))
		vm, err := newVersionMismatch(at, []string{"1.0"}, []string{"2.0"})
		if err != nil {
			t.Fatal(err)
		}
		appendChained(t, dir, cfg.reject, vm)
		return dir
	}

	edge := utcAt(VersionMismatchWindow) // boot + 10 min: ainda vale
	l, sink := openAt(t, write(t, edge), defaultConfig())
	if rec := l.Status().Reject.Recovery; len(rec.FutureAt) != 0 || len(sink.lines()) != 0 {
		t.Fatalf("at = boot + 10 min não é do futuro: %+v, logs %v", rec.FutureAt, sink.lines())
	}
	// retomado: um version_mismatch 9 min 59 s depois da linha restaurada não sai
	if err := l.VersionMismatch(boot(VersionMismatchWindow+VersionMismatchWindow-time.Second), []string{"1.0"}, []string{"2.0"}); err != nil {
		t.Fatal(err)
	}
	if n := len(ofEvent(rejectEntries(t, l.reject.dir), contract.AuditEventVersionMismatch)); n != 1 {
		t.Fatalf("o limite não foi retomado da linha de boot + 10 min: %d linhas version_mismatch", n)
	}

	past := utcAt(VersionMismatchWindow + time.Second) // boot + 10 min + 1 s: do futuro
	l, sink = openAt(t, write(t, past), defaultConfig())
	rec := l.Status().Reject.Recovery
	if len(rec.FutureAt) != len(kinds) {
		t.Fatalf("at = boot + 10 min + 1 s devia ser do futuro nos três eventos: %+v", rec.FutureAt)
	}
	for i, f := range rec.FutureAt {
		if f.Event != kinds[i] || !f.At.Equal(at(t, past)) {
			t.Fatalf("FutureAt[%d] = %+v", i, f)
		}
	}
	if logs := sink.lines(); len(logs) != 1 || !strings.Contains(logs[0], "level=WARN") {
		t.Fatalf("esperava um WARN, veio %v", logs)
	}
}

// Um at restaurado até boot + 10 min (relógio que voltou um pouco no reinício) ainda vale: os limites seguem
// atravessando o reinício, e nada vai para o FutureAt.
func TestAtRestauradoDentroDaJanelaAindaVale(t *testing.T) {
	dir := t.TempDir()
	l, _ := openAt(t, dir, defaultConfig())
	if err := l.VersionMismatch(boot(5*time.Minute), []string{"1.0"}, []string{"2.0"}); err != nil {
		t.Fatal(err)
	}
	if err := l.Redelivered(boot(5 * time.Minute)); err != nil { // fecha o período em 5 min
		t.Fatal(err)
	}
	l2, sink := openAt(t, dir, defaultConfig()) // boot 12:00, as linhas são das 12:05
	if rec := l2.Status().Reject.Recovery; len(rec.FutureAt) != 0 || len(sink.lines()) != 0 {
		t.Fatalf("um at dentro da janela não é do futuro: %+v, logs %v", rec, sink.lines())
	}
	if err := l2.VersionMismatch(boot(14*time.Minute+59*time.Second), []string{"1.0"}, []string{"2.0"}); err != nil {
		t.Fatal(err)
	}
	if err := l2.Redelivered(boot(5*time.Minute + 59*time.Second)); err != nil {
		t.Fatal(err)
	}
	es := rejectEntries(t, dir)
	if n := len(ofEvent(es, contract.AuditEventVersionMismatch)); n != 1 {
		t.Fatalf("version_mismatch 9 min 59 s depois da linha restaurada: %d linhas", n)
	}
	if n := len(ofEvent(es, contract.AuditEventRedelivered)); n != 1 {
		t.Fatalf("redelivered 59 s depois da linha restaurada: %d linhas", n)
	}
}

// floodModel tracks what the current Log counted, to check that no count is lost or counted twice.
type floodModel struct {
	unauth    [3]int64 // occurrences given to the current Log, by reason
	redel     int64
	firstLine int // index of the first reject line the current Log may have written
}

// O limite tem de valer sob QUALQUER padrão de chamadas: instantes que andam e voltam, Flush a qualquer hora,
// reinícios com qualquer boot, e a linha de cada tipo sempre a pelo menos 1 min (10 min para version_mismatch)
// da anterior, medida no at gravado. Nenhuma contagem se perde nem conta duas vezes enquanto o Log vive.
func TestAntiEnchenteSobQualquerPadraoDeChamadas(t *testing.T) {
	reasons := []contract.RejectReason{contract.ReasonBadEnvelope, contract.ReasonPayloadMismatch, contract.ReasonBadSignature}
	for seed := uint64(1); seed <= 10; seed++ {
		rng := rand.New(rand.NewPCG(seed, 0xa0d17))
		dir := t.TempDir()
		// o relógio anda aos passos de -20 s a +40 s (muitas chamadas caem perto da borda de 1 min e de 10 min) e, às
		// vezes, salta até 30 min para a frente ou para trás
		now := testBoot
		randTime := func() time.Time {
			if rng.IntN(100) == 0 {
				now = now.Add(time.Duration(rng.IntN(3601)-1800) * time.Second)
			} else {
				now = now.Add(time.Duration(rng.IntN(61)-20) * time.Second)
			}
			return now.Add(time.Duration(rng.IntN(1000)) * time.Millisecond)
		}
		l, err := open(dir, randTime(), Options{}, defaultConfig())
		if err != nil {
			t.Fatal(err)
		}
		var m floodModel
		for range 1500 {
			now := randTime()
			switch op := rng.IntN(100); {
			case op < 35:
				r := rng.IntN(3)
				if err := l.Unauthenticated(now, reasons[r]); err != nil {
					t.Fatalf("seed %d: %v", seed, err)
				}
				m.unauth[r]++
			case op < 60:
				if err := l.Redelivered(now); err != nil {
					t.Fatalf("seed %d: %v", seed, err)
				}
				m.redel++
			case op < 80:
				if err := l.VersionMismatch(now, []string{"1.0"}, []string{"2.0"}); err != nil {
					t.Fatalf("seed %d: %v", seed, err)
				}
			case op < 98:
				if err := l.Flush(now); err != nil {
					t.Fatalf("seed %d: %v", seed, err)
				}
			default: // reinício: o que estava pendente se perde, o que foi gravado fica
				// o boot é qualquer instante que o relógio de verificação permite: ele nunca volta, e o Open só
				// desconfia de linha mais de VersionMismatchWindow à frente do boot (TestAtNoFuturo...)
				es := rejectEntries(t, dir)
				b := randTime()
				for _, e := range es {
					if floor := at(t, e.At).Add(-VersionMismatchWindow); floor.After(b) {
						b = floor
					}
				}
				if l, err = open(dir, b, Options{}, defaultConfig()); err != nil {
					t.Fatal(err)
				}
				if f := l.Status().Reject.Recovery.FutureAt; len(f) != 0 {
					t.Fatalf("seed %d: reinício legítimo com linha no futuro: %v", seed, f)
				}
				m = floodModel{firstLine: len(es)}
			}
		}
		// um Flush bem depois de tudo grava o que restou do Log atual
		if err := l.Flush(testBoot.Add(10 * time.Hour)); err != nil {
			t.Fatal(err)
		}
		es := rejectEntries(t, dir)
		for ev, window := range map[contract.AuditEvent]time.Duration{
			contract.AuditEventUnauthenticated: CountWindow, contract.AuditEventRedelivered: CountWindow,
			contract.AuditEventVersionMismatch: VersionMismatchWindow,
		} {
			lines := ofEvent(es, ev)
			for i := 1; i < len(lines); i++ {
				prev, cur := at(t, lines[i-1].At), at(t, lines[i].At)
				if cur.Sub(prev) < window {
					t.Fatalf("seed %d: duas linhas %s a %v uma da outra (%s, %s)", seed, ev, cur.Sub(prev), lines[i-1].At, lines[i].At)
				}
			}
			for i, e := range lines {
				var since string
				switch ev {
				case contract.AuditEventUnauthenticated:
					since = e.Unauthenticated.Since
				case contract.AuditEventRedelivered:
					since = e.Redelivered.Since
				default:
					continue
				}
				if !at(t, since).Before(at(t, e.At)) {
					t.Fatalf("seed %d: since %s não é anterior ao at %s", seed, since, e.At)
				}
				if i > 0 && at(t, since).Before(at(t, lines[i-1].At)) {
					t.Fatalf("seed %d: o período %s–%s cobre a linha anterior (%s)", seed, since, e.At, lines[i-1].At)
				}
			}
		}
		// conservação no Log que terminou: o que ele contou está nas linhas que ele gravou
		var gotU [3]int64
		var gotR int64
		for _, e := range es[m.firstLine:] {
			switch e.Event {
			case contract.AuditEventUnauthenticated:
				gotU[0] += e.Unauthenticated.BadEnvelope
				gotU[1] += e.Unauthenticated.PayloadMismatch
				gotU[2] += e.Unauthenticated.BadSignature
			case contract.AuditEventRedelivered:
				gotR += e.Redelivered.Count
			}
		}
		if gotU != m.unauth || gotR != m.redel {
			t.Fatalf("seed %d: contou %v/%d, as linhas têm %v/%d", seed, m.unauth, m.redel, gotU, gotR)
		}
	}
}

// Sob chamadas concorrentes de vários goroutines o limite também vale: a decisão e a gravação são uma só, sob a
// trava do fluxo reject.
func TestAntiEnchenteSobConcorrencia(t *testing.T) {
	dir := t.TempDir()
	l, _ := openAt(t, dir, defaultConfig())
	var wg sync.WaitGroup
	for g := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range 200 {
				now := boot(time.Duration(i) * 7 * time.Second)
				_ = l.Unauthenticated(now, contract.ReasonBadSignature)
				_ = l.Redelivered(now)
				_ = l.VersionMismatch(now, []string{"1.0"}, []string{"2." + strconv.Itoa(g%2)})
				_ = l.Flush(now)
			}
		}()
	}
	wg.Wait()
	if err := l.Flush(boot(24 * time.Hour)); err != nil {
		t.Fatal(err)
	}
	es := rejectEntries(t, dir)
	var total int64
	for ev, window := range map[contract.AuditEvent]time.Duration{
		contract.AuditEventUnauthenticated: CountWindow, contract.AuditEventRedelivered: CountWindow,
		contract.AuditEventVersionMismatch: VersionMismatchWindow,
	} {
		lines := ofEvent(es, ev)
		for i := 1; i < len(lines); i++ {
			if d := at(t, lines[i].At).Sub(at(t, lines[i-1].At)); d < window {
				t.Fatalf("%s: duas linhas a %v", ev, d)
			}
		}
		if ev == contract.AuditEventUnauthenticated {
			for _, e := range lines {
				total += e.Unauthenticated.BadSignature
			}
		}
	}
	if total != 8*200 {
		t.Fatalf("as linhas somam %d recusas, foram %d", total, 8*200)
	}
}
