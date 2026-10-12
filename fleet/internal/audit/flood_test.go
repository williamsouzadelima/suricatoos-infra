package audit

import (
	"errors"
	"math/rand/v2"
	"strconv"
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
				if l, err = open(dir, randTime(), Options{}, defaultConfig()); err != nil {
					t.Fatal(err)
				}
				m = floodModel{firstLine: len(rejectEntries(t, dir))}
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
