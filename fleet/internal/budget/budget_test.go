package budget

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/williamsouzadelima/suricatoos-infra/fleet/contract"
)

var t0 = time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)

// wide are limits that never bite.
var wide = Limits{Total: MaxTotal, Sensitive: MaxSensitive}

// openAt opens a ledger in a fresh state dir and returns it with the dir.
func openAt(t *testing.T, boot time.Time) (*Ledger, string) {
	t.Helper()
	dir := t.TempDir()
	l, err := Open(dir, boot, Options{FirstBoot: true})
	if err != nil {
		t.Fatal(err)
	}
	return l, dir
}

func stateFile(dir string) string { return filepath.Join(dir, FileName) }

// seedDir creates a state dir whose budget.json holds content.
func seedDir(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(stateFile(dir), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

// Dois tipos do catálogo: um comum, que só conta no orçamento global, e um sensível (opt-in), que conta nos dois.
const (
	plain = contract.TypeTaskStart
	sens  = contract.TypeTaskCreate
)

// kind picks one of them.
func kind(sensitive bool) contract.CommandType {
	if sensitive {
		return sens
	}
	return plain
}

func consume(t *testing.T, l *Ledger, at time.Time, typ contract.CommandType, lim Limits) {
	t.Helper()
	if err := l.Consume(at, typ, lim); err != nil {
		t.Fatalf("Consume(%v, %s): %v", at, typ, err)
	}
}

// fits asks and reports whether the command fits in every budget it counts in.
func fits(t *testing.T, l *Ledger, at time.Time, typ contract.CommandType, lim Limits) bool {
	t.Helper()
	room, err := l.Fits(at, typ, lim)
	if err != nil {
		t.Fatalf("Fits(%v, %s): %v", at, typ, err)
	}
	return room.OK()
}

// stateJSON renders a budget.json the way the ledger writes it.
func stateJSON(total, sensitive []int64) string {
	list := func(v []int64) string {
		parts := make([]string, len(v))
		for i, n := range v {
			parts[i] = fmt.Sprint(n)
		}
		return "[" + strings.Join(parts, ",") + "]"
	}
	return fmt.Sprintf(`{"version":1,"total_ns":%s,"sensitive_ns":%s}`, list(total), list(sensitive))
}

func nsRun(from int64, n int) []int64 {
	out := make([]int64, n)
	for i := range out {
		out[i] = from + int64(i)
	}
	return out
}

func TestJanelaDeslizanteBordasExatas(t *testing.T) {
	q := t0.Add(5 * time.Hour) // o instante t da pergunta
	cases := []struct {
		name  string
		ts    time.Time
		count int
	}{
		{"1 ns antes de t-1h", q.Add(-time.Hour - 1), 0},
		{"exatamente t-1h não conta", q.Add(-time.Hour), 0},
		{"t-1h+1ns conta", q.Add(-time.Hour + 1), 1},
		{"1 ns antes de t conta", q.Add(-1), 1},
		{"exatamente t conta", q, 1},
		// com o relógio de verificação (que não volta) não existe instante depois de t; se existir, conta
		{"depois de t também conta (janela sem borda superior)", q.Add(1), 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			l, _ := openAt(t, t0)
			consume(t, l, c.ts, sens, wide)
			u := l.usageAt(q)
			if u.Total != c.count || u.Sensitive != c.count {
				t.Fatalf("usageAt(t) = %+v, esperava %d nos dois", u, c.count)
			}
			// a pergunta enxerga a mesma janela: com limite 1, cabe mais um só se o instante não conta
			lim := Limits{Total: 1, Sensitive: 1}
			if fits := fits(t, l, q, sens, lim); fits != (c.count == 0) {
				t.Fatalf("Fits(t) com limite 1 = %v, esperava %v", fits, c.count == 0)
			}
		})
	}
}

func TestSensivelContaNosDoisOrcamentos(t *testing.T) {
	l, _ := openAt(t, t0)
	consume(t, l, t0, sens, wide)
	if u := l.usageAt(t0); u != (usage{Total: 1, Sensitive: 1}) {
		t.Fatalf("depois de um sensível: %+v", u)
	}
	consume(t, l, t0.Add(time.Second), plain, wide)
	if u := l.usageAt(t0.Add(time.Second)); u != (usage{Total: 2, Sensitive: 1}) {
		t.Fatalf("depois de um não sensível: o sensível não cresce: %+v", u)
	}
}

// A sensibilidade de um comando vem do catálogo, dentro do ledger: quem pergunta (o portão) e quem consome (a
// gravação do aceite) não a informam, então não têm como discordar.
func TestSensibilidadeVemDoCatalogo(t *testing.T) {
	for _, e := range contract.Catalog() {
		t.Run(string(e.Type), func(t *testing.T) {
			l, _ := openAt(t, t0)
			lim := Limits{Total: 100, Sensitive: 1}
			consume(t, l, t0, e.Type, lim)

			want := usage{Total: 1}
			if e.Sensitive {
				want.Sensitive = 1
			}
			if got := l.usageAt(t0); got != want {
				t.Fatalf("depois de consumir %s (sensível=%v): %+v, esperava %+v", e.Type, e.Sensitive, got, want)
			}
			// com o orçamento de sensíveis em 1/1 só se o tipo consumido era sensível, outro sensível já não cabe
			if got := fits(t, l, t0, sens, lim); got != !e.Sensitive {
				t.Errorf("outro sensível cabe = %v, esperava %v", got, !e.Sensitive)
			}
			if !fits(t, l, t0, plain, lim) {
				t.Error("um comum sempre cabe: o global tem folga")
			}
		})
	}
}

// Um tipo fora do catálogo não tem sensibilidade para o ledger derivar: é erro, não "comum".
func TestTipoForaDoCatalogoEErroENadaMuda(t *testing.T) {
	l, dir := openAt(t, t0)
	before := readState(t, dir)
	for _, typ := range []contract.CommandType{"task.explode", "", "TASK.START", "tenant.scope_set"} {
		room, err := l.Fits(t0, typ, wide)
		if !errors.Is(err, contract.ErrUnknownType) || room != (Room{}) {
			t.Errorf("Fits(%q) = %+v, %v; esperava Room vazio e contract.ErrUnknownType", typ, room, err)
		}
		err = l.Consume(t0, typ, wide)
		if !errors.Is(err, contract.ErrUnknownType) || errors.Is(err, ErrOverBudget) {
			t.Errorf("Consume(%q): %v; esperava contract.ErrUnknownType (e não ErrOverBudget)", typ, err)
		}
		if err != nil && typ != "" && strings.Contains(err.Error(), string(typ)) {
			t.Errorf("o erro ecoa o tipo, que é entrada crua: %v", err)
		}
	}
	if after := readState(t, dir); after != before {
		t.Fatalf("um tipo desconhecido não grava: o arquivo mudou de\n%s\npara\n%s", before, after)
	}
	if u := l.usageAt(t0); u != (usage{}) {
		t.Fatalf("nada foi consumido: %+v", u)
	}
}

// Room diz qual orçamento não tem folga (o detail do portão depende disso).
func TestFitsDizQualOrcamentoNaoTemFolga(t *testing.T) {
	l, _ := openAt(t, t0)
	consume(t, l, t0, sens, wide) // 1 aceito, 1 sensível
	cases := []struct {
		name string
		lim  Limits
		typ  contract.CommandType
		want Room
	}{
		{"tudo com folga, comum", Limits{Total: 10, Sensitive: 10}, plain, Room{Total: true, Sensitive: true}},
		{"tudo com folga, sensível", Limits{Total: 10, Sensitive: 10}, sens, Room{Total: true, Sensitive: true}},
		{"global cheio, comum", Limits{Total: 1, Sensitive: 10}, plain, Room{Total: false, Sensitive: true}},
		{"global cheio, sensível", Limits{Total: 1, Sensitive: 10}, sens, Room{Total: false, Sensitive: true}},
		{"sensíveis cheio, comum: não conta nele", Limits{Total: 10, Sensitive: 1}, plain, Room{Total: true, Sensitive: true}},
		{"sensíveis cheio, sensível", Limits{Total: 10, Sensitive: 1}, sens, Room{Total: true, Sensitive: false}},
		{"os dois cheios, sensível", Limits{Total: 1, Sensitive: 1}, sens, Room{Total: false, Sensitive: false}},
		{"limite 0 nos dois, sensível", Limits{}, sens, Room{Total: false, Sensitive: false}},
		{"limite 0 no total, comum", Limits{Total: 0, Sensitive: 10}, plain, Room{Total: false, Sensitive: true}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := l.Fits(t0.Add(time.Second), c.typ, c.lim)
			if err != nil || got != c.want {
				t.Fatalf("Fits = %+v, %v; esperava %+v", got, err, c.want)
			}
			if got.OK() != (c.want.Total && c.want.Sensitive) {
				t.Fatalf("OK() = %v", got.OK())
			}
		})
	}
}

func TestFitsSoPerguntaENadaGrava(t *testing.T) {
	l, dir := openAt(t, t0)
	before := readState(t, dir)
	for i := 0; i < 5; i++ {
		if !fits(t, l, t0, sens, wide) {
			t.Fatal("deveria caber")
		}
	}
	if u := l.usageAt(t0); u != (usage{}) {
		t.Fatalf("perguntar não consome: %+v", u)
	}
	if after := readState(t, dir); after != before {
		t.Fatalf("perguntar não grava: o arquivo mudou de\n%s\npara\n%s", before, after)
	}
}

func TestLimiteZeroNaoAceitaNadaDaquelaClasse(t *testing.T) {
	l, dir := openAt(t, t0)
	before := readState(t, dir)

	noTotal := Limits{Total: 0, Sensitive: 30}
	if fits(t, l, t0, plain, noTotal) || fits(t, l, t0, sens, noTotal) {
		t.Fatal("total 0: nenhum comando aceito, sensível ou não")
	}
	noSensitive := Limits{Total: 100, Sensitive: 0}
	if fits(t, l, t0, sens, noSensitive) {
		t.Fatal("sensível 0: nenhum sensível")
	}
	if !fits(t, l, t0, plain, noSensitive) {
		t.Fatal("sensível 0 não toca os não sensíveis")
	}
	if err := l.Consume(t0, sens, noSensitive); !errors.Is(err, ErrOverBudget) {
		t.Fatalf("Consume de sensível com limite 0: %v", err)
	}
	if err := l.Consume(t0, plain, noTotal); !errors.Is(err, ErrOverBudget) {
		t.Fatalf("Consume com total 0: %v", err)
	}
	if after := readState(t, dir); after != before {
		t.Fatalf("o que não coube não pode ser gravado: o arquivo mudou de\n%s\npara\n%s", before, after)
	}
	consume(t, l, t0, plain, noSensitive) // o não sensível passa
}

func TestLimiteNegativoNaoAceitaNada(t *testing.T) {
	l, _ := openAt(t, t0)
	if fits(t, l, t0, plain, Limits{Total: -1, Sensitive: 30}) {
		t.Fatal("limite negativo é inválido: fail-closed")
	}
}

func TestOrcamentoEsgotaEVoltaQuandoAJanelaAnda(t *testing.T) {
	l, _ := openAt(t, t0)
	lim := Limits{Total: 3, Sensitive: 3}
	consume(t, l, t0, plain, lim)
	consume(t, l, t0.Add(time.Minute), plain, lim)
	consume(t, l, t0.Add(2*time.Minute), plain, lim)
	if fits(t, l, t0.Add(2*time.Minute), plain, lim) {
		t.Fatal("três de três: não cabe o quarto")
	}
	if err := l.Consume(t0.Add(3*time.Minute), plain, lim); !errors.Is(err, ErrOverBudget) {
		t.Fatalf("o quarto: %v", err)
	}
	if fits(t, l, t0.Add(time.Hour-1), plain, lim) {
		t.Fatal("1 ns antes de o primeiro sair da janela ainda são três")
	}
	if !fits(t, l, t0.Add(time.Hour), plain, lim) {
		t.Fatal("em t0+1h o primeiro instante (t0) sai da janela: cabe de novo")
	}
	consume(t, l, t0.Add(time.Hour), plain, lim)
	if fits(t, l, t0.Add(time.Hour), plain, lim) {
		t.Fatal("de novo três na janela")
	}
}

func TestInstantesIguaisContamCadaUm(t *testing.T) {
	l, _ := openAt(t, t0)
	lim := Limits{Total: 2, Sensitive: 2}
	consume(t, l, t0, plain, lim)
	consume(t, l, t0, plain, lim) // dois aceites no mesmo instante (relógio de baixa resolução)
	if u := l.usageAt(t0); u.Total != 2 {
		t.Fatalf("Usage = %+v", u)
	}
	if fits(t, l, t0, plain, lim) {
		t.Fatal("dois instantes iguais são dois consumos")
	}
}

func TestLimiteReduzidoValeJaSobreOQueEstaNaJanela(t *testing.T) {
	l, _ := openAt(t, t0)
	for i := 0; i < 5; i++ {
		consume(t, l, t0.Add(time.Duration(i)*time.Second), kind(i < 3), wide) // 5 aceitos, 3 sensíveis
	}
	at := t0.Add(10 * time.Second)
	for _, c := range []struct {
		lim  Limits
		typ  contract.CommandType
		fits bool
	}{
		{Limits{Total: 6, Sensitive: 100}, plain, true},
		{Limits{Total: 5, Sensitive: 100}, plain, false}, // já são cinco
		{Limits{Total: 2, Sensitive: 100}, plain, false}, // reduzido abaixo do que já está na janela
		{Limits{Total: 100, Sensitive: 4}, sens, true},
		{Limits{Total: 100, Sensitive: 3}, sens, false},
		{Limits{Total: 100, Sensitive: 1}, sens, false},
		{Limits{Total: 100, Sensitive: 1}, plain, true}, // o sensível reduzido não toca os demais
	} {
		if got := fits(t, l, at, c.typ, c.lim); got != c.fits {
			t.Errorf("Fits(%s, %+v) = %v, esperava %v", c.typ, c.lim, got, c.fits)
		}
	}
}

func TestOsDoisOrcamentosSeCruzam(t *testing.T) {
	// sensível esgotado, global com folga: o sensível é recusado e o não sensível passa
	l, _ := openAt(t, t0)
	lim := Limits{Total: 10, Sensitive: 2}
	consume(t, l, t0, sens, lim)
	consume(t, l, t0.Add(time.Second), sens, lim)
	at := t0.Add(2 * time.Second)
	if fits(t, l, at, sens, lim) || !fits(t, l, at, plain, lim) {
		t.Fatal("sensível esgotado só recusa sensível")
	}
	// global esgotado, sensível com folga: o global recusa também o sensível
	g, _ := openAt(t, t0)
	lim = Limits{Total: 2, Sensitive: 10}
	consume(t, g, t0, plain, lim)
	consume(t, g, t0.Add(time.Second), plain, lim)
	if fits(t, g, at, sens, lim) || fits(t, g, at, plain, lim) {
		t.Fatal("global esgotado recusa tudo, inclusive o sensível com folga própria")
	}
}

func TestPersistenciaIdaEVolta(t *testing.T) {
	l, dir := openAt(t, t0)
	consume(t, l, t0, sens, wide)
	consume(t, l, t0.Add(time.Minute), plain, wide)
	consume(t, l, t0.Add(2*time.Minute), sens, wide)
	at := t0.Add(3 * time.Minute)
	want := l.usageAt(at)
	if want != (usage{Total: 3, Sensitive: 2}) {
		t.Fatalf("Usage antes de reabrir: %+v", want)
	}

	re, err := Open(dir, at, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if re.Lost() != nil {
		t.Fatalf("estado válido não pode ser dado por perdido: %v", re.Lost())
	}
	if got := re.usageAt(at); got != want {
		t.Fatalf("depois de reabrir: %+v, esperava %+v", got, want)
	}
	// o que foi restaurado vale: limite 3 já está cheio
	if fits(t, re, at, plain, Limits{Total: 3, Sensitive: 30}) {
		t.Fatal("o estado restaurado deveria contar na janela")
	}
	// e a janela segue deslizando sobre o restaurado
	if !fits(t, re, t0.Add(time.Hour), plain, Limits{Total: 3, Sensitive: 30}) {
		t.Fatal("em t0+1h o instante t0 sai da janela, mesmo depois do reinício")
	}
}

func TestArquivoGravadoTemFormatoEModo(t *testing.T) {
	l, dir := openAt(t, t0)
	path := stateFile(dir)
	consume(t, l, t0, sens, wide)
	consume(t, l, t0.Add(time.Second), plain, wide)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Version     int     `json:"version"`
		TotalNS     []int64 `json:"total_ns"`
		SensitiveNS []int64 `json:"sensitive_ns"`
	}
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("budget.json não é JSON: %v\n%s", err, b)
	}
	if got.Version != 1 || len(got.TotalNS) != 2 || len(got.SensitiveNS) != 1 ||
		got.TotalNS[0] != t0.UnixNano() || got.TotalNS[1] != t0.Add(time.Second).UnixNano() || got.SensitiveNS[0] != t0.UnixNano() {
		t.Fatalf("conteúdo inesperado: %s", b)
	}
	if runtime.GOOS != "windows" {
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Fatalf("modo %v, esperava 0600", fi.Mode().Perm())
		}
	}
}

func TestArquivoSoGuardaOQueEstaNaJanela(t *testing.T) {
	l, dir := openAt(t, t0)
	path := stateFile(dir)
	consume(t, l, t0, sens, wide)
	consume(t, l, t0.Add(2*time.Hour), plain, wide) // o primeiro já saiu da janela
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if want := stateJSON([]int64{t0.Add(2 * time.Hour).UnixNano()}, nil); strings.TrimSpace(string(b)) != want {
		t.Fatalf("o arquivo não pode crescer sem fim:\n got %s\nwant %s", b, want)
	}
}

// readState returns the text of budget.json and checks that nothing else (a temporary file, say) sits next to it.
func readState(t *testing.T, dir string) string {
	t.Helper()
	b, err := os.ReadFile(stateFile(dir))
	if err != nil {
		t.Fatalf("budget.json deveria existir: %v", err)
	}
	if entries, err := os.ReadDir(dir); err != nil || len(entries) != 1 {
		t.Fatalf("o diretório deveria ter só o budget.json: %v %v", entries, err)
	}
	return string(b)
}

// Primeiro boot de verdade (o nó ainda não tem identidade): não há o que perder, o orçamento começa vazio. Mas
// Open grava o estado inicial já, porque só assim a ausência do arquivo, num boot seguinte, significa perda — um
// nó parado, sem nenhum aceite, não teria arquivo nenhum e todo reinício seria lido como perda.
func TestPrimeiroBootComecaVazioEGravaOEstadoInicial(t *testing.T) {
	dir := t.TempDir()
	l, err := Open(dir, t0, Options{FirstBoot: true})
	if err != nil {
		t.Fatal(err)
	}
	if l.Lost() != nil || !l.BlockedUntil().IsZero() {
		t.Fatalf("primeiro boot não é perda: %v %v", l.Lost(), l.BlockedUntil())
	}
	if u := l.usageAt(t0); u != (usage{}) || !fits(t, l, t0, sens, Limits{Total: 1, Sensitive: 1}) {
		t.Fatalf("deveria começar vazio: %+v", u)
	}
	if got, want := readState(t, dir), stateJSON(nil, nil)+"\n"; got != want {
		t.Fatalf("estado inicial:\n got %s\nwant %s", got, want)
	}

	// o nó se inscreve (ganha identidade) e reinicia sem nunca ter aceito um comando: o arquivo está lá, nada se perdeu
	re, err := Open(dir, t0.Add(time.Minute), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if re.Lost() != nil || !re.BlockedUntil().IsZero() {
		t.Fatalf("reinício de um nó parado não é perda: %v", re.Lost())
	}
}

// O sinal do chamador (a identidade do nó existe) transforma a ausência do arquivo em perda: apagar o
// budget.json, ou voltar o volume, não pode zerar o orçamento no reinício. O valor zero de Options é o seguro.
func TestAusenteNumNoQueJaTemIdentidadeContaComoPerda(t *testing.T) {
	dir := t.TempDir() // sem budget.json
	boot := t0.Add(7 * time.Minute)
	l, err := Open(dir, boot, Options{}) // FirstBoot falso: o nó já tem identidade
	if err != nil {
		t.Fatalf("perda não é erro de Open: %v", err)
	}
	assertBlockedUntilBootPlusHour(t, l, boot)
	if !strings.Contains(l.Lost().Error(), "identidade") {
		t.Fatalf("a causa deveria dizer que o nó já tem identidade: %v", l.Lost())
	}
	// Open não inventa o arquivo: se a ausência valesse como "criado agora", o reinício seguinte abriria a porta
	if _, err := os.Stat(stateFile(dir)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Open não pode criar o arquivo de um nó que perdeu o estado: %v", err)
	}

	// passada a hora, volta a aceitar, e a primeira gravação cria o arquivo: dali em diante o reinício lê o estado
	after := boot.Add(Window)
	consume(t, l, after, plain, wide)
	re, err := Open(dir, after, Options{})
	if err != nil || re.Lost() != nil {
		t.Fatalf("depois de uma gravação o arquivo existe e está íntegro: %v %v", err, re.Lost())
	}
	if u := re.usageAt(after); u != (usage{Total: 1}) {
		t.Fatalf("usageAt = %+v", u)
	}
}

// FirstBoot só vale para "arquivo ausente": não desculpa um arquivo que existe e não presta.
func TestPrimeiroBootNaoDesculpaArquivoCorrompido(t *testing.T) {
	boot := t0.Add(3 * time.Minute)
	l, err := Open(seedDir(t, "lixo"), boot, Options{FirstBoot: true})
	if err != nil {
		t.Fatal(err)
	}
	assertBlockedUntilBootPlusHour(t, l, boot)
}

func TestPrimeiroBootComArquivoValidoLeOArquivo(t *testing.T) {
	run := []int64{t0.UnixNano() - int64(time.Minute)}
	l, err := Open(seedDir(t, stateJSON(run, run)), t0, Options{FirstBoot: true})
	if err != nil || l.Lost() != nil {
		t.Fatalf("%v %v", err, l.Lost())
	}
	if u := l.usageAt(t0); u != (usage{Total: 1, Sensitive: 1}) {
		t.Fatalf("o estado do arquivo deveria valer: %+v", u)
	}
}

// Primeiro boot que não consegue gravar o estado inicial: o conector não teria como guardar orçamento nenhum.
func TestPrimeiroBootSemComoGravarEErro(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nao-existe")
	if _, err := Open(dir, t0, Options{FirstBoot: true}); err == nil {
		t.Fatal("primeiro boot sem diretório gravável tinha de ser erro")
	}
	// já a perda (sem FirstBoot) não escreve nada, então não depende do diretório
	l, err := Open(dir, t0, Options{})
	if err != nil {
		t.Fatal(err)
	}
	assertBlockedUntilBootPlusHour(t, l, t0)
}

// Uma queda entre criar o temporário e o rename deixa budget.json.tmp-* no FLEET_STATE_DIR. O Open do ledger
// limpa os seus, e só os seus: o diretório é dividido com os outros arquivos de estado.
func TestOpenRemoveOsTemporariosOrfaosSoDoProprioArquivo(t *testing.T) {
	setups := map[string]struct {
		prepare func(t *testing.T) string
		opts    Options
	}{
		"estado íntegro":    {func(t *testing.T) string { return seedDir(t, stateJSON(nil, nil)) }, Options{}},
		"estado corrompido": {func(t *testing.T) string { return seedDir(t, "lixo") }, Options{}},
		"primeiro boot":     {func(t *testing.T) string { return t.TempDir() }, Options{FirstBoot: true}},
		"estado perdido":    {func(t *testing.T) string { return t.TempDir() }, Options{}},
	}
	for name, setup := range setups {
		t.Run(name, func(t *testing.T) {
			dir := setup.prepare(t)
			for _, f := range []string{"budget.json.tmp-111", "budget.json.tmp-222", "politica.json.tmp-9", "store.db.tmp-3", "budget.json.bak"} {
				if err := os.WriteFile(filepath.Join(dir, f), []byte("x"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := Open(dir, t0, setup.opts); err != nil {
				t.Fatal(err)
			}
			for _, gone := range []string{"budget.json.tmp-111", "budget.json.tmp-222"} {
				if _, err := os.Stat(filepath.Join(dir, gone)); !errors.Is(err, os.ErrNotExist) {
					t.Errorf("%s deveria ter sido removido: %v", gone, err)
				}
			}
			for _, kept := range []string{"politica.json.tmp-9", "store.db.tmp-3", "budget.json.bak"} {
				if _, err := os.Stat(filepath.Join(dir, kept)); err != nil {
					t.Errorf("%s não é do ledger e tinha de ficar: %v", kept, err)
				}
			}
		})
	}
}

func TestOpenStateDirVazioEErro(t *testing.T) {
	// "" viraria ./budget.json: o diretório de trabalho nunca guarda o orçamento
	if _, err := Open("", t0, Options{FirstBoot: true}); err == nil {
		t.Fatal("FLEET_STATE_DIR vazio deveria ser erro")
	}
}

// A sonda da revisão: budget.json corrompido e boot zero. O boot+1h estoura o int64 de nanossegundos, o fim do
// bloqueio cai em 1754 e o orçamento "perdido" voltava vazio, isto é, abria a porta. O valor zero é o mais comum
// em Go (um campo que ninguém preencheu); Open recusa, simétrico ao stateDir vazio.
func TestOpenRecusaBootQueNaoERelogioDeVerificacao(t *testing.T) {
	cases := map[string]time.Time{
		"valor zero":                        {},
		"antes do que cabe em int64 de ns":  time.Date(1600, 1, 1, 0, 0, 0, 0, time.UTC),
		"depois do que cabe em int64 de ns": time.Date(3000, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	for name, boot := range cases {
		t.Run(name, func(t *testing.T) {
			dir := seedDir(t, "lixo") // estado corrompido: o caso em que o bloqueio é o que protege
			l, err := Open(dir, boot, Options{})
			if err == nil {
				t.Fatalf("Open aceitou boot %v; Lost=%v BlockedUntil=%v e Fits(2026-10-11)=%v (Fits=true é porta aberta)",
					boot, l.Lost() != nil, l.BlockedUntil(), fits(t, l, t0, plain, wide))
			}
			if l != nil {
				t.Fatalf("com erro, nenhum ledger: veio %+v", l)
			}
			// sem arquivo nenhum também: o boot é inválido, não importa o que haja no disco
			if _, err := Open(t.TempDir(), boot, Options{FirstBoot: true}); err == nil {
				t.Fatal("boot inválido sem arquivo também tinha de ser erro")
			}
		})
	}
	// o que um relógio de verificação de verdade produz continua valendo, inclusive com o relógio monotônico
	if _, err := Open(t.TempDir(), time.Now(), Options{FirstBoot: true}); err != nil {
		t.Fatalf("time.Now() deveria ser aceito: %v", err)
	}
	if _, err := Open(t.TempDir(), t0, Options{FirstBoot: true}); err != nil {
		t.Fatalf("%v", err)
	}
}

// Ruling: state that cannot be used at boot counts as a FULL window from boot for one hour; losing the budget
// must never open the door.
func TestEstadoIlegivelOuCorrompidoTrataJanelaComoCheiaPorUmaHora(t *testing.T) {
	bigTotal := nsRun(t0.UnixNano()-int64(time.Minute), MaxTotal+1)
	bigSensitive := nsRun(t0.UnixNano()-int64(time.Minute), MaxSensitive+1)
	cases := []struct{ name, content string }{
		{"lixo", "isto não é json"},
		{"vazio", ""},
		{"objeto vazio", "{}"},
		{"versão desconhecida", `{"version":2,"total_ns":[],"sensitive_ns":[]}`},
		{"sem versão", `{"total_ns":[],"sensitive_ns":[]}`},
		{"lista nula", `{"version":1,"total_ns":null,"sensitive_ns":[]}`},
		{"falta uma lista", `{"version":1,"total_ns":[]}`},
		{"membro a mais", `{"version":1,"total_ns":[],"sensitive_ns":[],"x":1}`},
		{"chave duplicada", `{"version":1,"total_ns":[],"total_ns":[],"sensitive_ns":[]}`},
		{"instante em texto", `{"version":1,"total_ns":["2026-10-11T12:00:00Z"],"sensitive_ns":[]}`},
		{"instante com fração", `{"version":1,"total_ns":[1.5],"sensitive_ns":[]}`},
		{"instante com expoente", `{"version":1,"total_ns":[1e18],"sensitive_ns":[]}`},
		{"instante fora de int64", `{"version":1,"total_ns":[99999999999999999999],"sensitive_ns":[]}`},
		{"dado depois do valor", stateJSON(nil, nil) + " {}"},
		{"truncado", stateJSON([]int64{1, 2, 3}, nil)[:30]},
		{"total acima do teto de memória", stateJSON(bigTotal, nil)},
		{"sensível acima do teto de memória", stateJSON(nil, bigSensitive)},
	}
	boot := t0.Add(7 * time.Minute)
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := seedDir(t, c.content)
			path := stateFile(dir)
			l, err := Open(dir, boot, Options{})
			if err != nil {
				t.Fatalf("estado perdido não é erro de Open: %v", err)
			}
			assertBlockedUntilBootPlusHour(t, l, boot)

			// o arquivo ruim fica onde está: sumir com ele abriria a porta no boot seguinte
			if got, err := os.ReadFile(path); err != nil || string(got) != c.content {
				t.Fatalf("Open não pode mexer no arquivo ilegível: %v", err)
			}

			// passada a hora, volta a aceitar e a primeira gravação cura o arquivo
			after := boot.Add(Window)
			consume(t, l, after, plain, wide)
			re, err := Open(dir, after, Options{})
			if err != nil || re.Lost() != nil {
				t.Fatalf("depois de uma gravação o arquivo deveria estar íntegro: %v %v", err, re.Lost())
			}
			if u := re.usageAt(after); u != (usage{Total: 1}) {
				t.Fatalf("Usage depois de curar: %+v", u)
			}
		})
	}
}

func TestEstadoIlegivelPorSerDiretorio(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(stateFile(dir), 0o700); err != nil {
		t.Fatal(err)
	}
	boot := t0
	l, err := Open(dir, boot, Options{})
	if err != nil {
		t.Fatal(err)
	}
	assertBlockedUntilBootPlusHour(t, l, boot)
}

func TestEstadoGrandeDemaisContaComoPerdido(t *testing.T) {
	dir := seedDir(t, stateJSON(nil, nil)+strings.Repeat(" ", maxFileBytes))
	l, err := Open(dir, t0, Options{})
	if err != nil {
		t.Fatal(err)
	}
	assertBlockedUntilBootPlusHour(t, l, t0)
}

func assertBlockedUntilBootPlusHour(t *testing.T, l *Ledger, boot time.Time) {
	t.Helper()
	if l.Lost() == nil {
		t.Fatal("Lost() deveria informar a causa")
	}
	if !l.BlockedUntil().Equal(boot.Add(Window)) {
		t.Fatalf("BlockedUntil = %v, esperava boot+1h = %v", l.BlockedUntil(), boot.Add(Window))
	}
	lim := Limits{Total: MaxTotal, Sensitive: MaxSensitive}
	for _, at := range []time.Time{boot, boot.Add(time.Minute), boot.Add(Window - 1)} {
		if fits(t, l, at, plain, lim) || fits(t, l, at, sens, lim) {
			t.Fatalf("janela cheia por 1 h a partir do boot: Fits(%v) deveria ser falso", at)
		}
		if err := l.Consume(at, plain, lim); !errors.Is(err, ErrOverBudget) {
			t.Fatalf("Consume(%v) durante o bloqueio: %v", at, err)
		}
	}
	if !fits(t, l, boot.Add(Window), plain, lim) || !fits(t, l, boot.Add(Window), sens, lim) {
		t.Fatal("em boot+1h o bloqueio acaba")
	}
	if u := l.usageAt(boot); u != (usage{}) {
		t.Fatalf("estado perdido não deixa instantes para trás: %+v", u)
	}
}

func TestFalhaDeGravacaoEErroENadaFicaContado(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "estado")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	l, err := Open(dir, t0, Options{FirstBoot: true})
	if err != nil {
		t.Fatal(err)
	}
	consume(t, l, t0, sens, wide)
	before := l.usageAt(t0)

	if err := os.RemoveAll(dir); err != nil { // o disco some debaixo do conector
		t.Fatal(err)
	}
	err = l.Consume(t0.Add(time.Second), sens, wide)
	if err == nil {
		t.Fatal("falha ao gravar o consumo tem de ser erro")
	}
	if errors.Is(err, ErrOverBudget) {
		t.Fatalf("falha de gravação não é estouro de orçamento (o chamador mapeia para unavailable): %v", err)
	}
	if got := l.usageAt(t0.Add(time.Second)); got != before {
		t.Fatalf("o consumo que não foi gravado não pode contar: %+v, antes %+v", got, before)
	}

	// o disco volta: a próxima gravação funciona e só o que foi gravado aparece
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	consume(t, l, t0.Add(2*time.Second), plain, wide)
	re, err := Open(dir, t0.Add(3*time.Second), Options{})
	if err != nil || re.Lost() != nil {
		t.Fatalf("%v %v", err, re.Lost())
	}
	// a gravação nova leva o estado da memória (t0, sensível, e t0+2s) e nunca o consumo que falhou (t0+1s)
	if u := re.usageAt(t0.Add(3 * time.Second)); u != (usage{Total: 2, Sensitive: 1}) {
		t.Fatalf("Usage depois de reabrir: %+v", u)
	}
}

func TestUsoConcorrenteNuncaPassaDoLimite(t *testing.T) {
	l, _ := openAt(t, t0)
	lim := Limits{Total: 8, Sensitive: 5}
	const workers = 24

	var wg sync.WaitGroup
	var mu sync.Mutex
	accepted, refused := 0, 0
	start := make(chan struct{})
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			typ := kind(i%2 == 0)
			err := l.Consume(t0.Add(time.Duration(i)*time.Millisecond), typ, lim)
			// leituras concorrentes com as gravações
			_, _ = l.Fits(t0, typ, lim)
			l.usageAt(t0.Add(time.Second))
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				accepted++
			case errors.Is(err, ErrOverBudget):
				refused++
			default:
				t.Errorf("erro inesperado: %v", err)
			}
		}(i)
	}
	close(start)
	wg.Wait()

	u := l.usageAt(t0.Add(time.Second))
	if u.Total > lim.Total || u.Sensitive > lim.Sensitive {
		t.Fatalf("passou do limite: %+v com %+v", u, lim)
	}
	if accepted != u.Total || accepted+refused != workers {
		t.Fatalf("aceitos %d, recusados %d, Usage %+v", accepted, refused, u)
	}
	if accepted != lim.Total {
		// 12 pedidos sensíveis e 12 não sensíveis disputam 8 vagas globais e 5 sensíveis; as 8 vagas se enchem
		t.Fatalf("aceitos %d, esperava as %d vagas globais cheias", accepted, lim.Total)
	}
}

func TestTetoDeMemoriaNaoDependeDoLimitePedido(t *testing.T) {
	at := t0.Add(time.Hour)
	huge := Limits{Total: 1 << 30, Sensitive: 1 << 30}

	// MaxTotal instantes na janela (a lista está no teto): nem com um limite absurdo entra mais um
	dir := seedDir(t, stateJSON(nsRun(at.UnixNano()-int64(time.Minute), MaxTotal), nil))
	l, err := Open(dir, at, Options{})
	if err != nil || l.Lost() != nil {
		t.Fatalf("%v %v", err, l.Lost())
	}
	if u := l.usageAt(at); u.Total != MaxTotal {
		t.Fatalf("Usage = %+v", u)
	}
	if fits(t, l, at, plain, huge) {
		t.Fatal("Fits tem de limitar o pedido ao teto do schema")
	}
	if err := l.Consume(at, plain, huge); !errors.Is(err, ErrOverBudget) {
		t.Fatalf("Consume no teto: %v", err)
	}

	// MaxSensitive sensíveis: nenhum sensível a mais, mas o não sensível ainda cabe no global
	run := nsRun(at.UnixNano()-int64(time.Minute), MaxSensitive)
	l2, err := Open(seedDir(t, stateJSON(run, run)), at, Options{})
	if err != nil || l2.Lost() != nil {
		t.Fatalf("%v %v", err, l2.Lost())
	}
	if err := l2.Consume(at, sens, huge); !errors.Is(err, ErrOverBudget) {
		t.Fatalf("sensível no teto: %v", err)
	}
	consume(t, l2, at, plain, huge)
}

// O relógio de verificação nunca anda para trás. Se um chamador (ou um estado gravado sob um relógio adiantado)
// trouxer um t anterior a instantes já gravados, esses instantes contam: relógio que voltou não reabre o orçamento.
func TestRelogioQueVoltouNaoReabreOOrcamento(t *testing.T) {
	l, _ := openAt(t, t0)
	lim := Limits{Total: 3, Sensitive: 3}
	later := t0.Add(10 * time.Minute)
	for i := 0; i < 3; i++ {
		consume(t, l, later.Add(time.Duration(i)*time.Second), plain, lim)
	}
	if fits(t, l, t0, plain, lim) {
		t.Fatal("t anterior aos instantes gravados: eles ainda contam, o orçamento segue cheio")
	}
	if err := l.Consume(t0, plain, lim); !errors.Is(err, ErrOverBudget) {
		t.Fatalf("Consume com t que voltou: %v", err)
	}
	if u := l.usageAt(t0); u.Total != 3 {
		t.Fatalf("usageAt(t anterior) = %+v", u)
	}
}

func TestInstantesForaDeOrdemSaoGuardadosTodos(t *testing.T) {
	l, _ := openAt(t, t0)
	later := t0.Add(10 * time.Minute)
	consume(t, l, later, plain, wide)
	consume(t, l, t0, plain, wide)
	if u := l.usageAt(later); u.Total != 2 {
		t.Fatalf("usageAt(later) = %+v", u)
	}
}
