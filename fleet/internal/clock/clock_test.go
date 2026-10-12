package clock

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/williamsouzadelima/suricatoos-infra/fleet/internal/fsutil"
)

var t0 = time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)

// writes counts the persists of a clock and can make them fail.
type writes struct {
	n    int
	fail error
}

func (w *writes) install(c *Clock) {
	real := c.write
	c.write = func(path string, data []byte) error {
		w.n++
		if w.fail != nil {
			return w.fail
		}
		return real(path, data)
	}
}

func openClock(t *testing.T, dir string) *Clock {
	t.Helper()
	c, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestParseSkew(t *testing.T) {
	ok := map[string]time.Duration{
		"":      DefaultSkew,
		"2m":    2 * time.Minute,
		"90s":   90 * time.Second,
		"1m30s": 90 * time.Second,
		"10m":   10 * time.Minute,
		"600s":  10 * time.Minute,
		"0s":    0,
		"0m":    0,
		"9m59s": 9*time.Minute + 59*time.Second,
		"0h2m":  2 * time.Minute,
	}
	for in, want := range ok {
		got, err := ParseSkew(in)
		if err != nil || got != want {
			t.Errorf("ParseSkew(%q) = %v, %v; esperava %v", in, got, err, want)
		}
	}
	bad := []string{
		"10m1s", "11m", "601s", "1h", // acima do teto: o conector não sobe
		"-1m", "+2m", "2.5m", "1.5s", "2", "0", " 2m", "2m ", "2M", "2 m", "120000ms", "1us", "1ns",
		"1m1m", "30s1m", "01m", "00s", "2m30", "m", "s", "h", "2mm", "１m", "2m\n",
		// números que a multiplicação pela unidade faria transbordar (e voltar negativos ou pequenos)
		"9223372036854775807s", "15372286728m1s", "2562047788015216h", "99999999999999999999s",
	}
	for _, in := range bad {
		if got, err := ParseSkew(in); !errors.Is(err, ErrInvalidSkew) {
			t.Errorf("ParseSkew(%q) = %v, %v; esperava ErrInvalidSkew", in, got, err)
		}
	}
}

// t = max(agora, marca): o relógio de verificação nunca volta, nem dentro do processo.
func TestNowNuncaVolta(t *testing.T) {
	c := openClock(t, t.TempDir())
	if got := c.Now(t0); !got.Equal(t0) {
		t.Fatalf("Now(t0) = %v", got)
	}
	if got := c.Now(t0.Add(-time.Hour)); !got.Equal(t0) {
		t.Fatalf("um relógio que voltou 1 h deu %v, esperava a marca %v", got, t0)
	}
	later := t0.Add(90 * time.Second)
	if got := c.Now(later); !got.Equal(later) {
		t.Fatalf("Now(depois) = %v", got)
	}
	if !c.Mark().Equal(later) {
		t.Fatalf("marca %v", c.Mark())
	}
}

// A leitura monotônica de time.Now() não entra na marca: com as duas leituras, Before/After comparariam só a
// monotônica, e um relógio de parede que voltou dentro do processo faria a marca (de parede) voltar junto.
func TestNowDescartaALeituraMonotonica(t *testing.T) {
	c := openClock(t, t.TempDir())
	got := c.Now(time.Now())
	if !reflect.DeepEqual(got, got.Round(0)) || got.Location() != time.UTC {
		t.Fatalf("Now devolveu um instante com leitura monotônica ou fora de UTC: %#v", got)
	}
	// uma marca de parede no futuro vence um agora monotônico mais novo
	c.Raise(time.Now().Add(time.Hour).Round(0))
	if mark, now := c.Mark(), c.Now(time.Now()); !now.Equal(mark) {
		t.Fatalf("Now = %v, esperava a marca %v", now, mark)
	}
}

// A marca persistida sobrevive ao reinício: um relógio que volta no reboot não reabre janela vencida.
func TestRelogioQueVoltaNoRebootNaoReabreJanela(t *testing.T) {
	dir := t.TempDir()
	c := openClock(t, dir)
	c.Now(t0)
	if err := c.Persist(); err != nil {
		t.Fatal(err)
	}
	c2 := openClock(t, dir)
	if !c2.Found() || c2.Lost() != nil {
		t.Fatalf("found=%v lost=%v", c2.Found(), c2.Lost())
	}
	if got := c2.Now(t0.Add(-24 * time.Hour)); !got.Equal(t0) {
		t.Fatalf("depois do reboot com o relógio 24 h atrás: %v, esperava %v", got, t0)
	}
}

// Raise sobe a marca (o store a sobe até a última decisão gravada) e nunca a desce.
func TestRaiseSoSobe(t *testing.T) {
	c := openClock(t, t.TempDir())
	c.Raise(t0)
	c.Raise(t0.Add(-time.Minute))
	if got := c.Now(t0.Add(-time.Hour)); !got.Equal(t0) {
		t.Fatalf("Now = %v", got)
	}
}

// Persist só grava quando a marca andou; um erro (ErrNotDurable inclusive) não conta como gravado, e a próxima
// chamada tenta de novo a partir da memória.
func TestPersistComErroNaoContaComoGravado(t *testing.T) {
	dir := t.TempDir()
	c := openClock(t, dir)
	w := &writes{fail: fsutil.ErrNotDurable}
	w.install(c)
	c.Now(t0)
	if err := c.Persist(); !errors.Is(err, fsutil.ErrNotDurable) {
		t.Fatalf("esperava ErrNotDurable, deu %v", err)
	}
	w.fail = nil
	if err := c.Persist(); err != nil || w.n != 2 {
		t.Fatalf("a nova tentativa devia gravar: err=%v gravações=%d", err, w.n)
	}
	if err := c.Persist(); err != nil || w.n != 2 {
		t.Fatalf("sem marca nova não regrava: err=%v gravações=%d", err, w.n)
	}
	c.Now(t0.Add(time.Second))
	if err := c.Persist(); err != nil || w.n != 3 {
		t.Fatalf("marca nova grava: err=%v gravações=%d", err, w.n)
	}
}

// Tick (o timer do conector) persiste a marca a cada minuto, não a cada chamada.
func TestTickPersisteACadaMinuto(t *testing.T) {
	c := openClock(t, t.TempDir())
	w := &writes{}
	w.install(c)
	for s := 0; s <= 180; s += 5 {
		if err := c.Tick(t0.Add(time.Duration(s) * time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	// t0 (nada durável ainda), t0+60s, t0+120s, t0+180s
	if w.n != 4 {
		t.Fatalf("%d gravações em 3 min de ticks a cada 5 s, esperava 4", w.n)
	}
	w.fail = errors.New("EIO simulado")
	if err := c.Tick(t0.Add(241 * time.Second)); err == nil {
		t.Fatal("o erro da gravação do Tick tem de chegar ao chamador")
	}
}

// Arquivo ausente: primeiro boot, marca zero. Arquivo ilegível ou corrompido: o boot segue (marca zero) mas Lost
// diz por quê — o store trata a perda da marca como perda de estado (piso de replay).
func TestArquivoAusenteIlegivelOuCorrompido(t *testing.T) {
	c := openClock(t, t.TempDir())
	if c.Found() || c.Lost() != nil || !c.Mark().IsZero() {
		t.Fatalf("ausente: found=%v lost=%v mark=%v", c.Found(), c.Lost(), c.Mark())
	}
	for name, content := range map[string]string{
		"lixo":            "não é json",
		"versão":          `{"version":2,"mark_ns":1}`,
		"membro estranho": `{"version":1,"mark_ns":1,"x":1}`,
		"sem marca":       `{"version":1}`,
		"fração":          `{"version":1,"mark_ns":1.5}`,
		"vazio":           "",
	} {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, FileName), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		c := openClock(t, dir)
		if !c.Found() || c.Lost() == nil || !c.Mark().IsZero() {
			t.Errorf("%s: found=%v lost=%v mark=%v", name, c.Found(), c.Lost(), c.Mark())
		}
	}
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, FileName), 0o700); err != nil {
		t.Fatal(err)
	}
	if c := openClock(t, dir); !c.Found() || c.Lost() == nil {
		t.Fatalf("diretório no lugar: found=%v lost=%v", c.Found(), c.Lost())
	}
}

// O arquivo gravado tem a forma fixa, com o instante exato em nanossegundos Unix.
func TestArquivoGravadoTemAFormaFixa(t *testing.T) {
	dir := t.TempDir()
	c := openClock(t, dir)
	at := t0.Add(123456789 * time.Nanosecond)
	c.Now(at)
	if err := c.Persist(); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, FileName))
	if err != nil {
		t.Fatal(err)
	}
	want := `{"version":1,"mark_ns":` + "1791720000123456789" + "}\n"
	if strings.TrimRight(string(b), "\r\n")+"\n" != want {
		t.Fatalf("arquivo %q, esperava %q", b, want)
	}
	if got := openClock(t, dir).Mark(); !got.Equal(at) {
		t.Fatalf("marca relida %v, esperava %v", got, at)
	}
}

func TestOpenStateDirVazioEErro(t *testing.T) {
	if _, err := Open(""); err == nil {
		t.Fatal("FLEET_STATE_DIR vazio devia ser erro")
	}
}

// A marca lida no Open só conta como durável depois de regravada: depois de uma queda do processo, o clock.json lido
// pode ser um WriteAtomic cujo sync do diretório não terminou. O primeiro Persist a grava de novo (o boot do store faz
// isso), mesmo sem marca nova; depois dele, sem marca nova, nada se regrava.
func TestMarcaLidaSoContaComoDuravelDepoisDeRegravada(t *testing.T) {
	dir := t.TempDir()
	c := openClock(t, dir)
	c.Now(t0)
	if err := c.Persist(); err != nil {
		t.Fatal(err)
	}
	c2 := openClock(t, dir)
	w := &writes{}
	w.install(c2)
	if err := c2.Persist(); err != nil || w.n != 1 {
		t.Fatalf("a marca lida devia ser regravada uma vez: err=%v gravações=%d", err, w.n)
	}
	if err := c2.Persist(); err != nil || w.n != 1 {
		t.Fatalf("depois de confirmada, sem marca nova, nada se regrava: err=%v gravações=%d", err, w.n)
	}
	if got := openClock(t, dir).Mark(); !got.Equal(t0) {
		t.Fatalf("marca %v", got)
	}
}

// Uma queda entre criar o temporário e o rename de um Persist deixa clock.json.tmp-* no FLEET_STATE_DIR. O Open do
// relógio limpa os seus, e só os seus: o diretório é dividido com os outros arquivos de estado, e um arquivo do
// operador que só divide o prefixo não é temporário.
func TestOpenRemoveOsTemporariosOrfaosSoDoProprioArquivo(t *testing.T) {
	setups := map[string]func(t *testing.T, dir string){
		"marca íntegra": func(t *testing.T, dir string) {
			c := openClock(t, dir)
			c.Now(t0)
			if err := c.Persist(); err != nil {
				t.Fatal(err)
			}
		},
		"marca inutilizável": func(t *testing.T, dir string) {
			if err := os.WriteFile(filepath.Join(dir, FileName), []byte("lixo"), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"sem marca": func(*testing.T, string) {},
	}
	for name, prepare := range setups {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			prepare(t, dir)
			for _, f := range []string{"clock.json.tmp-111", "clock.json.tmp-222", "clock.json.tmp-old", "clock.json.bak", "budget.json.tmp-9", "replay.log.tmp-3"} {
				if err := os.WriteFile(filepath.Join(dir, f), []byte("x"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			openClock(t, dir)
			for _, gone := range []string{"clock.json.tmp-111", "clock.json.tmp-222"} {
				if _, err := os.Stat(filepath.Join(dir, gone)); !errors.Is(err, os.ErrNotExist) {
					t.Errorf("%s deveria ter sido removido: %v", gone, err)
				}
			}
			for _, kept := range []string{"clock.json.tmp-old", "clock.json.bak", "budget.json.tmp-9", "replay.log.tmp-3"} {
				if _, err := os.Stat(filepath.Join(dir, kept)); err != nil {
					t.Errorf("%s não é temporário do relógio e tinha de ficar: %v", kept, err)
				}
			}
		})
	}
}
