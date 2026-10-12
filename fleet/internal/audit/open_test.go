package audit

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/williamsouzadelima/suricatoos-infra/fleet/contract"
)

var testBoot = time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)

func testConfig(ops fileOps) config {
	c := defaultConfig()
	c.ops = ops
	return c
}

// openAt opens the audit in dir with the default budgets and a log sink.
func openAt(t *testing.T, dir string, cfg config) (*Log, *logSink) {
	t.Helper()
	sink := &logSink{}
	l, err := open(dir, testBoot, Options{Logger: sink.logger()}, cfg)
	if err != nil {
		t.Fatal(err)
	}
	return l, sink
}

func policyChanged(t *testing.T, l *Log, n int) {
	t.Helper()
	if err := l.PolicyChanged(testBoot.Add(time.Duration(n)*time.Second), "linha "+strconv.Itoa(n)); err != nil {
		t.Fatalf("linha %d: %v", n, err)
	}
}

func execLines(t *testing.T, dir string) []string { return allLines(t, dir, defaultConfig().exec) }

// Cada fluxo tem a sua cadeia e o seu seq: num diretório novo os dois começam em 1 com os 64 zeros, e linhas
// intercaladas não se misturam.
func TestFluxosTemCadaUmASuaCadeia(t *testing.T) {
	dir := t.TempDir()
	l, _ := openAt(t, dir, defaultConfig())
	if st := l.Status(); st.Exec.Seq != 0 || st.Reject.Seq != 0 || st.Exec.HeadSHA256 != "" {
		t.Fatalf("diretório novo: %+v", st)
	}
	c := validCommand()
	for i := range 5 {
		if err := l.ConnectorStarted(testBoot, "connector 1.0.0 (central)"); err != nil {
			t.Fatal(err)
		}
		c.CommandID = "fb698477-2b44-4d52-9204-20ba4ebaaa7" + strconv.Itoa(i)
		if err := l.Deferred(testBoot, c, contract.ReasonNotYetValid, ""); err != nil {
			t.Fatal(err)
		}
	}
	exec := execLines(t, dir)
	reject := allLines(t, dir, defaultConfig().reject)
	if len(exec) != 5 || len(reject) != 5 {
		t.Fatalf("exec %d, reject %d", len(exec), len(reject))
	}
	checkChain(t, contract.StreamExec, exec, 1)
	checkChain(t, contract.StreamReject, reject, 1)
	if st := l.Status(); st.Exec.Seq != 5 || st.Reject.Seq != 5 || st.Exec.HeadSHA256 != sha(exec[4]) || st.Reject.HeadSHA256 != sha(reject[4]) {
		t.Fatalf("status %+v", st)
	}
}

// Um comando aceito deixa, nesta ordem e no fluxo exec, received (com quem emitiu, o hash do payload e a
// evidência), executed (só a referência) e result (o desfecho), com seq consecutivo e encadeado.
func TestOrdemRecebidoExecutadoResultado(t *testing.T) {
	dir := t.TempDir()
	l, _ := openAt(t, dir, defaultConfig())
	c := validCommand()
	c.ObjectIDs = []string{"2d5b8f0e-1c4a-4e6b-9a3d-7f0c5e1b2a49"}
	steps := []func() error{
		func() error { return l.Received(at(t, "2026-10-11T12:02:00Z"), c) },
		func() error { return l.Executed(at(t, "2026-10-11T12:03:00Z"), c.Ref) },
		func() error {
			return l.Result(at(t, "2026-10-11T12:04:00Z"), c.Ref, Outcome{Status: contract.StatusFailed, ErrorCode: contract.ErrorGVM, Detail: "gvmd respondeu 400"})
		},
	}
	for _, step := range steps {
		if err := step(); err != nil {
			t.Fatal(err)
		}
	}
	lines := execLines(t, dir)
	checkChain(t, contract.StreamExec, lines, 1)
	want := []string{
		`{"stream":"exec","seq":1,"at":"2026-10-11T12:02:00Z","event":"received","command_id":"6f1c2a9e-3b7d-4c8a-9e21-5d4f0a7b3c18","type":"task.start","tenant":"acme","issued_by":"op-7f3a","payload_sha256":"202e584626515573d531f5508c9094f8d6b705e0fc0fe6fbf29c76969fef313f","object_ids":["2d5b8f0e-1c4a-4e6b-9a3d-7f0c5e1b2a49"],"prev_sha256":"` + zeroSHA256 + `"}`,
		`{"stream":"exec","seq":2,"at":"2026-10-11T12:03:00Z","event":"executed","command_id":"6f1c2a9e-3b7d-4c8a-9e21-5d4f0a7b3c18","type":"task.start","tenant":"acme","prev_sha256":"`,
		`{"stream":"exec","seq":3,"at":"2026-10-11T12:04:00Z","event":"result","command_id":"6f1c2a9e-3b7d-4c8a-9e21-5d4f0a7b3c18","type":"task.start","tenant":"acme","status":"failed","error_code":"gvm_error","detail":"gvmd respondeu 400","prev_sha256":"`,
	}
	if len(lines) != 3 || lines[0] != want[0] || !strings.HasPrefix(lines[1], want[1]) || !strings.HasPrefix(lines[2], want[2]) {
		t.Fatalf("linhas:\n%s", strings.Join(lines, "\n"))
	}
}

// Linha que não se monta (entrada fora do contrato) não grava nada e não gasta seq.
func TestEntradaInvalidaNaoGastaSeq(t *testing.T) {
	dir := t.TempDir()
	l, _ := openAt(t, dir, defaultConfig())
	c := validCommand()
	c.Tenant = "inválido com espaço"
	if err := l.Received(testBoot, c); !errors.Is(err, ErrInvalid) {
		t.Fatalf("esperava ErrInvalid, deu %v", err)
	}
	if err := l.PolicyChanged(time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC), "x"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("instante fora de 0001–9999: esperava ErrInvalid, deu %v", err)
	}
	if st := l.Status(); st.Exec.Seq != 0 {
		t.Fatalf("seq %d", st.Exec.Seq)
	}
	policyChanged(t, l, 1)
	if lines := execLines(t, dir); len(lines) != 1 || !strings.Contains(lines[0], `"seq":1,`) {
		t.Fatalf("linhas %v", lines)
	}
}

// O boot retoma o seq e o hash da última linha COMPLETA de cada fluxo, atravessando os arquivos girados (logo
// depois de uma rotação a última linha está no ".1").
func TestBootRetomaSeqEHashAtravesDaRotacao(t *testing.T) {
	dir := t.TempDir()
	cfg := defaultConfig()
	cfg.exec.maxBytes, cfg.exec.maxFiles = 700, 3
	l, _ := openAt(t, dir, cfg)
	n := 0
	// até girar duas vezes (.2, .1 e o atual) e o arquivo atual ficar com uma linha só (a 1ª depois da rotação)
	for len(streamFiles(t, dir, ExecFileName)) < 3 || len(fileLines(t, filepath.Join(dir, ExecFileName))) != 1 {
		if n++; n > 100 {
			t.Fatal("não girou")
		}
		policyChanged(t, l, n)
	}
	before := l.Status().Exec
	rotated := fileLines(t, filepath.Join(dir, ExecFileName+".1"))
	// queda logo depois da rotação, antes da 1ª linha do arquivo novo: a última linha completa está no .1
	current := filepath.Join(dir, ExecFileName)
	saved := fileBytes(t, current)
	if err := os.Remove(current); err != nil {
		t.Fatal(err)
	}
	l2, sink := openAt(t, dir, cfg)
	if st := l2.Status().Exec; st.Seq != before.Seq-1 || st.HeadSHA256 != sha(rotated[len(rotated)-1]) || st.Recovery.Breaks != 0 {
		t.Fatalf("sem o atual: seq %d head %s quebras %d (antes seq %d)", st.Seq, st.HeadSHA256, st.Recovery.Breaks, before.Seq)
	}
	if err := os.WriteFile(current, saved, 0o600); err != nil {
		t.Fatal(err)
	}
	l3, _ := openAt(t, dir, cfg)
	if st := l3.Status().Exec; st.Seq != before.Seq || st.HeadSHA256 != before.HeadSHA256 || st.Recovery.Breaks != 0 {
		t.Fatalf("boot: seq %d head %s, antes seq %d head %s", st.Seq, st.HeadSHA256, before.Seq, before.HeadSHA256)
	}
	policyChanged(t, l3, n+1)
	execLinesAll := allLines(t, dir, cfg.exec) // a cadeia continua do mesmo jeito
	if !strings.Contains(execLinesAll[len(execLinesAll)-1], `"prev_sha256":"`+before.HeadSHA256+`"`) {
		t.Fatal("a linha nova não encadeia na última linha de antes do boot")
	}
	if logs := sink.lines(); len(logs) != 0 {
		t.Fatalf("um boot limpo não loga nada: %v", logs)
	}
}

// Linha final parcial (queda no meio da escrita): como cada linha é gravada antes do efeito, o efeito não
// aconteceu. O boot descarta os bytes parciais (corta o arquivo), conta isso no Status e numa linha de log — nunca
// numa linha do fluxo, que o contrato v1 não tem — e a cadeia segue da última linha completa.
func TestBootDescartaLinhaFinalParcial(t *testing.T) {
	dir := t.TempDir()
	l, _ := openAt(t, dir, defaultConfig())
	for i := 1; i <= 3; i++ {
		policyChanged(t, l, i)
	}
	complete := fileBytes(t, filepath.Join(dir, ExecFileName))
	lines := execLines(t, dir)
	partial := []byte(`{"stream":"exec","seq":4,"at":"2026-10-11T12:00:04Z","event":"rece`)
	appendRaw(t, filepath.Join(dir, ExecFileName), partial)

	l2, sink := openAt(t, dir, defaultConfig())
	if got := fileBytes(t, filepath.Join(dir, ExecFileName)); !bytes.Equal(got, complete) {
		t.Fatalf("a parte parcial não saiu do arquivo: %q", got[len(complete):])
	}
	st := l2.Status().Exec
	if st.Recovery.DiscardedBytes != int64(len(partial)) || !st.Recovery.DiscardedAt.Equal(testBoot) {
		t.Fatalf("recovery %+v", st.Recovery)
	}
	if st.Seq != 3 || st.HeadSHA256 != sha(lines[2]) || st.Recovery.Breaks != 0 || st.Poisoned != nil {
		t.Fatalf("status %+v", st)
	}
	logs := sink.lines()
	if len(logs) != 1 || !strings.Contains(logs[0], "level=WARN") || !strings.Contains(logs[0], "parcial") ||
		!strings.Contains(logs[0], "bytes="+strconv.Itoa(len(partial))) {
		t.Fatalf("esperava uma linha de log sobre a parcial, veio %v", logs)
	}
	policyChanged(t, l2, 4)
	got := execLines(t, dir)
	checkChain(t, contract.StreamExec, got, 1) // a linha 4 encadeia na 3; nenhuma linha fala da recuperação
	if len(got) != 4 || !strings.Contains(got[3], "linha 4") {
		t.Fatalf("linhas %v", got)
	}
	if rs := l2.Status().Reject.Recovery; rs.DiscardedBytes != 0 {
		t.Fatalf("o reject não tinha parcial: %+v", rs)
	}
}

func appendRaw(t *testing.T, path string, b []byte) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.Write(b); err != nil {
		t.Fatal(err)
	}
}

// Um fluxo só com a parte de uma linha (a queda foi na primeira escrita) recomeça do zero.
func TestBootComSoUmaLinhaParcialRecomecaDoZero(t *testing.T) {
	dir := t.TempDir()
	appendRaw(t, filepath.Join(dir, RejectFileName), []byte(`{"stream":"reject","seq":1,`))
	l, _ := openAt(t, dir, defaultConfig())
	if st := l.Status().Reject; st.Seq != 0 || st.Recovery.DiscardedBytes != int64(len(`{"stream":"reject","seq":1,`)) {
		t.Fatalf("status %+v", st)
	}
	if err := l.Rejected(testBoot, validCommand(), contract.ReasonReplay, ""); err != nil {
		t.Fatal(err)
	}
	if lines := allLines(t, dir, defaultConfig().reject); len(lines) != 1 || !strings.Contains(lines[0], `"seq":1,`) {
		t.Fatalf("linhas %v", lines)
	}
}

// Se a parte parcial não sai (o corte falha), o fluxo fica envenenado — nunca se grava depois de lixo — até um
// Open que consiga; o outro fluxo segue.
func TestBootQueNaoConsegueDescartarEnvenena(t *testing.T) {
	dir := t.TempDir()
	l, _ := openAt(t, dir, defaultConfig())
	policyChanged(t, l, 1)
	appendRaw(t, filepath.Join(dir, ExecFileName), []byte(`{"stream":"ex`))
	fl := &faults{failTruncate: errors.New("EROFS simulado")}
	l2, sink := openAt(t, dir, testConfig(fl.ops()))
	st := l2.Status()
	if st.Exec.Poisoned == nil || st.Exec.Recovery.DiscardedBytes != 0 {
		t.Fatalf("exec %+v", st.Exec)
	}
	if err := l2.PolicyChanged(testBoot, "x"); !errors.Is(err, ErrPoisoned) {
		t.Fatalf("esperava ErrPoisoned, deu %v", err)
	}
	if err := l2.Rejected(testBoot, validCommand(), contract.ReasonReplay, ""); err != nil {
		t.Fatalf("o reject não pode pagar pelo exec: %v", err)
	}
	if logs := sink.lines(); len(logs) != 1 || !strings.Contains(logs[0], "level=ERROR") {
		t.Fatalf("logs %v", logs)
	}
	l3, _ := openAt(t, dir, defaultConfig())
	if st := l3.Status().Exec; st.Poisoned != nil || st.Seq != 1 || st.Recovery.DiscardedBytes != int64(len(`{"stream":"ex`)) {
		t.Fatalf("o Open seguinte devia recuperar: %+v", st)
	}
}

// rewriteLine replaces line i (from 0) of the file with text.
func rewriteLine(t *testing.T, path string, i int, text string) {
	t.Helper()
	lines := fileLines(t, path)
	lines[i] = text
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

// Cadeia QUEBRADA no meio (adulteração): o boot não conserta nada — o arquivo fica como está —, segue da ÚLTIMA
// linha e expõe a quebra (Status e uma linha de log). Cada tipo de quebra aparece onde ela está.
func TestBootComCadeiaQuebradaNaoConsertaESegueDaUltimaLinha(t *testing.T) {
	cases := []struct {
		name   string
		tamper func(t *testing.T, path string, lines []string)
		line   int // linha (de 1) da primeira quebra
		seq    int64
		reason string
	}{
		{"linha alterada", func(t *testing.T, path string, lines []string) {
			rewriteLine(t, path, 2, strings.Replace(lines[2], "linha 3", "linha X", 1))
		}, 4, 4, "prev_sha256"},
		{"linha apagada", func(t *testing.T, path string, lines []string) {
			kept := append(append([]string{}, lines[:2]...), lines[3:]...)
			if err := os.WriteFile(path, []byte(strings.Join(kept, "\n")+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}, 3, 4, "seq"},
		{"lixo no lugar de uma linha", func(t *testing.T, path string, lines []string) {
			rewriteLine(t, path, 1, "isto não é JSON")
		}, 2, 2, "não é uma linha"},
		{"linha do outro fluxo", func(t *testing.T, path string, lines []string) {
			rewriteLine(t, path, 1, strings.Replace(lines[1], `"stream":"exec"`, `"stream":"reject"`, 1))
		}, 2, 2, "outro fluxo"},
		{"primeira linha sem zeros", func(t *testing.T, path string, lines []string) {
			rewriteLine(t, path, 0, strings.Replace(lines[0], zeroSHA256, sha("x"), 1))
		}, 1, 1, "zeros"},
		{"linha acima de 8 KiB", func(t *testing.T, path string, lines []string) {
			rewriteLine(t, path, 1, strings.Repeat("x", MaxLineBytes+1))
		}, 2, 2, "8 KiB"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			l, _ := openAt(t, dir, defaultConfig())
			for i := 1; i <= 5; i++ {
				policyChanged(t, l, i)
			}
			path := filepath.Join(dir, ExecFileName)
			c.tamper(t, path, fileLines(t, path))
			tampered := fileBytes(t, path)
			last := fileLines(t, path)

			l2, sink := openAt(t, dir, defaultConfig())
			st := l2.Status().Exec
			if st.Recovery.Breaks < 1 || st.Recovery.FirstBreak == nil {
				t.Fatalf("a quebra não foi exposta: %+v", st.Recovery)
			}
			fb := st.Recovery.FirstBreak
			if fb.File != ExecFileName || fb.Line != c.line || fb.Seq != c.seq || !strings.Contains(fb.Reason, c.reason) {
				t.Fatalf("primeira quebra %+v, esperava linha %d seq %d motivo com %q", *fb, c.line, c.seq, c.reason)
			}
			if !bytes.Equal(fileBytes(t, path), tampered) {
				t.Fatal("o boot mexeu no arquivo adulterado")
			}
			if st.HeadSHA256 != sha(last[len(last)-1]) {
				t.Fatal("o boot não segue da última linha")
			}
			if logs := sink.lines(); len(logs) != 1 || !strings.Contains(logs[0], "level=WARN") || !strings.Contains(logs[0], "quebrada") {
				t.Fatalf("logs %v", logs)
			}
			policyChanged(t, l2, 6)
			got := fileLines(t, path)
			newest := got[len(got)-1]
			if !strings.Contains(newest, `"prev_sha256":"`+sha(last[len(last)-1])+`"`) || !strings.Contains(newest, `"seq":`+strconv.Itoa(int(st.Seq+1))+`,`) {
				t.Fatalf("a linha nova não segue da última: %s (seq esperado %d)", newest, st.Seq+1)
			}
		})
	}
}

// Uma linha parcial num arquivo girado não é queda no meio da escrita (o girado nunca mais recebe linha): é
// adulteração ou corrupção, então é quebra — exposta, não cortada.
func TestBootLinhaParcialEmArquivoGiradoEQuebra(t *testing.T) {
	dir := t.TempDir()
	cfg := defaultConfig()
	cfg.exec.maxBytes = 700
	l, _ := openAt(t, dir, cfg)
	for i := 1; len(streamFiles(t, dir, ExecFileName)) < 2; i++ {
		if i > 100 {
			t.Fatal("não girou")
		}
		policyChanged(t, l, i)
	}
	rotated := filepath.Join(dir, ExecFileName+".1")
	appendRaw(t, rotated, []byte(`{"stream":"exec","se`))
	before := fileBytes(t, rotated)
	l2, _ := openAt(t, dir, cfg)
	st := l2.Status().Exec
	if st.Recovery.DiscardedBytes != 0 || st.Recovery.Breaks != 1 || st.Recovery.FirstBreak.File != ExecFileName+".1" {
		t.Fatalf("recovery %+v / %+v", st.Recovery, st.Recovery.FirstBreak)
	}
	if !bytes.Equal(fileBytes(t, rotated), before) {
		t.Fatal("o boot cortou um arquivo girado")
	}
}

// Arquivo que não se consegue ler no boot (aqui, um diretório no lugar do arquivo atual) é erro do Open: sem a
// última linha não há como continuar a cadeia.
func TestBootComArquivoIlegivelFalha(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, RejectFileName), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := open(dir, testBoot, Options{}, defaultConfig()); err == nil {
		t.Fatal("esperava erro do Open")
	}
}

func TestOpenRecusaEntradaInvalida(t *testing.T) {
	if _, err := Open("", testBoot, Options{}); err == nil {
		t.Error("FLEET_STATE_DIR vazio")
	}
	for _, boot := range []time.Time{{}, time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)} {
		if _, err := Open(t.TempDir(), boot, Options{}); err == nil {
			t.Errorf("boot %v devia ser recusado", boot)
		}
	}
	l, err := Open(t.TempDir(), testBoot, Options{}) // sem logger: nada quebra
	if err != nil {
		t.Fatal(err)
	}
	if err := l.ConnectorStarted(testBoot, "connector 1.0.0 (central)"); err != nil {
		t.Fatal(err)
	}
}

// O seq no teto (só por adulteração) é retomado do arquivo e recusa a próxima linha.
func TestBootComSeqNoTetoRecusa(t *testing.T) {
	dir := t.TempDir()
	e := newLifecycle(testAt, contract.AuditEventPolicyChanged, "x")
	e.Seq, e.PrevSHA256 = maxSeq, sha("anterior girada")
	b, err := encode(e)
	if err != nil {
		t.Fatal(err)
	}
	appendRaw(t, filepath.Join(dir, ExecFileName), append(b, '\n'))
	l, _ := openAt(t, dir, defaultConfig())
	if st := l.Status().Exec; st.Seq != maxSeq || st.Recovery.Breaks != 0 {
		t.Fatalf("status %+v", st)
	}
	if err := l.PolicyChanged(testBoot, "y"); !errors.Is(err, ErrSeqExhausted) {
		t.Fatalf("esperava ErrSeqExhausted, deu %v", err)
	}
}

// Nenhum método público recebe outra coisa além do instante, de textos curtos e dos tipos fechados de entrada:
// não há por onde um segredo (ou um payload, ou uma saída) entrar.
func TestMetodosSoRecebemTiposFechados(t *testing.T) {
	allowed := map[reflect.Type]bool{
		reflect.TypeOf(time.Time{}): true, reflect.TypeOf(""): true, reflect.TypeOf([]string(nil)): true,
		reflect.TypeOf(Ref{}): true, reflect.TypeOf(Command{}): true, reflect.TypeOf(Outcome{}): true,
		reflect.TypeOf(contract.RejectReason("")): true,
	}
	logType := reflect.TypeOf(&Log{})
	if logType.NumMethod() == 0 {
		t.Fatal("o Log não tem métodos públicos?")
	}
	for i := 0; i < logType.NumMethod(); i++ {
		m := logType.Method(i)
		for j := 1; j < m.Type.NumIn(); j++ { // 0 é o receptor
			if in := m.Type.In(j); !allowed[in] {
				t.Errorf("(*Log).%s recebe %s", m.Name, in)
			}
		}
	}
}
