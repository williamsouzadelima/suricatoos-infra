package audit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/williamsouzadelima/suricatoos-infra/fleet/contract"
	"github.com/williamsouzadelima/suricatoos-infra/fleet/internal/fsutil"
)

// logSink collects what the audit logs, for the tests that count log lines.
type logSink struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *logSink) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *logSink) lines() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	s := strings.TrimSpace(l.buf.String())
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

func (l *logSink) logger() *slog.Logger { return slog.New(slog.NewTextHandler(l, nil)) }

var execSpec = streamSpec{name: contract.StreamExec, file: ExecFileName, maxBytes: MaxFileBytes, maxFiles: ExecFiles}

// newTestStream is a stream on a fresh directory, as Open leaves it when there is nothing to recover.
func newTestStream(t *testing.T, spec streamSpec, ops fileOps) (*stream, *logSink) {
	t.Helper()
	sink := &logSink{}
	return newStream(t.TempDir(), spec, ops, sink.logger()), sink
}

// appendLine appends one exec lifecycle line whose detail says its number.
func appendLine(t *testing.T, s *stream, n int) error {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.appendLocked(newLifecycle(testAt, contract.AuditEventPolicyChanged, "linha "+strconv.Itoa(n)))
}

func mustAppend(t *testing.T, s *stream, n int) {
	t.Helper()
	if err := appendLine(t, s, n); err != nil {
		t.Fatalf("linha %d: %v", n, err)
	}
}

// streamFiles lists the files of a stream from the oldest to the newest: the rotated ones from the highest
// number down, then the current one.
func streamFiles(t *testing.T, dir, file string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var rotated []int
	current := false
	for _, e := range entries {
		switch suffix, ok := strings.CutPrefix(e.Name(), file+"."); {
		case e.Name() == file:
			current = true
		case ok:
			n, err := strconv.Atoi(suffix)
			if err != nil {
				t.Fatalf("arquivo estranho no diretório: %s", e.Name())
			}
			rotated = append(rotated, n)
		}
	}
	slices.Sort(rotated)
	slices.Reverse(rotated)
	var out []string
	for _, n := range rotated {
		out = append(out, file+"."+strconv.Itoa(n))
	}
	if current {
		out = append(out, file)
	}
	return out
}

// fileLines returns the lines of one file (each must end in '\n').
func fileLines(t *testing.T, path string) []string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) == 0 {
		return nil
	}
	if b[len(b)-1] != '\n' {
		t.Fatalf("%s termina sem '\\n'", filepath.Base(path))
	}
	return strings.Split(string(b[:len(b)-1]), "\n")
}

func sha(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// checkChain checks that lines are one unbroken stretch of the stream: each a contract audit_entry of the stream,
// seq +1 per line from firstSeq, prev_sha256 the sha256 of the line before (64 zeros before seq 1).
func checkChain(t *testing.T, name contract.AuditStream, lines []string, firstSeq int64) {
	t.Helper()
	for i, line := range lines {
		var e contract.AuditEntry
		if err := contract.DecodeStrict([]byte(line), &e); err != nil {
			t.Fatalf("linha %d não é audit_entry: %v", i, err)
		}
		if e.Stream != name || e.Seq != firstSeq+int64(i) {
			t.Fatalf("linha %d: fluxo %s seq %d, esperava %s seq %d", i, e.Stream, e.Seq, name, firstSeq+int64(i))
		}
		switch {
		case i > 0 && e.PrevSHA256 != sha(lines[i-1]):
			t.Fatalf("linha %d (seq %d): prev_sha256 não é o sha256 da linha anterior", i, e.Seq)
		case e.Seq == 1 && e.PrevSHA256 != zeroSHA256:
			t.Fatalf("seq 1 sem os 64 zeros")
		}
	}
}

// allLines reads every file of a stream, from the oldest, and checks the chain across them.
func allLines(t *testing.T, dir string, spec streamSpec) []string {
	t.Helper()
	var lines []string
	for _, f := range streamFiles(t, dir, spec.file) {
		lines = append(lines, fileLines(t, filepath.Join(dir, f))...)
	}
	if len(lines) > 0 {
		var first contract.AuditEntry
		if err := contract.DecodeStrict([]byte(lines[0]), &first); err != nil {
			t.Fatal(err)
		}
		checkChain(t, spec.name, lines, first.Seq)
	}
	return lines
}

func TestPrimeiraLinhaUsaOs64Zeros(t *testing.T) {
	s, _ := newTestStream(t, execSpec, defaultOps())
	mustAppend(t, s, 1)
	lines := allLines(t, s.dir, execSpec)
	if len(lines) != 1 || !strings.Contains(lines[0], `"seq":1,`) || !strings.Contains(lines[0], `"prev_sha256":"`+zeroSHA256+`"`) {
		t.Fatalf("primeira linha: %v", lines)
	}
}

// seq +1 por linha e prev_sha256 = sha256 dos bytes exatos da linha anterior, sem o '\n'; o estado em memória
// (seq, hash da última linha, tamanho do arquivo) acompanha o disco.
func TestCadeiaESeq(t *testing.T) {
	s, _ := newTestStream(t, execSpec, defaultOps())
	for i := 1; i <= 50; i++ {
		mustAppend(t, s, i)
	}
	lines := allLines(t, s.dir, execSpec)
	if len(lines) != 50 {
		t.Fatalf("%d linhas", len(lines))
	}
	checkChain(t, contract.StreamExec, lines, 1)
	fi, err := os.Stat(s.path(0))
	if err != nil {
		t.Fatal(err)
	}
	if s.seq != 50 || s.head != sha(lines[49]) || s.size != fi.Size() {
		t.Fatalf("memória: seq %d head %s size %d (arquivo %d)", s.seq, s.head, s.size, fi.Size())
	}
}

// A rotação acontece antes da linha que passaria do teto do arquivo; a cadeia e o seq atravessam os arquivos; o
// arquivo mais velho sai; nunca há mais arquivos que o orçamento, nem arquivo acima do teto; ".1" é o mais novo.
func TestRotacaoMantemACadeiaEOOrcamento(t *testing.T) {
	spec := streamSpec{name: contract.StreamExec, file: ExecFileName, maxBytes: 1024, maxFiles: 4}
	s, _ := newTestStream(t, spec, defaultOps())
	const n = 120
	for i := 1; i <= n; i++ {
		mustAppend(t, s, i)
	}
	files := streamFiles(t, s.dir, spec.file)
	if want := []string{spec.file + ".3", spec.file + ".2", spec.file + ".1", spec.file}; !slices.Equal(files, want) {
		t.Fatalf("arquivos %v, esperava %v", files, want)
	}
	for _, f := range files {
		if fi, _ := os.Stat(filepath.Join(s.dir, f)); fi.Size() > spec.maxBytes {
			t.Errorf("%s com %d bytes, teto %d", f, fi.Size(), spec.maxBytes)
		}
	}
	lines := allLines(t, s.dir, spec) // confere a cadeia através dos quatro arquivos
	var last contract.AuditEntry
	if err := contract.DecodeStrict([]byte(lines[len(lines)-1]), &last); err != nil || last.Seq != n {
		t.Fatalf("última linha: seq %d, %v", last.Seq, err)
	}
	var first contract.AuditEntry
	if err := contract.DecodeStrict([]byte(lines[0]), &first); err != nil || first.Seq <= 1 {
		t.Fatalf("o arquivo mais velho deveria ter saído (primeira linha retida: seq %d)", first.Seq)
	}
}

// Os orçamentos são de cada fluxo: girar um nunca mexe nos arquivos do outro.
func TestOrcamentosSeparados(t *testing.T) {
	dir := t.TempDir()
	small := func(name contract.AuditStream, file string, files int) streamSpec {
		return streamSpec{name: name, file: file, maxBytes: 600, maxFiles: files}
	}
	sink := &logSink{}
	execS := newStream(dir, small(contract.StreamExec, ExecFileName, 3), defaultOps(), sink.logger())
	rejectS := newStream(dir, small(contract.StreamReject, RejectFileName, 2), defaultOps(), sink.logger())
	mustAppend(t, execS, 1)
	before, err := os.ReadFile(execS.path(0))
	if err != nil {
		t.Fatal(err)
	}
	for i := range 60 {
		rejectS.mu.Lock()
		err := rejectS.appendLocked(newUnauthenticated(testAt, contract.AuditUnauthenticated{Since: testAt, BadSignature: int64(i + 1)}))
		rejectS.mu.Unlock()
		if err != nil {
			t.Fatal(err)
		}
	}
	if got := streamFiles(t, dir, RejectFileName); len(got) != 2 {
		t.Fatalf("reject: %v", got)
	}
	if got := streamFiles(t, dir, ExecFileName); len(got) != 1 {
		t.Fatalf("a enchente do reject girou o exec: %v", got)
	}
	after, err := os.ReadFile(execS.path(0))
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("a enchente do reject mudou o arquivo do exec")
	}
}

// faultyFile wraps the real file of an append to make its write or its fsync fail, and records the calls.
type faultyFile struct {
	*os.File
	failWrite, failSync error
	calls               *[]string
}

func (f *faultyFile) Write(p []byte) (int, error) {
	*f.calls = append(*f.calls, "write")
	if f.failWrite != nil {
		n, _ := f.File.Write(p[:len(p)/2]) // metade da linha chega ao arquivo
		return n, f.failWrite
	}
	return f.File.Write(p)
}

func (f *faultyFile) Sync() error {
	*f.calls = append(*f.calls, "sync")
	if f.failSync != nil {
		return f.failSync
	}
	return f.File.Sync()
}

func (f *faultyFile) Close() error {
	*f.calls = append(*f.calls, "close")
	return f.File.Close()
}

// faults makes the next appends fail as configured, and records every call to the file.
type faults struct {
	failWrite, failSync, failTruncate, failSyncDir, failRename error
	renameCalls                                                int
	failRenameAt                                               int // 0 = every rename fails while failRename is set
	calls                                                      []string
}

func (fl *faults) ops() fileOps {
	o := defaultOps()
	real := o
	o.openAppend = func(path string) (appendFile, error) {
		f, err := fsutil.OpenAppend(path)
		if err != nil {
			return nil, err
		}
		fl.calls = append(fl.calls, "open")
		return &faultyFile{File: f, failWrite: fl.failWrite, failSync: fl.failSync, calls: &fl.calls}, nil
	}
	o.truncate = func(path string, size int64) error {
		fl.calls = append(fl.calls, "truncate")
		if fl.failTruncate != nil {
			return fl.failTruncate
		}
		return real.truncate(path, size)
	}
	o.syncDir = func(dir string) error {
		fl.calls = append(fl.calls, "syncdir")
		if fl.failSyncDir != nil {
			return fl.failSyncDir
		}
		return real.syncDir(dir)
	}
	o.rename = func(oldpath, newpath string) error {
		fl.renameCalls++
		if fl.failRename != nil && (fl.failRenameAt == 0 || fl.renameCalls == fl.failRenameAt) {
			return fl.failRename
		}
		return real.rename(oldpath, newpath)
	}
	return o
}

func fileBytes(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Uma escrita que falha no meio não conta: a API devolve erro, o arquivo volta ao tamanho de antes (a meia linha
// sai), seq e hash em memória não andam, e a próxima linha sai com o mesmo seq, encadeada na última confirmada.
func TestFalhaNaEscritaNaoContaEOArquivoVolta(t *testing.T) {
	fl := &faults{}
	s, _ := newTestStream(t, execSpec, fl.ops())
	mustAppend(t, s, 1)
	before := fileBytes(t, s.path(0))
	fl.failWrite = errors.New("ENOSPC simulado")
	if err := appendLine(t, s, 2); err == nil || !errors.Is(err, fl.failWrite) {
		t.Fatalf("esperava o erro da escrita, deu %v", err)
	}
	if got := fileBytes(t, s.path(0)); !bytes.Equal(got, before) {
		t.Fatalf("o arquivo não voltou ao que era:\n%q", got)
	}
	if s.seq != 1 || s.poisoned != nil {
		t.Fatalf("seq %d, envenenado %v", s.seq, s.poisoned)
	}
	fl.failWrite = nil
	mustAppend(t, s, 3)
	lines := allLines(t, s.dir, execSpec)
	if len(lines) != 2 || !strings.Contains(lines[1], `"seq":2,`) || !strings.Contains(lines[1], "linha 3") {
		t.Fatalf("linhas %v", lines)
	}
}

// O fsync é parte da gravação: se ele falha, a linha não conta (o arquivo volta e a API devolve erro), e a API só
// devolve nil depois de o fsync da linha ter devolvido nil.
func TestFsyncAntesDoRetorno(t *testing.T) {
	fl := &faults{}
	s, _ := newTestStream(t, execSpec, fl.ops())
	mustAppend(t, s, 1)
	if i, j := slices.Index(fl.calls, "write"), slices.Index(fl.calls, "sync"); i < 0 || j < i || fl.calls[len(fl.calls)-1] != "close" {
		t.Fatalf("ordem das chamadas: %v (esperava write, sync, close)", fl.calls)
	}
	before := fileBytes(t, s.path(0))
	fl.failSync = errors.New("EIO simulado")
	if err := appendLine(t, s, 2); !errors.Is(err, fl.failSync) {
		t.Fatalf("esperava o erro do fsync, deu %v", err)
	}
	if got := fileBytes(t, s.path(0)); !bytes.Equal(got, before) || s.seq != 1 {
		t.Fatalf("depois do fsync que falhou: seq %d, arquivo %q", s.seq, got)
	}
	fl.failSync = nil
	mustAppend(t, s, 3)
	if lines := allLines(t, s.dir, execSpec); len(lines) != 2 {
		t.Fatalf("linhas %v", lines)
	}
}

// Se o próprio desfazer (o corte de volta) falha, o estado do arquivo é incerto: o fluxo se envenena e TODA
// linha seguinte é recusada até um novo Open (a recuperação do boot), para nunca acrescentar linha depois de lixo
// nem deixar o chamador seguir para o efeito. O outro fluxo não é afetado. Um aviso vai para o log, uma vez.
func TestCorteQueFalhaEnvenenaOFluxo(t *testing.T) {
	fl := &faults{}
	s, sink := newTestStream(t, execSpec, fl.ops())
	mustAppend(t, s, 1)
	fl.failWrite, fl.failTruncate = errors.New("EIO simulado"), errors.New("EIO no corte")
	err := appendLine(t, s, 2)
	if !errors.Is(err, ErrPoisoned) || !errors.Is(err, fl.failTruncate) {
		t.Fatalf("esperava ErrPoisoned com a causa, deu %v", err)
	}
	poisoned := fileBytes(t, s.path(0))
	fl.failWrite, fl.failTruncate = nil, nil
	for i := 3; i <= 5; i++ {
		if err := appendLine(t, s, i); !errors.Is(err, ErrPoisoned) {
			t.Fatalf("linha %d depois do veneno: esperava ErrPoisoned, deu %v", i, err)
		}
	}
	if got := fileBytes(t, s.path(0)); !bytes.Equal(got, poisoned) {
		t.Fatal("um fluxo envenenado não pode tocar no arquivo")
	}
	if s.seq != 1 {
		t.Fatalf("seq %d", s.seq)
	}
	// nem um arquivo que alguém deixou de novo do tamanho esperado tira o veneno: só um novo Open
	if err := os.Truncate(s.path(0), s.size); err != nil {
		t.Fatal(err)
	}
	if err := appendLine(t, s, 6); !errors.Is(err, ErrPoisoned) {
		t.Fatalf("o veneno vale até o próximo Open, deu %v", err)
	}
	if logs := sink.lines(); len(logs) != 1 || !strings.Contains(logs[0], "level=ERROR") {
		t.Fatalf("esperava uma linha de log de erro, veio %v", logs)
	}
	// o outro fluxo, no mesmo diretório, segue gravando
	other := newStream(s.dir, streamSpec{name: contract.StreamReject, file: RejectFileName, maxBytes: MaxFileBytes, maxFiles: RejectFiles}, defaultOps(), sink.logger())
	other.mu.Lock()
	err = other.appendLocked(newRedelivered(testAt, contract.AuditRedelivered{Since: testAt, Count: 1}))
	other.mu.Unlock()
	if err != nil {
		t.Fatalf("o fluxo reject não pode pagar pelo exec: %v", err)
	}
}

// Num arquivo ainda sem linha (acabado de criar, ou depois de uma rotação) a entrada do diretório precisa ser
// durável antes de a linha contar. Um erro desse sync — inclusive o ErrNotDurable do fsutil — é falha: nada é
// gravado, nada conta, e não há o que desfazer (o fluxo não se envenena).
func TestSyncDoDiretorioQueFalhaNaoGravaNada(t *testing.T) {
	fl := &faults{failSyncDir: fmt.Errorf("sincronizar: %w", fsutil.ErrNotDurable)}
	s, _ := newTestStream(t, execSpec, fl.ops())
	err := appendLine(t, s, 1)
	if !errors.Is(err, fsutil.ErrNotDurable) {
		t.Fatalf("esperava o ErrNotDurable, deu %v", err)
	}
	if slices.Contains(fl.calls, "write") {
		t.Fatalf("escreveu antes de o diretório estar durável: %v", fl.calls)
	}
	if fi, err := os.Stat(s.path(0)); err == nil && fi.Size() != 0 {
		t.Fatalf("o arquivo ganhou %d bytes", fi.Size())
	}
	if s.seq != 0 || s.poisoned != nil {
		t.Fatalf("seq %d, envenenado %v", s.seq, s.poisoned)
	}
	fl.failSyncDir = nil
	mustAppend(t, s, 2)
	if lines := allLines(t, s.dir, execSpec); len(lines) != 1 || !strings.Contains(lines[0], `"seq":1,`) {
		t.Fatalf("linhas %v", lines)
	}
}

// Uma rotação interrompida (aqui, o segundo rename falha) não grava a linha, e a próxima tentativa recomeça da
// listagem real: nenhum arquivo a mais é apagado, a cadeia continua inteira e o orçamento vale.
func TestRotacaoInterrompidaRetomaSemApagarAMais(t *testing.T) {
	spec := streamSpec{name: contract.StreamExec, file: ExecFileName, maxBytes: 600, maxFiles: 4}
	fl := &faults{}
	s, _ := newTestStream(t, spec, fl.ops())
	i := 0
	for len(streamFiles(t, s.dir, spec.file)) < 3 { // .2, .1 e o atual
		if i++; i > 100 {
			t.Fatal("o fluxo não girou")
		}
		mustAppend(t, s, i)
	}
	for { // enche o atual até a próxima linha forçar a rotação
		fi, _ := os.Stat(s.path(0))
		if fi.Size()+200 > spec.maxBytes {
			break
		}
		if i++; i > 200 {
			t.Fatal("o arquivo atual não enche")
		}
		mustAppend(t, s, i)
	}
	linesBefore := allLines(t, s.dir, spec)
	fl.renameCalls, fl.failRename, fl.failRenameAt = 0, errors.New("EBUSY simulado"), 2
	seq := s.seq
	if err := appendLine(t, s, i+1); err == nil {
		t.Fatal("a rotação interrompida deveria falhar o acréscimo")
	}
	if s.seq != seq || s.poisoned != nil {
		t.Fatalf("seq %d (era %d), envenenado %v", s.seq, seq, s.poisoned)
	}
	if got := allLines(t, s.dir, spec); !slices.Equal(got, linesBefore) {
		t.Fatal("a rotação interrompida perdeu ou mudou linha")
	}
	fl.failRename = nil
	mustAppend(t, s, i+2)
	files := streamFiles(t, s.dir, spec.file)
	if len(files) > spec.maxFiles {
		t.Fatalf("%d arquivos, orçamento %d", len(files), spec.maxFiles)
	}
	got := allLines(t, s.dir, spec)
	if !slices.Equal(got[:len(got)-1], linesBefore) {
		t.Fatalf("depois de retomar a rotação: %d linhas, antes %d (nenhuma podia ter saído além da cota)", len(got)-1, len(linesBefore))
	}
}

// Um arquivo que mudou por fora (aqui, bytes acrescentados por outro processo) deixa o estado incerto: o fluxo
// se envenena em vez de acrescentar depois do que não escreveu.
func TestArquivoQueMudouPorForaEnvenena(t *testing.T) {
	s, _ := newTestStream(t, execSpec, defaultOps())
	mustAppend(t, s, 1)
	f, err := os.OpenFile(s.path(0), os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(f, `{"forjada":`); err != nil {
		t.Fatal(err)
	}
	f.Close()
	before := fileBytes(t, s.path(0))
	if err := appendLine(t, s, 2); !errors.Is(err, ErrPoisoned) {
		t.Fatalf("esperava ErrPoisoned, deu %v", err)
	}
	if got := fileBytes(t, s.path(0)); !bytes.Equal(got, before) {
		t.Fatal("o fluxo acrescentou depois de bytes que não escreveu")
	}
}

// seq é inteiro exato também para um hub que lê JSON como double: no teto 2^53-1 o fluxo recusa (só uma
// adulteração chega lá; 8 640 linhas por dia levariam bilhões de anos).
func TestSeqNoTetoRecusa(t *testing.T) {
	s, _ := newTestStream(t, execSpec, defaultOps())
	s.seq, s.head = maxSeq, sha("x")
	if err := appendLine(t, s, 1); !errors.Is(err, ErrSeqExhausted) {
		t.Fatalf("esperava ErrSeqExhausted, deu %v", err)
	}
}

// A memória guarda as últimas TailLines linhas confirmadas, com o seq de cada uma (é de onde a cauda sai).
func TestMemoriaGuardaAsUltimasLinhas(t *testing.T) {
	s, _ := newTestStream(t, execSpec, defaultOps())
	for i := 1; i <= TailLines+50; i++ {
		mustAppend(t, s, i)
	}
	lines := allLines(t, s.dir, execSpec)
	if len(s.tail) != TailLines || s.tail[0].seq != 51 || s.tail[TailLines-1].seq != TailLines+50 {
		t.Fatalf("memória: %d linhas, de %d a %d", len(s.tail), s.tail[0].seq, s.tail[len(s.tail)-1].seq)
	}
	for i, l := range s.tail {
		if l.text != lines[50+i] {
			t.Fatalf("a linha %d da memória não é a do arquivo", l.seq)
		}
	}
}
