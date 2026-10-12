package fsutil

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// O arquivo de auditoria é só de acréscimo: o que se escreve cai no fim, qualquer que seja o offset, e o arquivo
// nasce na primeira escrita.
func TestOpenAppendCriaEAcrescentaNoFim(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	f, err := OpenAppend(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte("um\n")); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	f, err = OpenAppend(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	// o O_APPEND ignora o offset: voltar ao começo não sobrescreve nada
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte("dois\n")); err != nil {
		t.Fatal(err)
	}
	if err := f.Sync(); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, path); got != "um\ndois\n" {
		t.Fatalf("conteúdo %q", got)
	}
}

func TestOpenAppendRecusaDiretorio(t *testing.T) {
	dir := t.TempDir()
	f, err := OpenAppend(dir)
	if err == nil {
		f.Close()
		t.Fatal("abrir um diretório para acrescentar deveria falhar")
	}
	if errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("o diretório existe: não pode passar por ausente (%v)", err)
	}
}

func TestOpenAppendDiretorioPaiAusenteEErro(t *testing.T) {
	if _, err := OpenAppend(filepath.Join(t.TempDir(), "sem", "pai", "audit.jsonl")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("esperava fs.ErrNotExist, deu %v", err)
	}
}

// Desfazer um acréscimo que falhou (ou descartar a linha parcial de uma queda) corta o arquivo de volta ao
// tamanho de antes, e só para trás: um tamanho além do fim encheria o buraco de zeros.
func TestTruncateDurableCortaSoParaTras(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	if err := os.WriteFile(path, []byte("linha 1\nlinha 2\nparc"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := TruncateDurable(path, int64(len("linha 1\nlinha 2\n"))); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, path); got != "linha 1\nlinha 2\n" {
		t.Fatalf("conteúdo depois do corte: %q", got)
	}
	for _, size := range []int64{int64(len("linha 1\nlinha 2\n")) + 1, 1 << 20, -1} {
		if err := TruncateDurable(path, size); err == nil {
			t.Errorf("tamanho %d: deveria ser recusado", size)
		}
	}
	if got := readFile(t, path); got != "linha 1\nlinha 2\n" {
		t.Fatalf("um corte recusado mudou o arquivo: %q", got)
	}
	// o tamanho atual é um corte que não muda nada
	if err := TruncateDurable(path, int64(len("linha 1\nlinha 2\n"))); err != nil {
		t.Fatal(err)
	}
	if err := TruncateDurable(path, 0); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, path); got != "" {
		t.Fatalf("corte a zero: %q", got)
	}
}

func TestTruncateDurableNaoCriaNemAceitaDiretorio(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "nao-existe")
	if err := TruncateDurable(missing, 0); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("arquivo ausente: esperava fs.ErrNotExist, deu %v", err)
	}
	if _, err := os.Lstat(missing); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("o corte não pode criar o arquivo")
	}
	if err := TruncateDurable(dir, 0); err == nil {
		t.Fatal("cortar um diretório deveria falhar")
	}
}

// A leitura em fluxo (os arquivos de auditoria podem ter 32 MiB) usa as mesmas regras do ReadBounded: ausente é
// fs.ErrNotExist, link sem destino é ErrDanglingLink e o que não é arquivo regular é ErrNotRegular.
func TestOpenRegular(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "f")
	if err := os.WriteFile(path, []byte("conteudo"), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := OpenRegular(path)
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(f)
	f.Close()
	if err != nil || string(b) != "conteudo" {
		t.Fatalf("leitura: %q, %v", b, err)
	}
	if _, err := OpenRegular(filepath.Join(dir, "nao-existe")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("ausente: esperava fs.ErrNotExist, deu %v", err)
	}
	if _, err := OpenRegular(dir); !errors.Is(err, ErrNotRegular) {
		t.Fatalf("diretório: esperava ErrNotRegular, deu %v", err)
	}
	if _, err := OpenRegular(danglingLink(t, t.TempDir())); !errors.Is(err, ErrDanglingLink) {
		t.Fatalf("link sem destino: esperava ErrDanglingLink, deu %v", err)
	}
}

// O arquivo próprio lido no lugar (a auditoria, no boot) abre como o OpenRegular — ausente é fs.ErrNotExist, o
// que não é arquivo regular é ErrNotRegular —, mas nunca através de link (TestOpenRegularNoFollowRecusaLink, unix).
func TestOpenRegularNoFollow(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	if err := os.WriteFile(path, []byte("linha\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := OpenRegularNoFollow(path)
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(f)
	f.Close()
	if err != nil || string(b) != "linha\n" {
		t.Fatalf("leitura: %q, %v", b, err)
	}
	if _, err := OpenRegularNoFollow(filepath.Join(dir, "nao-existe")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("ausente: esperava fs.ErrNotExist, deu %v", err)
	}
	if _, err := OpenRegularNoFollow(dir); !errors.Is(err, ErrNotRegular) {
		t.Fatalf("diretório: esperava ErrNotRegular, deu %v", err)
	}
}

// O SyncDir exportado é o mesmo sync de diretório do WriteAtomic (mesmo seam, mesmas regras).
func TestSyncDirUsaOSyncDoWriteAtomic(t *testing.T) {
	boom := errors.New("EIO simulado")
	var got string
	swapSyncDirectory(t, func(dir string) error { got = dir; return boom })
	dir := t.TempDir()
	if err := SyncDir(dir); !errors.Is(err, boom) {
		t.Fatalf("esperava o erro do sync do diretório, deu %v", err)
	}
	if got != dir {
		t.Fatalf("sincronizou %q, esperava %q", got, dir)
	}
}

func TestSyncDirDeUmDiretorioComumNaoFalha(t *testing.T) {
	if err := SyncDir(t.TempDir()); err != nil {
		t.Fatal(err)
	}
}
