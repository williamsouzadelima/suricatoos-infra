//go:build linux

package fsutil

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// Uma FIFO sem escritor trava um open bloqueante para sempre, e com isso o processamento de comandos.
func TestReadBoundedFIFONaoTravaOChamador(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("mkfifo indisponível neste host: %v", err)
	}
	link := filepath.Join(dir, "link-para-fifo")
	if err := os.Symlink(fifo, link); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{fifo, link} {
		done := make(chan error, 1)
		go func() {
			_, err := ReadBounded(path, 64)
			done <- err
		}()
		select {
		case err := <-done:
			if !errors.Is(err, ErrNotRegular) {
				t.Errorf("%s: esperava ErrNotRegular, deu %v", filepath.Base(path), err)
			}
		case <-time.After(10 * time.Second):
			t.Fatalf("%s: ReadBounded travou numa FIFO", filepath.Base(path))
		}
	}
}

// Uma FIFO no lugar do arquivo de auditoria não trava o acréscimo nem o corte: sem leitor o open falha na hora
// (ENXIO, graças ao O_NONBLOCK), e com leitor o descritor aberto não é arquivo regular.
func TestAcrescimoECorteNumaFIFONaoTravam(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "audit.jsonl")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("mkfifo indisponível neste host: %v", err)
	}
	within := func(name string, fn func() error) error {
		t.Helper()
		done := make(chan error, 1)
		go func() { done <- fn() }()
		select {
		case err := <-done:
			return err
		case <-time.After(10 * time.Second):
			t.Fatalf("%s: travou numa FIFO", name)
			return nil
		}
	}
	openAppend := func() error {
		f, err := OpenAppend(fifo)
		if err == nil {
			f.Close()
		}
		return err
	}
	truncate := func() error { return TruncateDurable(fifo, 0) }
	if err := within("OpenAppend sem leitor", openAppend); err == nil {
		t.Error("OpenAppend numa FIFO sem leitor deveria falhar")
	}
	if err := within("TruncateDurable sem leitor", truncate); err == nil {
		t.Error("TruncateDurable numa FIFO sem leitor deveria falhar")
	}
	r, err := os.OpenFile(fifo, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if err := within("OpenAppend com leitor", openAppend); !errors.Is(err, ErrNotRegular) {
		t.Errorf("OpenAppend numa FIFO com leitor: esperava ErrNotRegular, deu %v", err)
	}
	if err := within("TruncateDurable com leitor", truncate); !errors.Is(err, ErrNotRegular) {
		t.Errorf("TruncateDurable numa FIFO com leitor: esperava ErrNotRegular, deu %v", err)
	}
}

// Fora do Windows o diretório é aberto e sincronizado de verdade, e a falha de abrir não é engolida.
func TestSyncDirDeVerdadeNoLinux(t *testing.T) {
	if err := syncDir(t.TempDir()); err != nil {
		t.Fatalf("sincronizar um diretório comum não pode falhar: %v", err)
	}
	if err := syncDir(filepath.Join(t.TempDir(), "nao-existe")); err == nil {
		t.Fatal("diretório que não abre tem de ser erro, não sucesso")
	}
	// o WriteAtomic devolve esse erro como ErrNotDurable quando o diretório some entre o rename e o sync
	dir := t.TempDir()
	swapSyncDirectory(t, func(string) error { return syncDir(filepath.Join(dir, "sumiu")) })
	err := WriteAtomic(filepath.Join(dir, "estado.json"), []byte("x"))
	if !errors.Is(err, ErrNotDurable) || !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("esperava ErrNotDurable com a causa da abertura, deu %v", err)
	}
}

// Modos de verdade, num sistema que os respeita (o link é seguido: vale o modo do destino).
func TestLooseModeComModosReaisNoLinux(t *testing.T) {
	dir := t.TempDir()
	mk := func(name string, mode os.FileMode) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil { // o chmod não sofre a umask
			t.Fatal(err)
		}
		return p
	}
	for _, c := range []struct {
		mode  os.FileMode
		loose bool
	}{{0o600, false}, {0o400, false}, {0o640, true}, {0o644, true}, {0o604, true}, {0o660, true}, {0o666, true}} {
		perm, loose, err := LooseMode(mk(fmt.Sprintf("f-%04o", c.mode), c.mode))
		if err != nil || loose != c.loose || perm != c.mode {
			t.Errorf("modo %04o: perm=%04o loose=%v err=%v, esperava loose=%v", c.mode, perm, loose, err, c.loose)
		}
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(mk("alvo", 0o644), link); err != nil {
		t.Fatal(err)
	}
	if perm, loose, err := LooseMode(link); err != nil || !loose || perm != 0o644 {
		t.Errorf("link para arquivo 0644: perm=%04o loose=%v err=%v", perm, loose, err)
	}
}
