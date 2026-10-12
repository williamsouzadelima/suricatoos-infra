//go:build linux

package fsutil

import (
	"errors"
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
