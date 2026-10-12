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
