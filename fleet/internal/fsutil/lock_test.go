package fsutil

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// lockOrSkip takes the lock, or skips where the platform has no exclusive lock (the connector runs on Linux; the
// tests run on Linux, macOS and Windows).
func lockOrSkip(t *testing.T, path string) *Lock {
	t.Helper()
	l, err := LockExclusive(path)
	if errors.Is(err, ErrLockUnsupported) {
		t.Skip("trava exclusiva sem suporte neste sistema")
	}
	if err != nil {
		t.Fatal(err)
	}
	return l
}

// Dois "processos" no mesmo FLEET_STATE_DIR: a segunda trava não espera nem passa, falha com ErrLocked na hora; e
// depois que a primeira solta, a trava volta a ser tomada.
func TestLockExclusiveSegundaTravaFalhaNaHora(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fleet.lock")
	first := lockOrSkip(t, path)
	second, err := LockExclusive(path)
	if !errors.Is(err, ErrLocked) || second != nil {
		t.Fatalf("a segunda trava devia falhar com ErrLocked, deu %v (%v)", err, second)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	third := lockOrSkip(t, path)
	if err := third.Close(); err != nil {
		t.Fatal(err)
	}
}

// O arquivo de trava é criado se não existe, fica no lugar depois de solto (apagá-lo abriria corrida entre dois
// processos) e o Close repetido não é erro.
func TestLockExclusiveCriaOArquivoEOMantem(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fleet.lock")
	l := lockOrSkip(t, path)
	if l.Path() != path {
		t.Fatalf("Path() = %q", l.Path())
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if err := l.Close(); err != nil {
		t.Fatalf("Close repetido: %v", err)
	}
	if fi, err := os.Stat(path); err != nil || !fi.Mode().IsRegular() {
		t.Fatalf("o arquivo de trava devia continuar no lugar: %v", err)
	}
}

// Um diretório no lugar do arquivo de trava é recusado (não é uma trava que vale), e um diretório pai ausente também.
func TestLockExclusiveRecusaQuemNaoEArquivoRegular(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "fleet.lock")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if l, err := LockExclusive(path); err == nil || errors.Is(err, ErrLocked) {
		l.Close()
		t.Fatalf("um diretório no lugar da trava devia ser recusado, deu %v", err)
	}
	if l, err := LockExclusive(filepath.Join(dir, "falta", "fleet.lock")); err == nil {
		l.Close()
		t.Fatal("diretório pai ausente devia ser erro")
	}
}
