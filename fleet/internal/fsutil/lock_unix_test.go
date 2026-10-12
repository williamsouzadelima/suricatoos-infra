//go:build linux || darwin || dragonfly || freebsd || netbsd || openbsd

package fsutil

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// O arquivo de trava nasce 0600 e a abertura nunca passa por um link simbólico no último componente (um link
// plantado no lugar levaria a trava para outro arquivo do nó), não trava numa FIFO e não pega terminal.
func TestLockExclusiveModoELink(t *testing.T) {
	for name, flag := range map[string]int{"O_NOFOLLOW": syscall.O_NOFOLLOW, "O_NONBLOCK": syscall.O_NONBLOCK, "O_NOCTTY": syscall.O_NOCTTY, "O_CREAT": os.O_CREATE, "O_RDWR": os.O_RDWR} {
		if lockFlags&flag != flag {
			t.Errorf("a trava abre sem %s", name)
		}
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "fleet.lock")
	l, err := LockExclusive(path)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	fi, err := os.Stat(path)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("modo %v (%v), esperava 0600", fi.Mode().Perm(), err)
	}

	target := filepath.Join(dir, "outro")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.lock")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if l2, err := LockExclusive(link); err == nil {
		l2.Close()
		t.Fatal("a trava passou por um link simbólico")
	}
}
