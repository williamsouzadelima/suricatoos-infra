//go:build linux || darwin || dragonfly || freebsd || netbsd || openbsd

package fsutil

import (
	"errors"
	"os"
	"syscall"
)

// lockFlags open the lock file for reading and writing, creating it, never through a symbolic link at the last
// component, without blocking on a FIFO and without taking a controlling terminal.
const lockFlags = os.O_RDWR | os.O_CREATE | syscall.O_NOFOLLOW | syscall.O_NONBLOCK | syscall.O_NOCTTY

func openLockFile(path string) (*os.File, error) { return os.OpenFile(path, lockFlags, 0o600) }

// lockFile takes flock(LOCK_EX|LOCK_NB) on f: EWOULDBLOCK (EAGAIN) means another open file holds it.
func lockFile(f *os.File) error {
	return flock(f, syscall.LOCK_EX|syscall.LOCK_NB)
}

func unlockFile(f *os.File) error { return flock(f, syscall.LOCK_UN) }

func flock(f *os.File, how int) error {
	rc, err := f.SyscallConn()
	if err != nil {
		return err
	}
	var ferr error
	if err := rc.Control(func(fd uintptr) {
		for {
			ferr = syscall.Flock(int(fd), how)
			if !errors.Is(ferr, syscall.EINTR) {
				return
			}
		}
	}); err != nil {
		return err
	}
	if errors.Is(ferr, syscall.EWOULDBLOCK) || errors.Is(ferr, syscall.EAGAIN) {
		return ErrLocked
	}
	return ferr
}
