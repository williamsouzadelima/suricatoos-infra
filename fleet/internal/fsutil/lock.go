package fsutil

import (
	"errors"
	"fmt"
	"os"
)

var (
	// ErrLocked: another process holds the lock — a second fleet connector on the same FLEET_STATE_DIR, which
	// would append audit lines with the same seq and take decisions in the anti-replay store concurrently.
	ErrLocked = errors.New("fsutil: trava exclusiva já tomada por outro processo")
	// ErrLockUnsupported: this system has no exclusive file lock the connector trusts (it runs on Linux; macOS, the
	// BSDs and Windows serve development).
	ErrLockUnsupported = errors.New("fsutil: trava exclusiva sem suporte neste sistema")
)

// Lock is an exclusive lock on a lock file, held for as long as the process keeps it: Close releases it, and so does
// the end of the process, whatever way it ends (the kernel drops the lock with the last descriptor). The *os.File
// is kept here on purpose: a file nobody references could be closed by the runtime, and the lock with it.
type Lock struct {
	f    *os.File
	path string
}

// LockExclusive takes, without waiting, the exclusive lock of the file at path — flock(LOCK_EX|LOCK_NB) on unix,
// LockFileEx(LOCKFILE_EXCLUSIVE_LOCK|LOCKFILE_FAIL_IMMEDIATELY) on Windows —, creating the file with mode 0600 when
// it does not exist. A lock another process holds is ErrLocked at once, never a wait: a second connector must not
// start, and say why. Two opens in the same process conflict too (both locks belong to the open file, not to the
// process), which is what a test of "two processes" relies on.
//
// The file is opened like the other files the connector owns: on unix never through a symbolic link at the last
// component (O_NOFOLLOW), without blocking on a FIFO or taking a controlling terminal, and it must be a regular file
// (else ErrNotRegular). The file stays in place after Close: removing it would let a third process lock a new file
// while a second one still holds the old.
func LockExclusive(path string) (*Lock, error) {
	f, err := openLockFile(path)
	if err != nil {
		return nil, fmt.Errorf("fsutil: abrir a trava %s: %w", path, err)
	}
	if _, err := regularInfo(f, path); err != nil {
		f.Close()
		return nil, err
	}
	if err := lockFile(f); err != nil {
		f.Close()
		if errors.Is(err, ErrLocked) || errors.Is(err, ErrLockUnsupported) {
			return nil, fmt.Errorf("%w: %s", err, path)
		}
		return nil, fmt.Errorf("fsutil: travar %s: %w", path, err)
	}
	return &Lock{f: f, path: path}, nil
}

// Path is the lock file.
func (l *Lock) Path() string { return l.path }

// Close releases the lock and closes the file; a second Close does nothing.
func (l *Lock) Close() error {
	if l == nil || l.f == nil {
		return nil
	}
	uerr := unlockFile(l.f)
	cerr := l.f.Close()
	l.f = nil
	return errors.Join(uerr, cerr)
}
