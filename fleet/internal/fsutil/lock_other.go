//go:build !(linux || darwin || dragonfly || freebsd || netbsd || openbsd || windows)

package fsutil

import "os"

// Elsewhere (Solaris, illumos, AIX, Plan 9, wasm) there is no exclusive lock the connector trusts: LockExclusive is
// ErrLockUnsupported and the connector does not start — fail-closed rather than run two of them unseen.
func openLockFile(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
}

func lockFile(*os.File) error { return ErrLockUnsupported }

func unlockFile(*os.File) error { return nil }
