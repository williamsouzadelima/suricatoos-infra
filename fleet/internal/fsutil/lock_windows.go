package fsutil

import (
	"errors"
	"io/fs"
	"os"
	"syscall"
	"unsafe"
)

// kernel32 is a KnownDLL: Windows always loads it from the system directory, whatever the search path.
var (
	modkernel32      = syscall.NewLazyDLL("kernel32.dll")
	procLockFileEx   = modkernel32.NewProc("LockFileEx")
	procUnlockFileEx = modkernel32.NewProc("UnlockFileEx")
)

const (
	lockfileFailImmediately = 0x00000001
	lockfileExclusiveLock   = 0x00000002
	// errorLockViolation is ERROR_LOCK_VIOLATION: another handle holds the range.
	errorLockViolation syscall.Errno = 33
)

// openLockFile opens the lock file for reading and writing, creating it with mode 0600. There is no O_NOFOLLOW
// here: an Lstat refuses a symbolic link first (best effort, with a window between the two; the connector runs on
// Linux, where the open itself refuses it).
func openLockFile(path string) (*os.File, error) {
	if fi, err := os.Lstat(path); err == nil && fi.Mode()&fs.ModeSymlink != 0 {
		return nil, &fs.PathError{Op: "open", Path: path, Err: errLinkRefused}
	}
	return os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
}

// lockFile takes LockFileEx(LOCKFILE_EXCLUSIVE_LOCK|LOCKFILE_FAIL_IMMEDIATELY) on the first byte of f: the lock
// belongs to the handle, so a second handle — in another process or in this one — gets ERROR_LOCK_VIOLATION.
func lockFile(f *os.File) error {
	var ol syscall.Overlapped
	r, _, err := procLockFileEx.Call(f.Fd(), lockfileExclusiveLock|lockfileFailImmediately, 0, 1, 0, uintptr(unsafe.Pointer(&ol)))
	if r != 0 {
		return nil
	}
	if errors.Is(err, errorLockViolation) {
		return ErrLocked
	}
	return err
}

func unlockFile(f *os.File) error {
	var ol syscall.Overlapped
	r, _, err := procUnlockFileEx.Call(f.Fd(), 0, 1, 0, uintptr(unsafe.Pointer(&ol)))
	if r != 0 {
		return nil
	}
	return err
}
