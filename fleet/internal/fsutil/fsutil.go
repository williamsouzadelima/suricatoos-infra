// Package fsutil holds the two file primitives the fleet connector's local state needs: a bounded read of a file
// the operator (or another service) owns, and the atomic replacement of a state file the connector owns
// (ADR-0011 "Anti-replay, idempotência e entrega": temp + rename with fsync, 0600).
package fsutil

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
)

var (
	// ErrTooLarge: the file is bigger than the cap the caller set.
	ErrTooLarge = errors.New("fsutil: arquivo maior que o teto")
	// ErrNotRegular: the path exists but is a directory, a device, a pipe...
	ErrNotRegular = errors.New("fsutil: não é um arquivo regular")
	// ErrDanglingLink: the path is a symbolic link whose target does not exist. Something IS there — a broken
	// config mount, say — so it is not "absent" and does not satisfy fs.ErrNotExist.
	ErrDanglingLink = errors.New("fsutil: link simbólico sem destino")
)

// ReadBounded reads the whole regular file at path, following symbolic links (a config mount is often one),
// and refuses a file bigger than limit bytes: a runaway file must not grow the connector's memory. Nothing at
// the path (or a missing parent directory) returns an error that satisfies errors.Is(err, fs.ErrNotExist), so
// "absent" can be told apart from "present but unusable": a dangling link is ErrDanglingLink, and anything that
// is not a regular file is ErrNotRegular.
//
// The path is opened first and the opened descriptor is what is checked (readRegular), so there is no window
// between a check and the open for the path to turn into something else; where the OS supports it the open does
// not block, so a FIFO swapped in at that very moment cannot hang the caller either.
func ReadBounded(path string, limit int64) ([]byte, error) {
	f, err := openRead(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			if _, lerr := os.Lstat(path); lerr == nil {
				return nil, fmt.Errorf("%w: %s", ErrDanglingLink, path)
			}
		}
		return nil, err
	}
	defer f.Close()
	return readRegular(f, path, limit)
}

// readRegular reads the open file f if, and only if, the descriptor is a regular file and fits in limit bytes.
func readRegular(f *os.File, name string, limit int64) ([]byte, error) {
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: %s", ErrNotRegular, name)
	}
	// one byte past the cap tells a file that grew while it was read from one that fits exactly
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("%w (%d bytes): %s", ErrTooLarge, limit, name)
	}
	return b, nil
}

// WriteAtomic replaces the file at path with data so that a reader — or a crash at any point — sees either the
// previous content or the new one, never a mix: the data goes to a temporary file in the same directory (mode
// 0600), is fsynced, and is renamed over path; then the directory is synced, so the rename itself survives a
// power cut.
//
// An error before the rename leaves the previous content of path untouched and removes the temporary file. An
// error from the directory sync — it could not be opened or synced — comes after the rename and wraps
// ErrNotDurable: the new content IS in place and readers see it, but nothing says it survives a power cut, so the
// caller must not treat the replacement as recorded (it answers unavailable and tries again). The directory sync
// is skipped on Windows, where a directory cannot be opened for it, and a filesystem that only says it cannot sync
// a directory (EINVAL, or errors.ErrUnsupported: ENOTSUP, EOPNOTSUPP, ENOSYS) is tolerated; any other error,
// such as EIO, is returned.
func WriteAtomic(path string, data []byte) (err error) {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, filepath.Base(path)+tempInfix+"*") // created with mode 0600
	if err != nil {
		return err
	}
	tmp := f.Name()
	renamed := false
	defer func() {
		if err != nil && !renamed {
			os.Remove(tmp)
		}
	}()
	if _, err = f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(tmp, path); err != nil {
		return err
	}
	renamed = true
	if serr := syncDirectory(dir); serr != nil {
		return fmt.Errorf("%w: sincronizar o diretório %s: %w", ErrNotDurable, dir, serr)
	}
	return nil
}

// tempInfix sits between the name of the file and the random suffix of the temporary file WriteAtomic creates.
const tempInfix = ".tmp-"

// RemoveOrphanTemps removes the temporary files an interrupted WriteAtomic(path, ...) left behind — a crash between
// creating the temporary file and renaming it — and returns how many it removed. Only the files that are named
// exactly like WriteAtomic names them for this path (the name of path, ".tmp-", a suffix) go; the directory is
// shared with the other state files of the connector, whose leftovers belong to them. Directories are never
// touched. It assumes no WriteAtomic of the same path is running. A directory that does not exist has nothing to
// clean; a file that cannot be removed is reported in the error (all the others are still removed).
func RemoveOrphanTemps(path string) (removed int, err error) {
	dir, prefix := filepath.Dir(path), filepath.Base(path)+tempInfix
	entries, rerr := os.ReadDir(dir)
	if rerr != nil {
		if errors.Is(rerr, fs.ErrNotExist) {
			return 0, nil
		}
		return 0, rerr
	}
	var errs []error
	for _, e := range entries {
		if e.IsDir() || !strings.HasPrefix(e.Name(), prefix) {
			continue
		}
		if rerr := os.Remove(filepath.Join(dir, e.Name())); rerr != nil && !errors.Is(rerr, fs.ErrNotExist) {
			errs = append(errs, rerr)
			continue
		}
		removed++
	}
	return removed, errors.Join(errs...)
}

// ErrNotDurable: WriteAtomic renamed the new content into place, but could not confirm that the directory entry
// is durable. The content is visible; only its survival of a power cut is unknown.
var ErrNotDurable = errors.New("fsutil: substituição feita, mas não confirmada como durável")

// syncDirectory syncs the directory dir after a rename. It is a variable only so that a test can make it fail.
var syncDirectory = syncDir

func syncDir(dir string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	if err := d.Sync(); err != nil && !dirSyncUnsupported(err) {
		return err
	}
	return nil
}

// dirSyncUnsupported reports whether err only says that this filesystem cannot sync a directory.
func dirSyncUnsupported(err error) bool {
	return errors.Is(err, syscall.EINVAL) || errors.Is(err, errors.ErrUnsupported)
}

// LooseMode reports whether the file at path can be reached by its group or by others, that is, whether it has any
// permission bit outside the owner's: a secrets file should be 0600. perm is the permission bits, for the warning
// the caller writes. Symbolic links are followed (a config mount is often one), so it is the mode of the file
// behind them. A missing file is the error from os.Stat (it satisfies fs.ErrNotExist). On Windows, where the mode
// bits are not the access control, loose is always false.
//
// It only reports: refusing a file by its mode would break read-only mounts that carry another owner's mode, so
// what to do about it (a warning at startup) is the caller's.
func LooseMode(path string) (perm fs.FileMode, loose bool, err error) {
	fi, err := os.Stat(path)
	if err != nil {
		return 0, false, err
	}
	perm = fi.Mode().Perm()
	if runtime.GOOS == "windows" {
		return perm, false, nil
	}
	return perm, looseBits(perm), nil
}

// looseBits reports whether perm has a bit of the group or of others (0o077).
func looseBits(perm fs.FileMode) bool { return perm.Perm()&0o077 != 0 }
