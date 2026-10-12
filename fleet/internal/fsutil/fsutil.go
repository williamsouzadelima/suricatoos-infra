// Package fsutil holds the file primitives the fleet connector's local state needs:
//
//   - ReadBounded: a bounded, race-free read of a file the operator (or another service) owns, telling "absent"
//     from "present but unusable"; OpenRegular is the same open, for a file read as a stream, and
//     OpenRegularNoFollow the one for a file the connector owns, which never goes through a symbolic link;
//   - WriteAtomic: the atomic, durable replacement of a state file the connector owns (ADR-0011 "Anti-replay,
//     idempotência e entrega": temp + rename with fsync, 0600), and RemoveOrphanTemps, which cleans what a crash
//     in the middle of it leaves behind;
//   - OpenAppend, TruncateDurable and SyncDir: what an append-only file the connector owns (the local audit) needs —
//     the append-only open, the durable cut that undoes a failed append, and the directory sync after a file is
//     created, renamed or removed;
//   - LooseMode: whether a secrets file is open to its group or to others (a warning for the log, not a refusal).
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
	f, err := openExisting(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return readRegular(f, path, limit)
}

// OpenRegular opens the file at path for reading under the rules of ReadBounded — symbolic links followed, an
// absent path satisfies fs.ErrNotExist, a dangling link is ErrDanglingLink, the opened descriptor (not the path)
// must be a regular file or it is ErrNotRegular, and the open does not block on a FIFO — but leaves the reading to
// the caller, for a file read as a stream instead of held whole in memory. The caller closes it.
func OpenRegular(path string) (*os.File, error) {
	f, err := openExisting(path)
	if err != nil {
		return nil, err
	}
	if _, err := regularInfo(f, path); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

// OpenRegularNoFollow is OpenRegular for a file the connector owns and reads in place (the local audit, at boot):
// it never opens through a symbolic link at the last component — on unix the open itself refuses it (O_NOFOLLOW);
// elsewhere an Lstat refuses it first —, so a link planted in place of the file cannot make the connector read, and
// pass on, another file of the node. A path with nothing at it satisfies fs.ErrNotExist; a link, dangling or not,
// is an error that does not; what is not a regular file is ErrNotRegular. The caller closes it.
func OpenRegularNoFollow(path string) (*os.File, error) {
	f, err := openReadNoFollow(path)
	if err != nil {
		return nil, err
	}
	if _, err := regularInfo(f, path); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

// openExisting opens path with openRead and tells a dangling link (ErrDanglingLink) from a path with nothing at
// it (fs.ErrNotExist).
func openExisting(path string) (*os.File, error) {
	f, err := openRead(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			if _, lerr := os.Lstat(path); lerr == nil {
				return nil, fmt.Errorf("%w: %s", ErrDanglingLink, path)
			}
		}
		return nil, err
	}
	return f, nil
}

// regularInfo returns the FileInfo of the open descriptor f, or ErrNotRegular when it is not a regular file.
func regularInfo(f *os.File, name string) (fs.FileInfo, error) {
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: %s", ErrNotRegular, name)
	}
	return fi, nil
}

// readRegular reads the open file f if, and only if, the descriptor is a regular file and fits in limit bytes.
func readRegular(f *os.File, name string, limit int64) ([]byte, error) {
	if _, err := regularInfo(f, name); err != nil {
		return nil, err
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
// a directory (EINVAL or ENOTSUP) is tolerated; any other error, such as EIO, is returned.
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
// exactly like WriteAtomic names them for this path go: the name of path, ".tmp-" and the suffix os.CreateTemp
// generates, which is decimal digits only (TestCreateTempGeraSufixoDeDigitosQueALimpezaReconhece pins it). The
// directory is shared with the other state files of the connector, whose leftovers belong to them, and a file of
// the operator's that merely shares the prefix ("budget.json.tmp-old") is not a temporary. Directories are never
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
		suffix, ok := strings.CutPrefix(e.Name(), prefix)
		if e.IsDir() || !ok || !decimalDigits(suffix) {
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

// decimalDigits reports whether s is a non-empty run of the ASCII digits 0-9 (and nothing else).
func decimalDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
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
	if err := syncHandle(d); err != nil && !dirSyncUnsupported(err) {
		return err
	}
	return nil
}

// syncHandle is (*os.File).Sync on the directory syncDir opened. It is a variable only so that a test can make a
// real directory's sync fail (an fsync EIO cannot be provoked on demand).
var syncHandle = (*os.File).Sync

// dirSyncUnsupported reports whether err only says that this filesystem cannot sync a directory: EINVAL, or ENOTSUP
// (EOPNOTSUPP is the same errno on Linux and the name the BSDs and macOS use). Nothing else is tolerated.
func dirSyncUnsupported(err error) bool {
	return errors.Is(err, syscall.EINVAL) || errors.Is(err, syscall.ENOTSUP) || errors.Is(err, syscall.EOPNOTSUPP)
}

// SyncDir makes the entries of the directory dir durable: what the creation, rename or removal of a file inside it
// needs to survive a power cut. It is WriteAtomic's directory sync, with its rules: skipped on Windows (a directory
// cannot be opened for it), EINVAL and ENOTSUP tolerated (the filesystem only says it cannot sync a directory), any
// other error returned.
func SyncDir(dir string) error { return syncDirectory(dir) }

// OpenAppend opens the file at path for appending — every write lands at the end, whatever the offset — creating
// it with mode 0600 when it does not exist (an existing file keeps its mode and content). The opened descriptor must
// be a regular file or it is ErrNotRegular, and nothing stays open. On unix it never opens through a symbolic link
// at the last component, does not block on a FIFO and takes no controlling terminal. The caller writes, Syncs and
// closes it; in a file it has just created, nothing written counts as durable before a SyncDir of its directory.
func OpenAppend(path string) (*os.File, error) {
	f, err := openAppend(path)
	if err != nil {
		return nil, err
	}
	if _, err := regularInfo(f, path); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

// TruncateDurable cuts the existing regular file at path down to size bytes and fsyncs it, so that the cut survives
// a power cut: it undoes an append that failed (whatever part of it reached the file goes) and discards a partial
// last line. It only shrinks — a size beyond the end, which would fill the gap with zeros, is refused, and so is a
// negative one — never creates the file, refuses what is not a regular file and, on unix, never goes through a
// symbolic link. After an error the cut may or may not have happened, or may not be durable: the caller must not
// rely on the content of the file.
func TruncateDurable(path string, size int64) error {
	f, err := openTruncate(path)
	if err != nil {
		return err
	}
	defer f.Close()
	fi, err := regularInfo(f, path)
	if err != nil {
		return err
	}
	if size < 0 || size > fi.Size() {
		return fmt.Errorf("fsutil: corte para %d bytes num arquivo de %d: %s", size, fi.Size(), path)
	}
	if err := f.Truncate(size); err != nil {
		return err
	}
	return f.Sync()
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
