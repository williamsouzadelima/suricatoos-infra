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
// 0600), is fsynced, and is renamed over path. The directory is then synced too, so the rename itself survives
// a power cut; that last step is best effort (a directory cannot be opened for sync on Windows, and some
// filesystems refuse it): the file content is durable either way, and the only thing a failed directory sync
// can cost is the very last replacement after a power cut. On any error the temporary file is removed and the
// previous content of path is untouched.
func WriteAtomic(path string, data []byte) (err error) {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*") // created with mode 0600
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() {
		if err != nil {
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
	syncDir(dir)
	return nil
}

func syncDir(dir string) {
	if runtime.GOOS == "windows" {
		return
	}
	d, err := os.Open(dir)
	if err != nil {
		return
	}
	d.Sync()
	d.Close()
}
