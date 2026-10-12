package replay

import (
	"io"
	"os"
)

// faultyFile wraps the real file of an append to make its write (half of the line reaches the file) or its fsync
// fail.
type faultyFile struct {
	*os.File
	failWrite, failSync error
}

func (f *faultyFile) Write(p []byte) (int, error) {
	if f.failWrite != nil {
		n, _ := f.File.Write(p[:len(p)/2])
		return n, f.failWrite
	}
	return f.File.Write(p)
}

func (f *faultyFile) Sync() error {
	if f.failSync != nil {
		return f.failSync
	}
	return f.File.Sync()
}

// faults makes the next file operations of a store fail as configured, and counts the directory syncs.
type faults struct {
	failWrite, failSync, failTruncate, failSyncDir, failRewrite, failRewriteAfter error
	syncDirs                                                                      int
}

// config is the default config with the file operations wrapped.
func (fl *faults) config() config {
	c := defaultConfig()
	real := c.ops
	c.ops.openAppend = func(path string) (appendFile, error) {
		f, err := real.openAppend(path)
		if err != nil {
			return nil, err
		}
		return &faultyFile{File: f.(*os.File), failWrite: fl.failWrite, failSync: fl.failSync}, nil
	}
	c.ops.truncate = func(path string, size int64) error {
		if fl.failTruncate != nil {
			return fl.failTruncate
		}
		return real.truncate(path, size)
	}
	c.ops.syncDir = func(dir string) error {
		fl.syncDirs++
		if fl.failSyncDir != nil {
			return fl.failSyncDir
		}
		return real.syncDir(dir)
	}
	c.ops.writeStream = func(path string, fill func(io.Writer) error) error {
		if fl.failRewrite != nil {
			return fl.failRewrite
		}
		err := real.writeStream(path, fill)
		if err == nil && fl.failRewriteAfter != nil {
			return fl.failRewriteAfter // e.g. fsutil.ErrNotDurable: the new content IS in place
		}
		return err
	}
	return c
}
