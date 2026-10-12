//go:build unix

package fsutil

import (
	"os"
	"syscall"
)

// openRead opens path for reading without blocking: opening a FIFO that has no writer would otherwise wait
// for one forever. A regular file ignores the flag.
func openRead(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
}
