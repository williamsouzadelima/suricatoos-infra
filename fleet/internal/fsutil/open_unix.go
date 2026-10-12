//go:build unix

package fsutil

import (
	"os"
	"syscall"
)

// readFlags open whatever is at the path for reading without blocking — opening a FIFO that has no writer would
// otherwise wait for one forever; a regular file ignores the flag — and with O_NOCTTY: a tty opened without it
// becomes the controlling terminal of a session leader that has none, which is what a service is.
const readFlags = os.O_RDONLY | syscall.O_NONBLOCK | syscall.O_NOCTTY

// openRead opens path for reading with readFlags. The caller checks the descriptor afterwards (readRegular).
func openRead(path string) (*os.File, error) {
	return os.OpenFile(path, readFlags, 0)
}
