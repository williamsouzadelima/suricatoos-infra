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

// readNoFollowFlags open a file the connector owns and reads in place (OpenRegularNoFollow): readFlags plus
// O_NOFOLLOW, so a symbolic link at the last component is refused by the open itself.
const readNoFollowFlags = readFlags | syscall.O_NOFOLLOW

// appendFlags open a file the connector owns for appending (created if missing, never truncated), never through a
// symbolic link at the last component (O_NOFOLLOW), and, like readFlags, without blocking on a FIFO or taking a
// controlling terminal.
const appendFlags = os.O_WRONLY | os.O_APPEND | os.O_CREATE | syscall.O_NOFOLLOW | syscall.O_NONBLOCK | syscall.O_NOCTTY

// truncateFlags open an existing file the connector owns to cut it: no O_CREATE, no O_APPEND, never through a link.
const truncateFlags = os.O_WRONLY | syscall.O_NOFOLLOW | syscall.O_NONBLOCK | syscall.O_NOCTTY

// openRead opens path for reading with readFlags. The caller checks the descriptor afterwards (regularInfo).
func openRead(path string) (*os.File, error) { return os.OpenFile(path, readFlags, 0) }

// openReadNoFollow opens path with readNoFollowFlags.
func openReadNoFollow(path string) (*os.File, error) { return os.OpenFile(path, readNoFollowFlags, 0) }

// openAppend opens path with appendFlags; a file it creates gets mode 0600.
func openAppend(path string) (*os.File, error) { return os.OpenFile(path, appendFlags, 0o600) }

// openTruncate opens path with truncateFlags.
func openTruncate(path string) (*os.File, error) { return os.OpenFile(path, truncateFlags, 0) }
