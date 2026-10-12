//go:build !unix

package fsutil

import "os"

// openRead opens path for reading. Where there is no O_NONBLOCK (Windows) the descriptor is checked after the
// open all the same.
func openRead(path string) (*os.File, error) { return os.Open(path) }

// openAppend opens path for appending, creating it with mode 0600. There is no O_NOFOLLOW here: the refusal of a
// symbolic link is unix-only (the connector runs on Linux; this build serves development).
func openAppend(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
}

// openTruncate opens an existing path for writing without O_APPEND: on Windows an O_APPEND handle has no right to
// cut the file.
func openTruncate(path string) (*os.File, error) { return os.OpenFile(path, os.O_WRONLY, 0) }
