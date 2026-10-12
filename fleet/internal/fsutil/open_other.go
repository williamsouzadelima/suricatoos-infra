//go:build !unix

package fsutil

import "os"

// openRead opens path for reading. Where there is no O_NONBLOCK (Windows) the descriptor is checked after the
// open all the same.
func openRead(path string) (*os.File, error) { return os.Open(path) }
