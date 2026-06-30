//go:build !linux && !darwin && !windows

package service

// Restart is unsupported on platforms without a native service manager.
func Restart() error { return ErrNotSupported }
