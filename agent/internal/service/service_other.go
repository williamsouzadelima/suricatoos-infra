//go:build !linux && !darwin && !windows

package service

func defaultStateDir() string { return "/var/lib/suricatoos-agent" }

// Install is not supported on this platform.
func Install(Config) error { return ErrNotSupported }

// Uninstall is not supported on this platform.
func Uninstall() error { return ErrNotSupported }

// Status is not supported on this platform.
func Status() (string, error) { return "", ErrNotSupported }
