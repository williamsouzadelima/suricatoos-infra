//go:build !windows

package main

// isWindowsService always returns false on non-Windows platforms.
func isWindowsService() bool { return false }

// runWindowsSvc is a no-op stub on non-Windows platforms.
func runWindowsSvc(_ []string) {}
