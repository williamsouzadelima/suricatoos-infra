// Package service installs and manages the Suricatoos Agent as a native
// system service. Each platform provides its own implementation:
//
//   - Linux: systemd unit at /etc/systemd/system/suricatoos-agent.service
//   - macOS: launchd LaunchDaemon at /Library/LaunchDaemons/com.suricatoos.agent.plist
//   - Windows: Windows Service Control Manager ("SuricatoosAgent")
//
// Install and Uninstall require elevated privileges (root/Administrator).
package service

import (
	"errors"
	"os"
	"time"
)

// ServiceName is the canonical name used by the native service manager.
const ServiceName = "suricatoos-agent"

// Config holds the parameters written into the native service definition.
// BinaryPath defaults to the current executable when empty.
type Config struct {
	IngestURL  string
	StateDir   string
	QueueDir   string
	Interval   time.Duration
	MaxQueue   int
	BinaryPath string
}

// Defaults fills zero-value fields in cfg with sensible values.
func (cfg *Config) Defaults() error {
	if cfg.StateDir == "" {
		cfg.StateDir = defaultStateDir()
	}
	if cfg.QueueDir == "" {
		cfg.QueueDir = cfg.StateDir + "/queue"
	}
	if cfg.Interval <= 0 {
		cfg.Interval = 15 * time.Minute
	}
	if cfg.MaxQueue <= 0 {
		cfg.MaxQueue = 1000
	}
	if cfg.BinaryPath == "" {
		exe, err := os.Executable()
		if err != nil {
			return err
		}
		cfg.BinaryPath = exe
	}
	return nil
}

// ErrNotSupported is returned on platforms without a service implementation.
var ErrNotSupported = errors.New("native service management not supported on this platform")
