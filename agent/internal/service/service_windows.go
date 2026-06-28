//go:build windows

package service

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const windowsServiceName = "SuricatoosAgent"

func defaultStateDir() string {
	if pd := os.Getenv("PROGRAMDATA"); pd != "" {
		return pd + `\Suricatoos\agent`
	}
	return `C:\ProgramData\Suricatoos\agent`
}

// Install creates and starts the Windows service via the Service Control Manager.
func Install(cfg Config) error {
	if err := cfg.Defaults(); err != nil {
		return err
	}
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to SCM: %w", err)
	}
	defer m.Disconnect()

	// Build the command line the SCM will pass to the binary.
	args := []string{
		"run",
		"--state", cfg.StateDir,
		"--ingest", cfg.IngestURL,
		"--queue", cfg.QueueDir,
		"--interval", cfg.Interval.String(),
		"--max-queue", fmt.Sprintf("%d", cfg.MaxQueue),
	}
	s, err := m.CreateService(
		windowsServiceName,
		cfg.BinaryPath,
		mgr.Config{
			DisplayName: "Suricatoos Vulnerability Agent",
			Description: "Collects local vulnerability posture and reports to the Suricatoos platform.",
			StartType:   mgr.StartAutomatic,
		},
		args...,
	)
	if err != nil {
		return fmt.Errorf("create service: %w", err)
	}
	defer s.Close()
	return s.Start()
}

// Uninstall stops and removes the Windows service.
func Uninstall() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to SCM: %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(windowsServiceName)
	if err != nil {
		return nil // already removed
	}
	defer s.Close()
	s.Control(svc.Stop) // best-effort stop
	return s.Delete()
}

// svcStateName converts a svc.State to a human-readable string.
func svcStateName(s svc.State) string {
	switch s {
	case svc.Stopped:
		return "stopped"
	case svc.StartPending:
		return "start-pending"
	case svc.StopPending:
		return "stop-pending"
	case svc.Running:
		return "running"
	case svc.ContinuePending:
		return "continue-pending"
	case svc.PausePending:
		return "pause-pending"
	case svc.Paused:
		return "paused"
	default:
		return fmt.Sprintf("state(%d)", s)
	}
}

// Status returns the Windows service state as a string.
func Status() (string, error) {
	m, err := mgr.Connect()
	if err != nil {
		return "", fmt.Errorf("connect to SCM: %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(windowsServiceName)
	if err != nil {
		return "not installed", nil
	}
	defer s.Close()
	st, err := s.Query()
	if err != nil {
		return "", err
	}
	return svcStateName(st.State), nil
}
