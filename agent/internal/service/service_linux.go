//go:build linux

package service

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const (
	unitPath     = "/etc/systemd/system/suricatoos-agent.service"
	unitTemplate = `[Unit]
Description=Suricatoos Vulnerability Agent
Documentation=https://github.com/williamsouzadelima/suricatoos-infra
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=600
StartLimitBurst=5

[Service]
Type=simple
ExecStart=%s run \
  --state %s \
  --ingest %s \
  --queue %s \
  --interval %s \
  --max-queue %d
Restart=always
RestartSec=30
StandardOutput=journal
StandardError=journal
SyslogIdentifier=suricatoos-agent

# Hardening (paridade com o pacote). O diretório do binário é RW para o
# auto-update assinado poder trocar o próprio binário; o resto fica read-only.
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=%s %s
ProtectHome=yes
PrivateTmp=yes
ProtectKernelTunables=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes

[Install]
WantedBy=multi-user.target
`
)

func defaultStateDir() string { return "/var/lib/suricatoos-agent" }

// Install writes the systemd unit file and enables + starts the service.
func Install(cfg Config) error {
	if err := cfg.Defaults(); err != nil {
		return err
	}
	unit := fmt.Sprintf(unitTemplate,
		cfg.BinaryPath,
		cfg.StateDir,
		cfg.IngestURL,
		cfg.QueueDir,
		cfg.Interval,
		cfg.MaxQueue,
		cfg.StateDir,                 // ReadWritePaths: state dir
		filepath.Dir(cfg.BinaryPath), // ReadWritePaths: binary dir (p/ auto-update)
	)
	if err := os.WriteFile(unitPath, []byte(unit), 0o644); err != nil {
		return fmt.Errorf("write unit file: %w", err)
	}
	for _, args := range [][]string{
		{"daemon-reload"},
		{"enable", "--now", ServiceName},
	} {
		if out, err := exec.Command("systemctl", args...).CombinedOutput(); err != nil {
			return fmt.Errorf("systemctl %s: %w\n%s", strings.Join(args, " "), err, out)
		}
	}
	return nil
}

// Uninstall stops, disables and removes the systemd unit.
func Uninstall() error {
	for _, args := range [][]string{
		{"stop", ServiceName},
		{"disable", ServiceName},
	} {
		exec.Command("systemctl", args...).Run() // best-effort
	}
	os.Remove(unitPath) // best-effort
	exec.Command("systemctl", "daemon-reload").Run()
	return nil
}

// Status returns the systemd service status string.
func Status() (string, error) {
	out, err := exec.Command("systemctl", "is-active", ServiceName).Output()
	return strings.TrimSpace(string(out)), err
}
