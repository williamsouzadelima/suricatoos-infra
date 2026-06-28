//go:build darwin

package service

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

const (
	launchdLabel  = "com.suricatoos.agent"
	plistPath     = "/Library/LaunchDaemons/" + launchdLabel + ".plist"
	plistTemplate = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>com.suricatoos.agent</string>
	<key>ProgramArguments</key>
	<array>
		<string>%s</string>
		<string>run</string>
		<string>--state</string>
		<string>%s</string>
		<string>--ingest</string>
		<string>%s</string>
		<string>--queue</string>
		<string>%s</string>
		<string>--interval</string>
		<string>%s</string>
		<string>--max-queue</string>
		<string>%d</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
	<key>StandardOutPath</key>
	<string>/var/log/suricatoos-agent.log</string>
	<key>StandardErrorPath</key>
	<string>/var/log/suricatoos-agent.log</string>
</dict>
</plist>
`
)

func defaultStateDir() string { return "/var/lib/suricatoos-agent" }

// Install writes the launchd plist and bootstraps the daemon into the system domain.
func Install(cfg Config) error {
	if err := cfg.Defaults(); err != nil {
		return err
	}
	plist := fmt.Sprintf(plistTemplate,
		cfg.BinaryPath,
		cfg.StateDir,
		cfg.IngestURL,
		cfg.QueueDir,
		cfg.Interval,
		cfg.MaxQueue,
	)
	if err := os.WriteFile(plistPath, []byte(plist), 0o644); err != nil {
		return fmt.Errorf("write plist: %w", err)
	}
	// launchctl bootstrap system loads the daemon into the system domain.
	if out, err := exec.Command("launchctl", "bootstrap", "system", plistPath).CombinedOutput(); err != nil {
		return fmt.Errorf("launchctl bootstrap: %w\n%s", err, out)
	}
	return nil
}

// Uninstall removes the launchd daemon and its plist.
func Uninstall() error {
	exec.Command("launchctl", "bootout", "system/"+launchdLabel).Run() // best-effort
	os.Remove(plistPath)                                               // best-effort
	return nil
}

// Status returns the launchd service status.
func Status() (string, error) {
	out, err := exec.Command("launchctl", "print", "system/"+launchdLabel).Output()
	if err != nil {
		return "not loaded", nil
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, "state =") {
			return strings.TrimSpace(line), nil
		}
	}
	return strings.TrimSpace(string(out)), nil
}
