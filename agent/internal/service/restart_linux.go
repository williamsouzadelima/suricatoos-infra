//go:build linux

package service

import (
	"fmt"
	"os/exec"
)

// Restart bounces the systemd service so a freshly-swapped binary takes effect.
// systemd re-execs the new binary at the unit's ExecStart path.
func Restart() error {
	if out, err := exec.Command("systemctl", "restart", ServiceName).CombinedOutput(); err != nil {
		return fmt.Errorf("systemctl restart %s: %w\n%s", ServiceName, err, out)
	}
	return nil
}
