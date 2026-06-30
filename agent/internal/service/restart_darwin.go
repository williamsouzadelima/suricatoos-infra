//go:build darwin

package service

import (
	"fmt"
	"os/exec"
)

// Restart kickstarts the launchd daemon; -k kills the running instance first so
// launchd relaunches it from the (now updated) binary path.
func Restart() error {
	if out, err := exec.Command("launchctl", "kickstart", "-k", "system/"+launchdLabel).CombinedOutput(); err != nil {
		return fmt.Errorf("launchctl kickstart system/%s: %w\n%s", launchdLabel, err, out)
	}
	return nil
}
