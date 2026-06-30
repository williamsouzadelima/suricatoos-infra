//go:build windows

package service

import (
	"fmt"
	"os/exec"
	"syscall"
)

// Restart bounces the SCM service. The agent IS the service, so stopping itself
// inline would kill this process before the start ran. Instead a DETACHED helper
// waits briefly, then stop+start via SCM — surviving our own termination.
func Restart() error {
	cmd := exec.Command("cmd", "/C",
		"timeout /t 2 /nobreak >nul & net stop "+windowsServiceName+" & net start "+windowsServiceName)
	// DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP — outlive the stopping service.
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: 0x00000008 | 0x00000200}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("agendar restart do serviço %s: %w", windowsServiceName, err)
	}
	return nil
}
