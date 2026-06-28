// Package service integrates the agent as a native system service: systemd
// (Linux), launchd LaunchDaemon (macOS) and the Windows Service Control Manager,
// behind a cross-platform abstraction, running as a least-privilege service
// account. Linux in Fase 1; macOS/Windows in Fase 3.
package service
