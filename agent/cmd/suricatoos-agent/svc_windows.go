//go:build windows

package main

import (
	"context"
	"fmt"
	"os"

	"golang.org/x/sys/windows/svc"

	"github.com/williamsouzadelima/suricatoos-infra/agent/internal/agentd"
)

const winSvcName = "SuricatoosAgent"

// isWindowsService returns true when the process was started by the Windows SCM.
func isWindowsService() bool {
	ok, err := svc.IsWindowsService()
	return err == nil && ok
}

// runWindowsSvc wraps the agent daemon in the Windows Service Control Manager
// protocol. args must start with "run" followed by the daemon flags.
func runWindowsSvc(args []string) {
	if len(args) == 0 || args[0] != "run" {
		fmt.Fprintf(os.Stderr, "svc: expected 'run' subcommand, got %v\n", args)
		os.Exit(1)
	}
	ag, err := buildAgent(args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, "svc: build agent:", err)
		os.Exit(1)
	}
	ctx, cancel := context.WithCancel(context.Background())
	if err := svc.Run(winSvcName, &svcHandler{ag: ag, cancel: cancel, ctx: ctx}); err != nil {
		fmt.Fprintln(os.Stderr, "svc: run:", err)
		os.Exit(1)
	}
}

// svcHandler implements svc.Handler for the Suricatoos Agent Windows service.
type svcHandler struct {
	ag     *agentd.Agent
	cancel context.CancelFunc
	ctx    context.Context
}

func (h *svcHandler) Execute(_ []string, r <-chan svc.ChangeRequest, s chan<- svc.Status) (bool, uint32) {
	s <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	done := make(chan struct{})
	go func() {
		h.ag.Run(h.ctx)
		close(done)
	}()
	for {
		select {
		case c := <-r:
			switch c.Cmd {
			case svc.Stop, svc.Shutdown:
				s <- svc.Status{State: svc.StopPending}
				h.cancel()
				<-done
				return false, 0
			}
		case <-done:
			return false, 0
		}
	}
}
