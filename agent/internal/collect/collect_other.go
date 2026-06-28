//go:build !linux

// Package collect selects the inventory Collector for the host OS at build time.
package collect

import (
	"errors"
	"runtime"

	"github.com/williamsouzadelima/suricatoos-infra/agent/internal/inventory"
)

// New returns the inventory Collector for this host. The macOS and Windows
// collectors arrive in Fase 3.
func New() (inventory.Collector, error) {
	return nil, errors.New("coletor de inventário ainda não disponível para " + runtime.GOOS + " (Fase 3)")
}
