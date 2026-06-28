//go:build windows

// Package collect selects the inventory Collector for the host OS at build time.
package collect

import (
	"github.com/williamsouzadelima/suricatoos-infra/agent/internal/inventory"
	"github.com/williamsouzadelima/suricatoos-infra/agent/internal/inventory/windows"
)

// New returns the inventory Collector for this Windows host.
func New() (inventory.Collector, error) {
	return windows.New(), nil
}
