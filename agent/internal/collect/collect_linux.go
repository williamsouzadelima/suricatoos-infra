//go:build linux

// Package collect selects the inventory Collector for the host OS at build time.
package collect

import (
	"github.com/williamsouzadelima/suricatoos-infra/agent/internal/inventory"
	"github.com/williamsouzadelima/suricatoos-infra/agent/internal/inventory/linux"
)

// New returns the inventory Collector for this host.
func New() (inventory.Collector, error) {
	return linux.New(), nil
}
