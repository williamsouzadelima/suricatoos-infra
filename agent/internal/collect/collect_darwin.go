//go:build darwin

// Package collect selects the inventory Collector for the host OS at build time.
package collect

import (
	"github.com/williamsouzadelima/suricatoos-infra/agent/internal/inventory"
	"github.com/williamsouzadelima/suricatoos-infra/agent/internal/inventory/darwin"
)

// New returns the inventory Collector for this macOS host.
func New() (inventory.Collector, error) {
	return darwin.New(), nil
}
