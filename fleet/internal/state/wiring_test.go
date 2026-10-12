package state

import (
	"github.com/williamsouzadelima/suricatoos-infra/fleet/internal/audit"
	"github.com/williamsouzadelima/suricatoos-infra/fleet/internal/replay"
	"github.com/williamsouzadelima/suricatoos-infra/fleet/internal/tenant"
)

// O conector (F2.6) liga o Collector às peças reais das fatias anteriores: o tenant.Source, o log da auditoria e o
// store anti-replay já têm o que as interfaces do estado pedem.
var (
	_ Tenants     = tenant.Source(nil)
	_ AuditTail   = (*audit.Log)(nil)
	_ ReplayFloor = (*replay.Store)(nil)
)
