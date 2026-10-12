package state

import (
	"context"

	"github.com/williamsouzadelima/suricatoos-infra/fleet/contract"
)

// ControlPlane is the central node's admin API (slice F2.2) as the state reads it: one listing per kind. The items
// come in the contract's shape — types with no member for a secret, a created_by, a separate hostname, an inventory,
// a payload, a signature or the targets of a job (D4) — and Tenant is what the control-plane says: the O of the
// agent's or sensor's certificate, the token's Scope.Tenant, the job's tenant, "" for an ADR-0006 loop request
// (only counted). The state attributes and checks every item again before anything leaves. The HTTP client arrives
// with slice F2.2; until then only the tests implement it.
type ControlPlane interface {
	Agents(ctx context.Context) ([]contract.AgentItem, error)
	Tokens(ctx context.Context) ([]contract.TokenItem, error)
	Sensors(ctx context.Context) ([]contract.SensorItem, error)
	ScanRequests(ctx context.Context) ([]contract.ScanRequestItem, error)
	Remediation(ctx context.Context) ([]contract.RemediationItem, error)
}
