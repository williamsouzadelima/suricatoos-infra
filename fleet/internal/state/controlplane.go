package state

import (
	"context"
	"slices"

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

// knownTenants is the check of a control-plane item's tenant: an ENABLED tenant of the node's listing whose name
// matches the tenant pattern. The items of a disabled tenant are only counted, like those of an unknown one (the
// scope kind still shows the tenant, with enabled false).
func (c *Collector) knownTenants(cyc *cycle) (func(string) bool, error) {
	list, err := c.listing(cyc)
	if err != nil {
		return nil, err
	}
	names := make(map[string]bool, len(list))
	for _, l := range list {
		if l.Enabled && ruleTenant.ok(l.Name) {
			names[l.Name] = true
		}
	}
	return func(t string) bool { return names[t] }, nil
}

// cpList reads one control-plane listing and finishes it.
func cpList[T any](c *Collector, ctx context.Context, cyc *cycle, spec listSpec[T],
	read func(context.Context) ([]T, error)) ([]byte, error) {
	known, err := c.knownTenants(cyc)
	if err != nil {
		return nil, err
	}
	items, err := read(ctx)
	if err != nil {
		return nil, err
	}
	return finishList(spec, items, false, 0, known, c.dataLimit)
}

// idTenant is the sort key of items whose id may repeat across tenants (an agent's hostname): (id, tenant). The id
// has no control character, so the NUL separator keeps the order of the pair.
func idTenant(id, tenantName string) string { return id + "\x00" + tenantName }

var agentSpec = listSpec[contract.AgentItem]{
	max:    maxAgents,
	tenant: func(i *contract.AgentItem) string { return i.Tenant },
	valid: func(i *contract.AgentItem) bool {
		policyOK := i.Policy == nil || *i.Policy == contract.PolicyAgentEndpoint ||
			*i.Policy == contract.PolicyScannerSensor
		return ruleAgentID.ok(i.AgentID) && policyOK && ruleOSArch.opt(i.OS) && ruleOSArch.opt(i.Arch) &&
			ruleVersion.opt(i.AgentVersion) && ruleUTC.opt(i.LastSeen)
	},
	key: func(i *contract.AgentItem) string { return idTenant(i.AgentID, i.Tenant) },
	wrap: func(items []contract.AgentItem, tr bool, u int64) any {
		return contract.DataAgents{Items: items, Truncated: tr, UnattributedCount: u}
	},
}

var tokenSpec = listSpec[contract.TokenItem]{
	max:    maxTokens,
	tenant: func(i *contract.TokenItem) string { return i.Tenant },
	valid: func(i *contract.TokenItem) bool {
		return ruleTokenID.ok(i.TokenID) &&
			(i.TokenType == contract.TokenSingleHost || i.TokenType == contract.TokenDeployment) &&
			ruleTokenPolicy.opt(i.Policy) && i.MaxUses >= 1 && i.Remaining >= 0 && ruleUTC.ok(i.ExpiresAt)
	},
	key: func(i *contract.TokenItem) string { return i.TokenID },
	wrap: func(items []contract.TokenItem, tr bool, u int64) any {
		return contract.DataTokens{Items: items, Truncated: tr, UnattributedCount: u}
	},
}

var sensorSpec = listSpec[contract.SensorItem]{
	max:    maxSensors,
	tenant: func(i *contract.SensorItem) string { return i.Tenant },
	valid: func(i *contract.SensorItem) bool {
		return ruleAgentID.ok(i.SensorID) && ruleUTC.opt(i.LastSeen) && ruleVersion.opt(i.FeedVersion) &&
			optNonNegative(i.ActiveJobs)
	},
	key: func(i *contract.SensorItem) string { return idTenant(i.SensorID, i.Tenant) },
	wrap: func(items []contract.SensorItem, tr bool, u int64) any {
		return contract.DataSensors{Items: items, Truncated: tr, UnattributedCount: u}
	},
}

var scanRequestStates = []contract.ScanRequestState{contract.ScanRequestPending, contract.ScanRequestDelivered,
	contract.ScanRequestAcked, contract.ScanRequestDone, contract.ScanRequestExpired}

var scanRequestSpec = listSpec[contract.ScanRequestItem]{
	max:    maxScanRequests,
	tenant: func(i *contract.ScanRequestItem) string { return i.Tenant },
	valid: func(i *contract.ScanRequestItem) bool {
		return ruleJobID.ok(i.JobID) && slices.Contains(scanRequestStates, i.State) && i.TargetsCount >= 0 &&
			ruleUTC.ok(i.CreatedAt) && ruleUTC.opt(i.ExpiresAt)
	},
	key: func(i *contract.ScanRequestItem) string { return i.JobID },
	wrap: func(items []contract.ScanRequestItem, tr bool, u int64) any {
		return contract.DataScanRequests{Items: items, Truncated: tr, UnattributedCount: u}
	},
}

var remediationStates = []contract.RemediationState{contract.RemediationPendingApproval, contract.RemediationApproved,
	contract.RemediationDelivered, contract.RemediationAcked, contract.RemediationApplied, contract.RemediationFailed,
	contract.RemediationVerified, contract.RemediationExpired, contract.RemediationRejected}

var remediationSpec = listSpec[contract.RemediationItem]{
	max:    maxRemediation,
	tenant: func(i *contract.RemediationItem) string { return i.Tenant },
	valid: func(i *contract.RemediationItem) bool {
		return ruleJobID.ok(i.JobID) && ruleAgentID.ok(i.AgentID) &&
			(i.Type == contract.RemediationPackagePatch || i.Type == contract.RemediationConfigHardening) &&
			slices.Contains(remediationStates, i.State) && ruleUTC.ok(i.CreatedAt) && ruleUTC.opt(i.ApprovedAt) &&
			ruleUTC.opt(i.ExpiresAt)
	},
	key: func(i *contract.RemediationItem) string { return i.JobID },
	wrap: func(items []contract.RemediationItem, tr bool, u int64) any {
		return contract.DataRemediation{Items: items, Truncated: tr, UnattributedCount: u}
	},
}
