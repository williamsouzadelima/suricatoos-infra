package state

import (
	"slices"

	"github.com/williamsouzadelima/suricatoos-infra/fleet/contract"
	"github.com/williamsouzadelima/suricatoos-infra/fleet/internal/tenant"
)

// Observation is what one complete collection cycle found, delivered to Config.Observe at its end: the input of the
// event transitions (package events).
type Observation struct {
	// Kinds holds every kind whose collection gave a new snapshot in this cycle. A kind whose source failed is absent:
	// it keeps its last snapshot (Current), but nothing new was seen of it.
	Kinds map[contract.StateKind]Observed
}

// Observed is one kind of an Observation.
type Observed struct {
	// Snapshot is the kind's new snapshot. Its Data is the Collector's own: read it, never change it.
	Snapshot Snapshot
	// Tenants are, sorted, the tenants whose objects the kind lists: those its collection attributed objects to — an
	// enabled tenant with a valid name and, for the gvmd kinds, a gvmd user of its own (gvmOwners). An object of any
	// other tenant is only counted, so a tenant that enters or leaves this set makes its objects appear in, or vanish
	// from, the list without any change of theirs. Empty (not nil) when the kind attributes to no tenant; nil for node,
	// scope and audit_tail, which attribute nothing.
	Tenants []string
	// Partial: the snapshot is new, but was built without one of its sources — the node without gvmd, whose feeds are
	// then unknown, not absent.
	Partial bool
}

// attributed returns, sorted, the tenants a kind attributes objects to under the listing of a cycle — the domain of
// the kind's known check: the owners' tenants for the gvmd kinds, the enabled tenants for the control-plane kinds; nil
// for the kinds that attribute nothing.
func attributed(kind contract.StateKind, list []tenant.Listing) []string {
	var names map[string]bool
	switch kind {
	case contract.KindTasks, contract.KindTargets, contract.KindSchedules, contract.KindReports:
		names = ownerTenants(gvmOwners(list))
	case contract.KindAgents, contract.KindTokens, contract.KindSensors, contract.KindScanRequests,
		contract.KindRemediation:
		names = enabledTenants(list)
	default:
		return nil
	}
	out := make([]string, 0, len(names))
	for name := range names {
		out = append(out, name)
	}
	slices.Sort(out)
	return out
}
