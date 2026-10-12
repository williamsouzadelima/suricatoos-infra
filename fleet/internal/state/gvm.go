package state

import (
	"context"
	"slices"

	"github.com/williamsouzadelima/suricatoos-infra/fleet/contract"
	"github.com/williamsouzadelima/suricatoos-infra/fleet/internal/tenant"
)

// GVM is the gvmd side of the state: fleet_ops.py's state.* reads (Bridge in production, a fake in the tests). The
// list reads take owners, the gvmd user of each enabled tenant mapped to its name (gvmOwners; fleet_ops attributes
// every object by its owner and only counts the rest), and return the kind's data as fleet_ops built it; the state
// checks it all again before anything leaves.
type GVM interface {
	Node(ctx context.Context, req NodeRequest) (contract.DataNode, error)
	Tasks(ctx context.Context, owners map[string]string) (contract.DataTasks, error)
	Targets(ctx context.Context, owners map[string]string) (contract.DataTargets, error)
	Schedules(ctx context.Context, owners map[string]string) (contract.DataSchedules, error)
	Reports(ctx context.Context, owners map[string]string) (contract.DataReports, error)
}

// NodeRequest is the payload of fleet_ops' state.node: the members of data_node the connector owns. fleet_ops
// adds the ones gvmd owns (versions.gmp_protocol and python_gvm, feeds, health.status and gvmd_up,
// capabilities.report_formats) and echoes these.
type NodeRequest struct {
	NodeKind         contract.NodeKind      `json:"node_kind"`
	ConnectorVersion string                 `json:"connector_version"`
	Policy           contract.Policy        `json:"policy"`
	PolicySHA256     string                 `json:"policy_sha256"`
	ReplayFloor      string                 `json:"replay_floor"`
	SupportedTypes   []contract.CommandType `json:"supported_types"`
	StateKinds       []contract.StateKind   `json:"state_kinds"`
	Versions         *LocalVersions         `json:"versions,omitzero"`
	Health           *LocalHealth           `json:"health,omitzero"`
}

// LocalVersions are the versions the connector is told (gvmd, openvas_scanner, gsa, control_plane); nil = unknown.
type LocalVersions struct {
	GVMD           *string `json:"gvmd,omitzero"`
	OpenVASScanner *string `json:"openvas_scanner,omitzero"`
	GSA            *string `json:"gsa,omitzero"`
	ControlPlane   *string `json:"control_plane,omitzero"`
}

// LocalHealth is the health the connector measures on its own; nil = unknown.
type LocalHealth struct {
	ScannerUp *bool `json:"scanner_up,omitzero"`
	// DiskFreePct is sent in whole percent (rounded down): a finer value would change the node kind — and send it
	// again — at almost every cycle.
	DiskFreePct  *float64 `json:"disk_free_pct,omitzero"`
	ActiveTasks  *int64   `json:"active_tasks,omitzero"`
	ClockOffsetS *int64   `json:"clock_offset_s,omitzero"`
}

// ownerRule is what fleet_ops accepts as a key of owners (its _c_text(256, 1)): 1 to 256 characters, no control
// character, U+FFFE or U+FFFF. A key it would refuse would fail the whole read, so such a user is left out here.
var ownerRule = newRule(1, 256, "", nil)

// gvmOwners maps the gvmd user of each enabled tenant to the tenant (the owners of fleet_ops' state.* reads), in two
// passes. The first counts the claimants of every gvmd user over the WHOLE registry — every record with a usable
// user, whatever its name or enabled flag. The second maps a user only when its single claimant has a valid tenant
// name and is enabled. So the objects of a user that two records share are only counted — the fleet never guesses
// which one owns an object, even when one of them is outside the fleet (an invalid name, a disabled tenant) —, and
// so are those of a disabled tenant, of an invalid name, of a tenant without a gvmd user and of a user fleet_ops
// would refuse (such a user is never a key of owners).
func gvmOwners(list []tenant.Listing) map[string]string {
	claims := map[string]int{}
	for _, l := range list {
		if ownerRule.ok(l.GVMUser) {
			claims[l.GVMUser]++
		}
	}
	owners := map[string]string{}
	for _, l := range list {
		if ownerRule.ok(l.GVMUser) && claims[l.GVMUser] == 1 && l.Enabled && ruleTenant.ok(l.Name) {
			owners[l.GVMUser] = l.Name
		}
	}
	return owners
}

// gvmOwners returns, for this cycle, the owners map and the check of an item's tenant: one of the tenants the map
// names, so an item fleet_ops attributed to anything else is only counted.
func (c *Collector) gvmOwners(cyc *cycle) (map[string]string, func(string) bool, error) {
	list, err := c.listing(cyc)
	if err != nil {
		return nil, nil, err
	}
	owners := gvmOwners(list)
	names := make(map[string]bool, len(owners))
	for _, name := range owners {
		names[name] = true
	}
	return owners, func(t string) bool { return names[t] }, nil
}

var taskSpec = listSpec[contract.TaskItem]{
	max:    maxTasks,
	tenant: func(i *contract.TaskItem) string { return i.Tenant },
	valid:  validTask,
	key:    func(i *contract.TaskItem) string { return i.TaskID },
	wrap: func(items []contract.TaskItem, tr bool, u int64) any {
		return contract.DataTasks{Items: items, Truncated: tr, UnattributedCount: u}
	},
}

func validTask(i *contract.TaskItem) bool {
	return ruleUUID.ok(i.TaskID) && ruleName.ok(i.Name) && ruleStatus.ok(i.Status) &&
		(i.Progress == nil || (*i.Progress >= -1 && *i.Progress <= 100)) &&
		ruleUUID.opt(i.TargetID) && ruleUUID.opt(i.ScanConfigID) && ruleUUID.opt(i.ScannerID) &&
		ruleUUID.opt(i.ScheduleID) && ruleUUID.opt(i.LastReportID) && ruleUTC.opt(i.LastReportAt) && i.ReportCount >= 0
}

var targetSpec = listSpec[contract.TargetItem]{
	max:     maxTargets,
	tenant:  func(i *contract.TargetItem) string { return i.Tenant },
	prepare: prepareTarget,
	valid:   validTarget,
	key:     func(i *contract.TargetItem) string { return i.TargetID },
	wrap: func(items []contract.TargetItem, tr bool, u int64) any {
		return contract.DataTargets{Items: items, Truncated: tr, UnattributedCount: u}
	},
}

// prepareTarget keeps the first 256 hosts (literal_entries keeps the total, so the cut needs no truncated).
func prepareTarget(i *contract.TargetItem) bool {
	if i.Hosts == nil {
		i.Hosts = []string{}
	}
	if len(i.Hosts) > maxTargetHosts {
		i.Hosts = i.Hosts[:maxTargetHosts]
	}
	return false
}

// validTarget lists only IP/CIDR literals: a hostname among the hosts makes the whole target count, never leave.
func validTarget(i *contract.TargetItem) bool {
	return ruleUUID.ok(i.TargetID) && ruleName.ok(i.Name) && len(i.Hosts) <= maxTargetHosts &&
		all(i.Hosts, ruleIPOrCIDR.ok) && nonNegative(i.LiteralEntries, i.NonLiteralEntries) &&
		optNonNegative(i.ExcludeEntries) && ruleUUID.opt(i.PortListID) && ruleAliveTest.opt(i.AliveTest)
}

var scheduleSpec = listSpec[contract.ScheduleItem]{
	max:     maxSchedules,
	tenant:  func(i *contract.ScheduleItem) string { return i.Tenant },
	prepare: prepareSchedule,
	valid:   validSchedule,
	key:     func(i *contract.ScheduleItem) string { return i.ScheduleID },
	wrap: func(items []contract.ScheduleItem, tr bool, u int64) any {
		return contract.DataSchedules{Items: items, Truncated: tr, UnattributedCount: u}
	},
}

// prepareSchedule sorts the linked task ids without repetition (uniqueItems) and keeps the first 256; that cut has
// no count of its own, so it marks the snapshot truncated.
func prepareSchedule(i *contract.ScheduleItem) bool {
	ids := slices.Clone(i.TaskIDs)
	slices.Sort(ids)
	ids = slices.Compact(ids)
	cut := len(ids) > maxScheduleTasks
	if cut {
		ids = ids[:maxScheduleTasks]
	}
	if ids == nil {
		ids = []string{}
	}
	i.TaskIDs = ids
	return cut
}

func validSchedule(i *contract.ScheduleItem) bool {
	return ruleUUID.ok(i.ScheduleID) && ruleName.ok(i.Name) && ruleTimezone.ok(i.Timezone) &&
		ruleICalendar.ok(i.ICalendar) && ruleUTC.opt(i.NextRun) && len(i.TaskIDs) <= maxScheduleTasks &&
		all(i.TaskIDs, ruleUUID.ok)
}

var reportSpec = listSpec[contract.ReportItem]{
	max:    maxReports,
	tenant: func(i *contract.ReportItem) string { return i.Tenant },
	valid:  validReport,
	key:    nil, // most recent first, as fleet_ops orders them (the item has no creation time to sort by)
	wrap: func(items []contract.ReportItem, tr bool, u int64) any {
		return contract.DataReports{Items: items, Truncated: tr, UnattributedCount: u}
	},
}

// validReport: metadata and counts only — the type has no member for a finding.
func validReport(i *contract.ReportItem) bool {
	n := i.Counts
	return ruleUUID.ok(i.ReportID) && ruleUUID.ok(i.TaskID) && ruleStatus.ok(i.ScanStatus) &&
		ruleUTC.opt(i.ScanStart) && ruleUTC.opt(i.ScanEnd) &&
		nonNegative(n.Critical, n.High, n.Medium, n.Low, n.Log, n.FalsePositive, i.HostsCount)
}

func (c *Collector) collectTasks(ctx context.Context, cyc *cycle) ([]byte, error) {
	owners, known, err := c.gvmOwners(cyc)
	if err != nil {
		return nil, err
	}
	d, err := c.cfg.GVM.Tasks(ctx, owners)
	if err != nil {
		return nil, err
	}
	return finishList(taskSpec, d.Items, d.Truncated, d.UnattributedCount, known, c.dataLimit)
}

func (c *Collector) collectTargets(ctx context.Context, cyc *cycle) ([]byte, error) {
	owners, known, err := c.gvmOwners(cyc)
	if err != nil {
		return nil, err
	}
	d, err := c.cfg.GVM.Targets(ctx, owners)
	if err != nil {
		return nil, err
	}
	return finishList(targetSpec, d.Items, d.Truncated, d.UnattributedCount, known, c.dataLimit)
}

func (c *Collector) collectSchedules(ctx context.Context, cyc *cycle) ([]byte, error) {
	owners, known, err := c.gvmOwners(cyc)
	if err != nil {
		return nil, err
	}
	d, err := c.cfg.GVM.Schedules(ctx, owners)
	if err != nil {
		return nil, err
	}
	return finishList(scheduleSpec, d.Items, d.Truncated, d.UnattributedCount, known, c.dataLimit)
}

func (c *Collector) collectReports(ctx context.Context, cyc *cycle) ([]byte, error) {
	owners, known, err := c.gvmOwners(cyc)
	if err != nil {
		return nil, err
	}
	d, err := c.cfg.GVM.Reports(ctx, owners)
	if err != nil {
		return nil, err
	}
	return finishList(reportSpec, d.Items, d.Truncated, d.UnattributedCount, known, c.dataLimit)
}
