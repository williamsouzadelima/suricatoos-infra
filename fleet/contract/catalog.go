package contract

import (
	"crypto/sha256"
	"encoding/hex"
	"slices"
)

// CatalogEntry is one command type of the closed v1 catalog (ADR-0011 "Catálogo de comandos v1"), as DATA for the
// connector's line 7 (unsupported, type_not_allowed, rate_limited) and for the hub.
type CatalogEntry struct {
	Type    CommandType
	Payload string // fleet-command.schema.json#/$defs/<Payload>
	Output  string // fleet-result.schema.json#/$defs/<Output>
	// OptIn: false = allowed by the default policy ("permitido"); true = only once the LOCAL operator adds it to
	// policy.json "allow" (schedule.create with task_ids also needs task.modify allowed: checked by the policy).
	OptIn bool
	// Sensitive: counts in sensitive_per_hour (opt-in + report.export + report.summary); every accepted command
	// also counts in total_per_hour.
	Sensitive bool
	NodeKinds []NodeKind // node kinds that support the type (else: unsupported)
}

var allNodeKinds = []NodeKind{NodeCentral, NodeStandalone, NodeSensor}

var catalog = []CatalogEntry{
	{TypeStateResync, "payload_state_resync", "output_state_resync", false, false, allNodeKinds},
	{TypeTaskStart, "payload_task_ref", "output_task_action", false, false, allNodeKinds},
	{TypeTaskStop, "payload_task_ref", "output_task_action", false, false, allNodeKinds},
	{TypeTaskResume, "payload_task_ref", "output_task_action", false, false, allNodeKinds},
	{TypeTaskCreate, "payload_task_create", "output_task_create", true, true, allNodeKinds},
	{TypeTaskModify, "payload_task_modify", "output_task_modify", true, true, allNodeKinds},
	{TypeTaskClone, "payload_task_clone", "output_task_clone", true, true, allNodeKinds},
	{TypeTaskDelete, "payload_task_ref", "output_trash", true, true, allNodeKinds},
	{TypeTargetCreate, "payload_target_create", "output_target_create", true, true, allNodeKinds},
	{TypeTargetModify, "payload_target_modify", "output_target_modify", true, true, allNodeKinds},
	{TypeTargetDelete, "payload_target_ref", "output_trash", true, true, allNodeKinds},
	{TypeScheduleCreate, "payload_schedule_create", "output_schedule_create", true, true, allNodeKinds},
	{TypeScheduleModify, "payload_schedule_modify", "output_schedule_modify", true, true, allNodeKinds},
	{TypeScheduleDelete, "payload_schedule_ref", "output_trash", true, true, allNodeKinds},
	{TypeReportExport, "payload_report_export", "output_report_export", false, true, allNodeKinds},
	{TypeReportSummary, "payload_report_summary", "output_report_summary", false, true, allNodeKinds},
	{TypeAgentScanNow, "payload_agent_ref", "output_agent_scan_now", false, false, []NodeKind{NodeCentral}},
	{TypeAgentRevoke, "payload_agent_revoke", "output_agent_revoke", true, true, []NodeKind{NodeCentral}},
	{TypeEnrollTokenCreate, "payload_enroll_token_create", "output_enroll_token_create", true, true, []NodeKind{NodeCentral}},
	{TypeEnrollTokenRevoke, "payload_enroll_token_revoke", "output_enroll_token_revoke", true, true, []NodeKind{NodeCentral}},
	{TypeSensorJobEnqueue, "payload_sensor_job_enqueue", "output_sensor_job_enqueue", true, true, []NodeKind{NodeCentral}},
	{TypeFeedSyncNow, "payload_empty", "output_feed_sync_now", true, true, []NodeKind{NodeCentral, NodeStandalone}},
}

// Defaults of the local policy when FLEET_STATE_DIR/policy.json does not exist.
const (
	DefaultSensitivePerHour = 30
	DefaultTotalPerHour     = 120
)

// Catalog returns (a copy of) the v1 catalog, in schema order.
func Catalog() []CatalogEntry {
	out := slices.Clone(catalog)
	for i := range out {
		out[i].NodeKinds = slices.Clone(out[i].NodeKinds)
	}
	return out
}

// LookupType returns the catalog entry of t; ok is false for a type outside the v1 catalog (line 7:
// unsupported).
func LookupType(t CommandType) (CatalogEntry, bool) {
	for _, e := range catalog {
		if e.Type == t {
			e.NodeKinds = slices.Clone(e.NodeKinds)
			return e, true
		}
	}
	return CatalogEntry{}, false
}

// Supports reports whether a node of kind k can execute the type.
func (e CatalogEntry) Supports(k NodeKind) bool { return slices.Contains(e.NodeKinds, k) }

// SupportedTypes lists the types a node of kind k supports (data_node.capabilities.supported_types).
func SupportedTypes(k NodeKind) []CommandType {
	var out []CommandType
	for _, e := range catalog {
		if e.Supports(k) {
			out = append(out, e.Type)
		}
	}
	return out
}

// DefaultAllow lists the types allowed without a policy.json: the "permitido" ones supported by kind k.
func DefaultAllow(k NodeKind) []CommandType {
	var out []CommandType
	for _, e := range catalog {
		if !e.OptIn && e.Supports(k) {
			out = append(out, e.Type)
		}
	}
	return out
}

// DefaultPolicy is the local policy in force without FLEET_STATE_DIR/policy.json.
func DefaultPolicy(k NodeKind) Policy {
	return Policy{Allow: DefaultAllow(k), SensitivePerHour: DefaultSensitivePerHour, TotalPerHour: DefaultTotalPerHour}
}

// PolicySHA256 is data_node.policy_sha256 (and data_connector_started's): the SHA-256 of the policy as compact
// JSON with sorted keys and a sorted allow list, so the hub recomputes it from the state.
func PolicySHA256(p Policy) string {
	allow := slices.Clone(p.Allow)
	if allow == nil {
		allow = []CommandType{}
	}
	slices.Sort(allow)
	p.Allow = allow
	b, err := MarshalCompact(p) // Policy's members are declared in key order (locked by a test)
	if err != nil {
		panic(err) // unreachable: a struct of strings and ints
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
