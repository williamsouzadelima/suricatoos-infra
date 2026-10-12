package contract

import "encoding/json"

// Conventions of every body type (enforced by the parity test against the schemas):
//   - one struct per object of a schema, its fields in the schema's property order, the json tag = the exact
//     property name;
//   - a REQUIRED property has a tag without options; an OPTIONAL one has ",omitzero" and a nil-able type
//     (pointer, slice, map or json.RawMessage), so "absent" and "present but empty" ("", [], 0, false) stay
//     distinct after a decode — the schemas give them different meanings (e.g. schedule_id "" unlinks);
//   - an enum is a named string type whose constants are exactly the enum; integers are int/int64 (decoded
//     only from integer literals), numbers float64;
//   - a free JSON object of the schema (the command payload, a state's data, an event's data, a result's
//     output) is a json.RawMessage holding the exact bytes as transmitted: hashes cover those bytes.

// Command is the signed command envelope (fleet-command.schema.json#/$defs/command, and #/$defs/envelope, the
// same members as line 0 checks them). The field order is the order of the ADR-0011 worked example, which Sign
// reproduces. The first ten fields are the signed ones (Canonical); Payload holds the exact raw bytes of the
// payload value as received (payload_sha256 covers them) and Signature the standard base64 of the Ed25519
// signature over the canonical form.
type Command struct {
	SchemaVersion string          `json:"schema_version"`
	CommandID     string          `json:"command_id"`
	NodeID        string          `json:"node_id"`
	Tenant        string          `json:"tenant"`
	Type          CommandType     `json:"type"`
	IssuedBy      string          `json:"issued_by"`
	IssuedAt      string          `json:"issued_at"`
	NotAfter      string          `json:"not_after"`
	Nonce         string          `json:"nonce"`
	PayloadSHA256 string          `json:"payload_sha256"`
	Payload       json.RawMessage `json:"payload"`
	Signature     string          `json:"signature"`
}

// PollResponse is the 200 body of GET /fleet/v1/commands (fleet-command.schema.json#/$defs/poll_response).
// Each command stays raw: every envelope goes through the verification lines on its own (DecodePollResponse,
// then VerifyAt per element), so one bad envelope never discards the others.
type PollResponse struct {
	Commands []json.RawMessage `json:"commands"`
}

// PayloadStateResync is the payload of state.resync.
type PayloadStateResync struct {
	Kinds []StateKind `json:"kinds"`
}

// PayloadTaskRef is the payload of task.start, task.stop, task.resume and task.delete.
type PayloadTaskRef struct {
	TaskID string `json:"task_id"`
}

// PayloadTaskCreate is the payload of task.create.
type PayloadTaskCreate struct {
	Name         string  `json:"name"`
	Comment      *string `json:"comment,omitzero"`
	TargetID     string  `json:"target_id"`
	ScanConfigID string  `json:"scan_config_id"`
	ScannerID    *string `json:"scanner_id,omitzero"`
	ScheduleID   *string `json:"schedule_id,omitzero"`
}

// PayloadTaskModify is the payload of task.modify. ScheduleID "" unlinks the schedule.
type PayloadTaskModify struct {
	TaskID       string  `json:"task_id"`
	Name         *string `json:"name,omitzero"`
	Comment      *string `json:"comment,omitzero"`
	TargetID     *string `json:"target_id,omitzero"`
	ScanConfigID *string `json:"scan_config_id,omitzero"`
	ScheduleID   *string `json:"schedule_id,omitzero"`
}

// PayloadTaskClone is the payload of task.clone.
type PayloadTaskClone struct {
	TaskID string  `json:"task_id"`
	Name   *string `json:"name,omitzero"`
}

// PayloadTargetCreate is the payload of target.create (exactly one of PortListID and PortRange).
type PayloadTargetCreate struct {
	Name         string     `json:"name"`
	Comment      *string    `json:"comment,omitzero"`
	Hosts        []string   `json:"hosts"`
	ExcludeHosts []string   `json:"exclude_hosts,omitzero"`
	PortListID   *string    `json:"port_list_id,omitzero"`
	PortRange    *string    `json:"port_range,omitzero"`
	AliveTest    *AliveTest `json:"alive_test,omitzero"`
}

// PayloadTargetModify is the payload of target.modify. Ports change only through PortListID: gvmd's
// modify_target has no port_range.
type PayloadTargetModify struct {
	TargetID     string     `json:"target_id"`
	Name         *string    `json:"name,omitzero"`
	Comment      *string    `json:"comment,omitzero"`
	Hosts        []string   `json:"hosts,omitzero"`
	ExcludeHosts []string   `json:"exclude_hosts,omitzero"`
	PortListID   *string    `json:"port_list_id,omitzero"`
	AliveTest    *AliveTest `json:"alive_test,omitzero"`
}

// PayloadTargetRef is the payload of target.delete.
type PayloadTargetRef struct {
	TargetID string `json:"target_id"`
}

// PayloadScheduleCreate is the payload of schedule.create.
type PayloadScheduleCreate struct {
	Name      string   `json:"name"`
	Comment   *string  `json:"comment,omitzero"`
	ICalendar string   `json:"icalendar"`
	Timezone  string   `json:"timezone"`
	TaskIDs   []string `json:"task_ids,omitzero"`
}

// PayloadScheduleModify is the payload of schedule.modify.
type PayloadScheduleModify struct {
	ScheduleID string  `json:"schedule_id"`
	Name       *string `json:"name,omitzero"`
	Comment    *string `json:"comment,omitzero"`
	ICalendar  *string `json:"icalendar,omitzero"`
	Timezone   *string `json:"timezone,omitzero"`
}

// PayloadScheduleRef is the payload of schedule.delete.
type PayloadScheduleRef struct {
	ScheduleID string `json:"schedule_id"`
}

// PayloadReportExport is the payload of report.export (gvm-* formats only as lang en + variant technical).
type PayloadReportExport struct {
	ReportID      string        `json:"report_id"`
	Format        ReportFormat  `json:"format"`
	Lang          ReportLang    `json:"lang"`
	Variant       ReportVariant `json:"variant"`
	DeltaReportID *string       `json:"delta_report_id,omitzero"`
	Filter        string        `json:"filter"`
}

// PayloadReportSummary is the payload of report.summary: fixed parameters, no free filter.
type PayloadReportSummary struct {
	ReportID       string `json:"report_id"`
	MinQoD         int    `json:"min_qod"`
	ApplyOverrides bool   `json:"apply_overrides"`
	Levels         string `json:"levels"`
}

// PayloadAgentRef is the payload of agent.scan_now.
type PayloadAgentRef struct {
	AgentID string `json:"agent_id"`
}

// PayloadAgentRevoke is the payload of agent.revoke.
type PayloadAgentRevoke struct {
	AgentID string  `json:"agent_id"`
	Reason  *string `json:"reason,omitzero"`
}

// PayloadEnrollTokenCreate is the payload of enroll_token.create (agent-endpoint tokens only).
type PayloadEnrollTokenCreate struct {
	TokenType TokenType   `json:"token_type"`
	Policy    AgentPolicy `json:"policy"`
	TTLHours  int         `json:"ttl_hours"`
	MaxUses   *int        `json:"max_uses,omitzero"`
}

// PayloadEnrollTokenRevoke is the payload of enroll_token.revoke.
type PayloadEnrollTokenRevoke struct {
	TokenID string `json:"token_id"`
}

// PayloadSensorJobEnqueue is the payload of sensor_job.enqueue.
type PayloadSensorJobEnqueue struct {
	Targets []string `json:"targets"`
	Ports   *string  `json:"ports,omitzero"`
}

// PayloadEmpty is the payload of feed.sync_now: the empty object.
type PayloadEmpty struct{}
