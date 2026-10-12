package contract

import "encoding/json"

// Result is the body of POST /fleet/v1/commands/{id}/result (fleet-result.schema.json#/$defs/result): the
// outcome of an ACCEPTED command. Output holds the exact bytes of the type's output_* object.
type Result struct {
	SchemaVersion  string          `json:"schema_version"`
	CommandID      string          `json:"command_id"`
	NodeID         string          `json:"node_id"`
	Type           CommandType     `json:"type"`
	Status         ResultStatus    `json:"status"`
	StartedAt      string          `json:"started_at"`
	FinishedAt     string          `json:"finished_at"`
	ContainsSecret bool            `json:"contains_secret"`
	Error          *ResultError    `json:"error,omitzero"`
	Output         json.RawMessage `json:"output,omitzero"`
	Artifacts      []Artifact      `json:"artifacts,omitzero"`
}

// Ack is the body of POST /fleet/v1/commands/{id}/ack (fleet-result.schema.json#/$defs/ack), sent only for
// authenticated envelopes (lines 3–9 and accepted).
type Ack struct {
	SchemaVersion string        `json:"schema_version"`
	CommandID     string        `json:"command_id"`
	NodeID        string        `json:"node_id"`
	Decision      Decision      `json:"decision"`
	Reason        *RejectReason `json:"reason,omitzero"`
	Detail        *string       `json:"detail,omitzero"`
	ReceivedAt    string        `json:"received_at"`
}

// SameAck reports whether two acks are the same for the hub's idempotency (ADR-0011 "Idempotência do ack",
// normative): same command_id, decision and reason. received_at, detail and the other members do not count,
// so a repeat with another received_at is answered 204, never 409.
func SameAck(a, b Ack) bool {
	if a.CommandID != b.CommandID || a.Decision != b.Decision {
		return false
	}
	if a.Reason == nil || b.Reason == nil {
		return a.Reason == nil && b.Reason == nil
	}
	return *a.Reason == *b.Reason
}

// ResultError is fleet-result.schema.json#/$defs/error.
type ResultError struct {
	Code    ErrorCode `json:"code"`
	Message string    `json:"message"`
}

// Artifact is fleet-result.schema.json#/$defs/artifact: an export already uploaded with
// PUT /fleet/v1/artifacts/{command_id}/{name}.
type Artifact struct {
	Name                string              `json:"name"`
	ContentEncoding     string              `json:"content_encoding"`
	Size                int64               `json:"size"`
	SHA256              string              `json:"sha256"`
	OriginalContentType ArtifactContentType `json:"original_content_type"`
	OriginalSize        int64               `json:"original_size"`
	OriginalSHA256      string              `json:"original_sha256"`
}

// OutputStateResync is the output of state.resync.
type OutputStateResync struct {
	Kinds []StateKind `json:"kinds"`
}

// OutputTaskAction is the output of task.start, task.stop and task.resume.
type OutputTaskAction struct {
	TaskID   string  `json:"task_id"`
	Status   string  `json:"status"`
	ReportID *string `json:"report_id,omitzero"`
}

// OutputTaskCreate is the output of task.create.
type OutputTaskCreate struct {
	TaskID string `json:"task_id"`
}

// OutputTaskModify is the output of task.modify.
type OutputTaskModify struct {
	TaskID  string            `json:"task_id"`
	Changed []TaskModifyField `json:"changed"`
	Before  TaskModifyBefore  `json:"before"`
}

// TaskModifyBefore holds the previous values of the changed fields (comment excluded).
type TaskModifyBefore struct {
	Name         *string `json:"name,omitzero"`
	TargetID     *string `json:"target_id,omitzero"`
	ScanConfigID *string `json:"scan_config_id,omitzero"`
	ScheduleID   *string `json:"schedule_id,omitzero"`
}

// OutputTaskClone is the output of task.clone.
type OutputTaskClone struct {
	SourceTaskID string `json:"source_task_id"`
	TaskID       string `json:"task_id"`
}

// OutputTrash is the output of task.delete, target.delete and schedule.delete (always to the trash).
type OutputTrash struct {
	ObjectID string `json:"object_id"`
	Trash    bool   `json:"trash"`
}

// OutputTargetCreate is the output of target.create.
type OutputTargetCreate struct {
	TargetID           string    `json:"target_id"`
	AliveTestEffective AliveTest `json:"alive_test_effective"`
}

// OutputTargetModify is the output of target.modify.
type OutputTargetModify struct {
	TargetID           string              `json:"target_id"`
	Changed            []TargetModifyField `json:"changed"`
	Before             TargetModifyBefore  `json:"before"`
	AliveTestEffective *AliveTest          `json:"alive_test_effective,omitzero"`
}

// TargetModifyBefore holds the previous values of the changed fields (comment excluded; hosts as literal
// entries only plus the count of non-literal ones; alive_test is the contract name of the set read from gvmd
// when it matches one, else the methods read joined with ", ").
type TargetModifyBefore struct {
	Name                   *string  `json:"name,omitzero"`
	Hosts                  []string `json:"hosts,omitzero"`
	HostsNonLiteralEntries *int64   `json:"hosts_non_literal_entries,omitzero"`
	ExcludeHosts           []string `json:"exclude_hosts,omitzero"`
	PortListID             *string  `json:"port_list_id,omitzero"`
	AliveTest              *string  `json:"alive_test,omitzero"`
}

// OutputScheduleCreate is the output of schedule.create.
type OutputScheduleCreate struct {
	ScheduleID    string   `json:"schedule_id"`
	LinkedTaskIDs []string `json:"linked_task_ids"`
}

// OutputScheduleModify is the output of schedule.modify.
type OutputScheduleModify struct {
	ScheduleID string                `json:"schedule_id"`
	Changed    []ScheduleModifyField `json:"changed"`
	Before     ScheduleModifyBefore  `json:"before"`
}

// ScheduleModifyBefore holds the previous values of the changed fields (comment excluded).
type ScheduleModifyBefore struct {
	Name      *string `json:"name,omitzero"`
	ICalendar *string `json:"icalendar,omitzero"`
	Timezone  *string `json:"timezone,omitzero"`
}

// OutputReportExport is the output of report.export (the artifact goes in Result.Artifacts).
type OutputReportExport struct {
	ReportID       string        `json:"report_id"`
	ReportFormatID string        `json:"report_format_id"`
	Format         ReportFormat  `json:"format"`
	Lang           ReportLang    `json:"lang"`
	Variant        ReportVariant `json:"variant"`
	DeltaReportID  *string       `json:"delta_report_id,omitzero"`
	ArtifactName   string        `json:"artifact_name"`
}

// OutputReportSummary is the output of report.summary: counts only.
type OutputReportSummary struct {
	ReportID       string         `json:"report_id"`
	TaskID         string         `json:"task_id"`
	ScanStatus     string         `json:"scan_status"`
	ScanStart      *string        `json:"scan_start,omitzero"`
	ScanEnd        *string        `json:"scan_end,omitzero"`
	FilterApplied  string         `json:"filter_applied"`
	Counts         SeverityCounts `json:"counts"`
	QoDHistogram   QoDHistogram   `json:"qod_histogram"`
	HostsCount     int64          `json:"hosts_count"`
	Hosts          []SummaryHost  `json:"hosts"`
	HostsTruncated bool           `json:"hosts_truncated"`
}

// QoDHistogram counts results per QoD band.
type QoDHistogram struct {
	Q0To29   int64 `json:"q0_29"`
	Q30To69  int64 `json:"q30_69"`
	Q70To100 int64 `json:"q70_100"`
}

// SummaryHost is the per-IP counts of a report.summary.
type SummaryHost struct {
	IP       string `json:"ip"`
	Critical int64  `json:"critical"`
	High     int64  `json:"high"`
	Medium   int64  `json:"medium"`
	Low      int64  `json:"low"`
	Log      int64  `json:"log"`
}

// OutputAgentScanNow is the output of agent.scan_now.
type OutputAgentScanNow struct {
	AgentID string `json:"agent_id"`
	Queued  bool   `json:"queued"`
}

// OutputAgentRevoke is the output of agent.revoke.
type OutputAgentRevoke struct {
	AgentID      string `json:"agent_id"`
	RevokedCerts int64  `json:"revoked_certs"`
}

// OutputEnrollTokenCreate is the output of enroll_token.create. Token is the ONLY secret of the contract
// (contains_secret=true): never written to disk, log or audit.
type OutputEnrollTokenCreate struct {
	TokenID   string      `json:"token_id"`
	Token     string      `json:"token"`
	TokenType TokenType   `json:"token_type"`
	Policy    AgentPolicy `json:"policy"`
	MaxUses   int         `json:"max_uses"`
	ExpiresAt string      `json:"expires_at"`
	CAPin     string      `json:"ca_pin"`
}

// OutputEnrollTokenRevoke is the output of enroll_token.revoke.
type OutputEnrollTokenRevoke struct {
	TokenID string `json:"token_id"`
	Revoked bool   `json:"revoked"`
}

// OutputSensorJobEnqueue is the output of sensor_job.enqueue.
type OutputSensorJobEnqueue struct {
	JobID         string `json:"job_id"`
	CorrelationID string `json:"correlation_id"`
}

// OutputFeedSyncNow is the output of feed.sync_now.
type OutputFeedSyncNow struct {
	Status FeedSyncStatus `json:"status"`
}
