package contract

import "encoding/json"

// StateSnapshot is the body of PUT /fleet/v1/state/{kind} (fleet-state.schema.json). Data holds the exact bytes
// of the kind's data_<kind> object: content_sha256 covers them.
type StateSnapshot struct {
	SchemaVersion string          `json:"schema_version"`
	NodeID        string          `json:"node_id"`
	Kind          StateKind       `json:"kind"`
	CollectedAt   string          `json:"collected_at"`
	ContentSHA256 string          `json:"content_sha256"`
	Data          json.RawMessage `json:"data"`
}

// SeverityCounts is fleet-state.schema.json#/$defs/severity_counts: counts only, never results.
type SeverityCounts struct {
	Critical      int64 `json:"critical"`
	High          int64 `json:"high"`
	Medium        int64 `json:"medium"`
	Low           int64 `json:"low"`
	Log           int64 `json:"log"`
	FalsePositive int64 `json:"false_positive"`
}

// DataNode is the data of the "node" kind.
type DataNode struct {
	NodeKind         NodeKind         `json:"node_kind"`
	ConnectorVersion string           `json:"connector_version"`
	Versions         NodeVersions     `json:"versions"`
	Feeds            []FeedStatus     `json:"feeds"`
	Health           NodeHealth       `json:"health"`
	Capabilities     NodeCapabilities `json:"capabilities"`
	Policy           Policy           `json:"policy"`
	PolicySHA256     string           `json:"policy_sha256"`
	ReplayFloor      string           `json:"replay_floor"`
}

// NodeVersions is data_node.versions.
type NodeVersions struct {
	GVMD           *string `json:"gvmd,omitzero"`
	GMPProtocol    *string `json:"gmp_protocol,omitzero"`
	PythonGVM      *string `json:"python_gvm,omitzero"`
	OpenVASScanner *string `json:"openvas_scanner,omitzero"`
	GSA            *string `json:"gsa,omitzero"`
	ControlPlane   *string `json:"control_plane,omitzero"`
}

// FeedStatus is an item of data_node.feeds.
type FeedStatus struct {
	Feed     FeedType `json:"feed"`
	Version  string   `json:"version"`
	AgeHours float64  `json:"age_hours"`
	Syncing  bool     `json:"syncing"`
}

// NodeHealth is data_node.health.
type NodeHealth struct {
	Status       HealthStatus `json:"status"`
	GVMDUp       bool         `json:"gvmd_up"`
	ScannerUp    *bool        `json:"scanner_up,omitzero"`
	DiskFreePct  *float64     `json:"disk_free_pct,omitzero"`
	ActiveTasks  *int64       `json:"active_tasks,omitzero"`
	ClockOffsetS *int64       `json:"clock_offset_s,omitzero"`
}

// NodeCapabilities is data_node.capabilities.
type NodeCapabilities struct {
	SupportedTypes []CommandType            `json:"supported_types"`
	StateKinds     []StateKind              `json:"state_kinds"`
	ReportFormats  []ReportFormatCapability `json:"report_formats"`
}

// ReportFormatCapability is a (format, lang, variants) the node can render for report.export.
type ReportFormatCapability struct {
	Format   ReportFormat    `json:"format"`
	Lang     ReportLang      `json:"lang"`
	Variants []ReportVariant `json:"variants"`
}

// Policy is the LOCAL policy in force: FLEET_STATE_DIR/policy.json, edited only on the node.
type Policy struct {
	Allow            []CommandType `json:"allow"`
	SensitivePerHour int           `json:"sensitive_per_hour"`
	TotalPerHour     int           `json:"total_per_hour"`
}

// DataTasks is the data of the "tasks" kind.
type DataTasks struct {
	Items             []TaskItem `json:"items"`
	Truncated         bool       `json:"truncated"`
	UnattributedCount int64      `json:"unattributed_count"`
}

// TaskItem is a gvmd task (no comment).
type TaskItem struct {
	TaskID       string  `json:"task_id"`
	Tenant       string  `json:"tenant"`
	Name         string  `json:"name"`
	Status       string  `json:"status"`
	Progress     *int    `json:"progress,omitzero"`
	TargetID     *string `json:"target_id,omitzero"`
	ScanConfigID *string `json:"scan_config_id,omitzero"`
	ScannerID    *string `json:"scanner_id,omitzero"`
	ScheduleID   *string `json:"schedule_id,omitzero"`
	LastReportID *string `json:"last_report_id,omitzero"`
	LastReportAt *string `json:"last_report_at,omitzero"`
	ReportCount  int64   `json:"report_count"`
}

// DataTargets is the data of the "targets" kind.
type DataTargets struct {
	Items             []TargetItem `json:"items"`
	Truncated         bool         `json:"truncated"`
	UnattributedCount int64        `json:"unattributed_count"`
}

// TargetItem is a gvmd target: literal entries only (hostnames are counted, never sent).
type TargetItem struct {
	TargetID          string   `json:"target_id"`
	Tenant            string   `json:"tenant"`
	Name              string   `json:"name"`
	Hosts             []string `json:"hosts"`
	LiteralEntries    int64    `json:"literal_entries"`
	NonLiteralEntries int64    `json:"non_literal_entries"`
	ExcludeEntries    *int64   `json:"exclude_entries,omitzero"`
	PortListID        *string  `json:"port_list_id,omitzero"`
	AliveTest         *string  `json:"alive_test,omitzero"`
	InUse             bool     `json:"in_use"`
}

// DataSchedules is the data of the "schedules" kind.
type DataSchedules struct {
	Items             []ScheduleItem `json:"items"`
	Truncated         bool           `json:"truncated"`
	UnattributedCount int64          `json:"unattributed_count"`
}

// ScheduleItem is a gvmd schedule.
type ScheduleItem struct {
	ScheduleID string   `json:"schedule_id"`
	Tenant     string   `json:"tenant"`
	Name       string   `json:"name"`
	Timezone   string   `json:"timezone"`
	ICalendar  string   `json:"icalendar"`
	NextRun    *string  `json:"next_run,omitzero"` // only when gvmd provides it (gvmd 26's get_schedules does not)
	TaskIDs    []string `json:"task_ids"`
}

// DataReports is the data of the "reports" kind.
type DataReports struct {
	Items             []ReportItem `json:"items"`
	Truncated         bool         `json:"truncated"`
	UnattributedCount int64        `json:"unattributed_count"`
}

// ReportItem is a gvmd report: metadata and counts, never findings.
type ReportItem struct {
	ReportID   string         `json:"report_id"`
	TaskID     string         `json:"task_id"`
	Tenant     string         `json:"tenant"`
	ScanStatus string         `json:"scan_status"`
	ScanStart  *string        `json:"scan_start,omitzero"`
	ScanEnd    *string        `json:"scan_end,omitzero"`
	Counts     SeverityCounts `json:"counts"`
	HostsCount int64          `json:"hosts_count"`
}

// DataAgents is the data of the "agents" kind (central only).
type DataAgents struct {
	Items             []AgentItem `json:"items"`
	Truncated         bool        `json:"truncated"`
	UnattributedCount int64       `json:"unattributed_count"`
}

// AgentItem is an enrolled endpoint agent. AgentID is by default the host's hostname: it may be personal data.
type AgentItem struct {
	AgentID      string       `json:"agent_id"`
	Tenant       string       `json:"tenant"`
	Policy       *AgentPolicy `json:"policy,omitzero"`
	OS           *string      `json:"os,omitzero"`
	Arch         *string      `json:"arch,omitzero"`
	AgentVersion *string      `json:"agent_version,omitzero"`
	LastSeen     *string      `json:"last_seen,omitzero"`
	Online       bool         `json:"online"`
}

// DataTokens is the data of the "tokens" kind (central only): bootstrap tokens without their secret.
type DataTokens struct {
	Items             []TokenItem `json:"items"`
	Truncated         bool        `json:"truncated"`
	UnattributedCount int64       `json:"unattributed_count"`
}

// TokenItem is a scanner bootstrap token without its secret.
type TokenItem struct {
	TokenID   string    `json:"token_id"`
	Tenant    string    `json:"tenant"`
	TokenType TokenType `json:"token_type"`
	Policy    *string   `json:"policy,omitzero"`
	MaxUses   int64     `json:"max_uses"`
	Remaining int64     `json:"remaining"`
	ExpiresAt string    `json:"expires_at"`
	Revoked   bool      `json:"revoked"`
}

// DataSensors is the data of the "sensors" kind (central only).
type DataSensors struct {
	Items             []SensorItem `json:"items"`
	Truncated         bool         `json:"truncated"`
	UnattributedCount int64        `json:"unattributed_count"`
}

// SensorItem is an ADR-0007 sensor enrolled into this node.
type SensorItem struct {
	SensorID    string  `json:"sensor_id"`
	Tenant      string  `json:"tenant"`
	LastSeen    *string `json:"last_seen,omitzero"`
	Online      bool    `json:"online"`
	FeedVersion *string `json:"feed_version,omitzero"`
	GVMDUp      *bool   `json:"gvmd_up,omitzero"`
	ActiveJobs  *int64  `json:"active_jobs,omitzero"`
}

// DataScanRequests is the data of the "scan_requests" kind (central only).
type DataScanRequests struct {
	Items             []ScanRequestItem `json:"items"`
	Truncated         bool              `json:"truncated"`
	UnattributedCount int64             `json:"unattributed_count"`
}

// ScanRequestItem is an ADR-0007 sensor job with the COUNT of its targets.
type ScanRequestItem struct {
	JobID        string           `json:"job_id"`
	Tenant       string           `json:"tenant"`
	State        ScanRequestState `json:"state"`
	TargetsCount int64            `json:"targets_count"`
	CreatedAt    string           `json:"created_at"`
	ExpiresAt    *string          `json:"expires_at,omitzero"`
}

// DataRemediation is the data of the "remediation" kind (central only, read-only in v1).
type DataRemediation struct {
	Items             []RemediationItem `json:"items"`
	Truncated         bool              `json:"truncated"`
	UnattributedCount int64             `json:"unattributed_count"`
}

// RemediationItem is an ADR-0010 job without payload, signature or result.
type RemediationItem struct {
	JobID      string           `json:"job_id"`
	Tenant     string           `json:"tenant"`
	AgentID    string           `json:"agent_id"`
	Type       RemediationType  `json:"type"`
	State      RemediationState `json:"state"`
	CreatedAt  string           `json:"created_at"`
	ApprovedAt *string          `json:"approved_at,omitzero"`
	ExpiresAt  *string          `json:"expires_at,omitzero"`
}

// DataScope is the data of the "scope" kind: read-only (D2).
type DataScope struct {
	Items             []ScopeItem `json:"items"`
	Truncated         bool        `json:"truncated"`
	UnattributedCount int64       `json:"unattributed_count"`
}

// ScopeItem is the scan scope of one tenant on this node.
type ScopeItem struct {
	Tenant            string      `json:"tenant"`
	Enabled           bool        `json:"enabled"`
	Scope             []string    `json:"scope"`
	GMPUserConfigured bool        `json:"gmp_user_configured"`
	Source            ScopeSource `json:"source"`
}

// DataAuditTail is the data of the "audit_tail" kind: the last lines of both local audit streams, verbatim.
type DataAuditTail struct {
	Exec   AuditStreamTail `json:"exec"`
	Reject AuditStreamTail `json:"reject"`
}

// AuditStreamTail is fleet-state.schema.json#/$defs/audit_stream_tail.
type AuditStreamTail struct {
	Lines      []string `json:"lines"`
	FirstSeq   *int64   `json:"first_seq,omitzero"`
	LastSeq    *int64   `json:"last_seq,omitzero"`
	HeadSHA256 *string  `json:"head_sha256,omitzero"`
}

// AuditEntry is one line of a local audit stream (fleet-state.schema.json#/$defs/audit_entry).
type AuditEntry struct {
	Stream          AuditStream           `json:"stream"`
	Seq             int64                 `json:"seq"`
	At              string                `json:"at"`
	Event           AuditEvent            `json:"event"`
	CommandID       *string               `json:"command_id,omitzero"`
	Type            *CommandType          `json:"type,omitzero"`
	Tenant          *string               `json:"tenant,omitzero"`
	IssuedBy        *string               `json:"issued_by,omitzero"`
	PayloadSHA256   *string               `json:"payload_sha256,omitzero"`
	ObjectIDs       []string              `json:"object_ids,omitzero"`
	Hosts           []string              `json:"hosts,omitzero"`
	HostsCount      *int64                `json:"hosts_count,omitzero"`
	Report          *AuditReport          `json:"report,omitzero"`
	Artifact        *AuditArtifact        `json:"artifact,omitzero"`
	Reason          *RejectReason         `json:"reason,omitzero"`
	Status          *ResultStatus         `json:"status,omitzero"`
	ErrorCode       *ErrorCode            `json:"error_code,omitzero"`
	Unauthenticated *AuditUnauthenticated `json:"unauthenticated,omitzero"`
	Redelivered     *AuditRedelivered     `json:"redelivered,omitzero"`
	Versions        *AuditVersions        `json:"versions,omitzero"`
	Detail          *string               `json:"detail,omitzero"`
	PrevSHA256      string                `json:"prev_sha256"`
}

// AuditReport is audit_entry.report: the parameters of report.export / report.summary.
type AuditReport struct {
	ReportID       string         `json:"report_id"`
	Format         *ReportFormat  `json:"format,omitzero"`
	Lang           *ReportLang    `json:"lang,omitzero"`
	Variant        *ReportVariant `json:"variant,omitzero"`
	DeltaReportID  *string        `json:"delta_report_id,omitzero"`
	Filter         *string        `json:"filter,omitzero"`
	MinQoD         *int           `json:"min_qod,omitzero"`
	ApplyOverrides *bool          `json:"apply_overrides,omitzero"`
	Levels         *string        `json:"levels,omitzero"`
}

// AuditArtifact is audit_entry.artifact: what left the node with a report.export.
type AuditArtifact struct {
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// AuditUnauthenticated is the periodic count of envelopes refused at lines 0–2.
type AuditUnauthenticated struct {
	Since           string `json:"since"`
	BadEnvelope     int64  `json:"bad_envelope"`
	PayloadMismatch int64  `json:"payload_mismatch"`
	BadSignature    int64  `json:"bad_signature"`
}

// AuditRedelivered is the periodic count of redeliveries (line 2a).
type AuditRedelivered struct {
	Since string `json:"since"`
	Count int64  `json:"count"`
}

// AuditVersions is the version_mismatch line: both announcements.
type AuditVersions struct {
	Node []string `json:"node"`
	Hub  []string `json:"hub"`
}
