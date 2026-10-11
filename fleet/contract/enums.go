package contract

// The enums of the six fleet schemas. Every constant is declared with its type and a string literal: the
// parity test collects them from this source (go/ast) and requires each set to be EXACTLY the enum of the
// schema location(s) that use the type. RejectReason and Decision live in reasons.go.

// CommandType is a type of the v1 command catalog (fleet-command.schema.json#/$defs/command_type). At
// verification line 0 any value matching command_type_any is well-formed; a type outside the catalog is
// refused at line 7 (unsupported), never at line 0.
type CommandType string

// The v1 catalog, in schema (and ADR) order.
const (
	TypeStateResync       CommandType = "state.resync"
	TypeTaskStart         CommandType = "task.start"
	TypeTaskStop          CommandType = "task.stop"
	TypeTaskResume        CommandType = "task.resume"
	TypeTaskCreate        CommandType = "task.create"
	TypeTaskModify        CommandType = "task.modify"
	TypeTaskClone         CommandType = "task.clone"
	TypeTaskDelete        CommandType = "task.delete"
	TypeTargetCreate      CommandType = "target.create"
	TypeTargetModify      CommandType = "target.modify"
	TypeTargetDelete      CommandType = "target.delete"
	TypeScheduleCreate    CommandType = "schedule.create"
	TypeScheduleModify    CommandType = "schedule.modify"
	TypeScheduleDelete    CommandType = "schedule.delete"
	TypeReportExport      CommandType = "report.export"
	TypeReportSummary     CommandType = "report.summary"
	TypeAgentScanNow      CommandType = "agent.scan_now"
	TypeAgentRevoke       CommandType = "agent.revoke"
	TypeEnrollTokenCreate CommandType = "enroll_token.create"
	TypeEnrollTokenRevoke CommandType = "enroll_token.revoke"
	TypeSensorJobEnqueue  CommandType = "sensor_job.enqueue"
	TypeFeedSyncNow       CommandType = "feed.sync_now"
)

// commandTypes is the v1 catalog in order.
func commandTypes() []CommandType {
	return []CommandType{
		TypeStateResync, TypeTaskStart, TypeTaskStop, TypeTaskResume, TypeTaskCreate, TypeTaskModify, TypeTaskClone,
		TypeTaskDelete, TypeTargetCreate, TypeTargetModify, TypeTargetDelete, TypeScheduleCreate, TypeScheduleModify,
		TypeScheduleDelete, TypeReportExport, TypeReportSummary, TypeAgentScanNow, TypeAgentRevoke,
		TypeEnrollTokenCreate, TypeEnrollTokenRevoke, TypeSensorJobEnqueue, TypeFeedSyncNow,
	}
}

// NodeKind is the kind of a fleet node (enroll_request.node_kind, data_node.node_kind).
type NodeKind string

const (
	NodeCentral    NodeKind = "central"
	NodeStandalone NodeKind = "standalone"
	NodeSensor     NodeKind = "sensor"
)

// StateKind is a state snapshot kind (fleet-state.schema.json#/$defs/state_kind).
type StateKind string

const (
	KindNode         StateKind = "node"
	KindTasks        StateKind = "tasks"
	KindTargets      StateKind = "targets"
	KindSchedules    StateKind = "schedules"
	KindReports      StateKind = "reports"
	KindAgents       StateKind = "agents"
	KindTokens       StateKind = "tokens"
	KindSensors      StateKind = "sensors"
	KindScanRequests StateKind = "scan_requests"
	KindRemediation  StateKind = "remediation"
	KindScope        StateKind = "scope"
	KindAuditTail    StateKind = "audit_tail"
)

// EventType is a fleet event type (fleet-event.schema.json#/$defs/event_type).
type EventType string

const (
	EventConnectorStarted           EventType = "connector.started"
	EventTaskStatusChanged          EventType = "task.status_changed"
	EventReportCompleted            EventType = "report.completed"
	EventAgentOnline                EventType = "agent.online"
	EventAgentOffline               EventType = "agent.offline"
	EventFeedStale                  EventType = "feed.stale"
	EventFeedUpdated                EventType = "feed.updated"
	EventRemediationPendingApproval EventType = "remediation.pending_approval"
	EventCommandRejectedByPolicy    EventType = "command.rejected_by_policy"
)

// ReportFormat is the symbolic export format of report.export (fleet-command.schema.json#/$defs/report_format).
type ReportFormat string

const (
	FormatSuricatoosPDF ReportFormat = "suricatoos-pdf"
	FormatGVMXML        ReportFormat = "gvm-xml"
	FormatGVMCSVResults ReportFormat = "gvm-csv-results"
	FormatGVMPDF        ReportFormat = "gvm-pdf"
)

// ReportLang is the language of an export (fleet-command.schema.json#/$defs/report_lang).
type ReportLang string

const (
	LangEN   ReportLang = "en"
	LangPTBR ReportLang = "pt_BR"
	LangES   ReportLang = "es"
)

// ReportVariant is the report EDITION (fleet-command.schema.json#/$defs/report_variant). Full vs delta is not
// a variant: it is only the optional delta_report_id.
type ReportVariant string

const (
	VariantTechnical ReportVariant = "technical"
	VariantClient    ReportVariant = "client"
	VariantExecutive ReportVariant = "executive"
)

// AliveTest is the contract NAME of a set of gvmd alive-test methods (fleet-command.schema.json#/$defs/alive_test,
// ADR-0011 decision D9): the node never sends the name to gvmd; fleet_ops.py sends each method of the set as one
// <alive_test> sub-element (e.g. "ICMP, TCP-SYN Service & ARP Ping" = ICMP Ping + TCP-SYN Service Ping + ARP Ping).
type AliveTest string

const (
	AliveICMPTCPSYNARP     AliveTest = "ICMP, TCP-SYN Service & ARP Ping"
	AliveICMPTCPACKARP     AliveTest = "ICMP, TCP-ACK Service & ARP Ping"
	AliveICMPTCPACK        AliveTest = "ICMP & TCP-ACK Service Ping"
	AliveICMPARP           AliveTest = "ICMP & ARP Ping"
	AliveTCPACKARP         AliveTest = "TCP-ACK Service & ARP Ping"
	AliveICMP              AliveTest = "ICMP Ping"
	AliveTCPACK            AliveTest = "TCP-ACK Service Ping"
	AliveTCPSYN            AliveTest = "TCP-SYN Service Ping"
	AliveARP               AliveTest = "ARP Ping"
	AliveConsiderAlive     AliveTest = "Consider Alive"
	AliveScanConfigDefault AliveTest = "Scan Config Default"
)

// The alive-test set of a target created without one, and the documented fallback set when the local gvmd
// refuses it (ADR-0011 "Alive test"): never a silent fall back to Consider Alive or Scan Config Default.
const (
	DefaultAliveTest  = AliveICMPTCPSYNARP
	FallbackAliveTest = AliveICMPTCPACKARP
)

// FeedType is a GVM feed (fleet-state.schema.json#/$defs/feed_type).
type FeedType string

const (
	FeedNVT      FeedType = "nvt"
	FeedSCAP     FeedType = "scap"
	FeedCERT     FeedType = "cert"
	FeedGVMDData FeedType = "gvmd_data"
)

// ResultStatus is the outcome of an accepted command (result.status, audit_entry.status).
type ResultStatus string

const (
	StatusSucceeded ResultStatus = "succeeded"
	StatusFailed    ResultStatus = "failed"
)

// ErrorCode says why an accepted command failed (fleet-result.schema.json#/$defs/error_code).
type ErrorCode string

const (
	ErrorNotFound             ErrorCode = "not_found"
	ErrorConflict             ErrorCode = "conflict"
	ErrorGVM                  ErrorCode = "gvm_error"
	ErrorTimeout              ErrorCode = "timeout"
	ErrorInterrupted          ErrorCode = "interrupted"
	ErrorUnavailable          ErrorCode = "unavailable"
	ErrorArtifactTooLarge     ErrorCode = "artifact_too_large"
	ErrorArtifactUploadFailed ErrorCode = "artifact_upload_failed"
	ErrorSecretLost           ErrorCode = "secret_lost"
	ErrorInternal             ErrorCode = "internal_error"
)

// TokenType is the kind of a scanner bootstrap token (payload_enroll_token_create, data_tokens).
type TokenType string

const (
	TokenSingleHost TokenType = "single_host"
	TokenDeployment TokenType = "deployment"
)

// AgentPolicy is the certificate OU policy of an enrolled agent or sensor (data_agents.policy). The fleet can
// only mint agent-endpoint tokens (the const of payload_enroll_token_create.policy).
type AgentPolicy string

const (
	PolicyAgentEndpoint AgentPolicy = "agent-endpoint"
	PolicyScannerSensor AgentPolicy = "scanner-sensor"
)

// ArtifactContentType is the content type of a decompressed export (artifact.original_content_type).
type ArtifactContentType string

const (
	ContentTypePDF ArtifactContentType = "application/pdf"
	ContentTypeXML ArtifactContentType = "application/xml"
	ContentTypeCSV ArtifactContentType = "text/csv"
)

// HealthStatus is data_node.health.status.
type HealthStatus string

const (
	HealthOK       HealthStatus = "ok"
	HealthDegraded HealthStatus = "degraded"
	HealthDown     HealthStatus = "down"
)

// ScanRequestState is the state of an ADR-0007 sensor job (data_scan_requests).
type ScanRequestState string

const (
	ScanRequestPending   ScanRequestState = "PENDING"
	ScanRequestDelivered ScanRequestState = "DELIVERED"
	ScanRequestAcked     ScanRequestState = "ACKED"
	ScanRequestDone      ScanRequestState = "DONE"
	ScanRequestExpired   ScanRequestState = "EXPIRED"
)

// RemediationType is the type of an ADR-0010 job (data_remediation, data_remediation_pending).
type RemediationType string

const (
	RemediationPackagePatch    RemediationType = "package_patch"
	RemediationConfigHardening RemediationType = "config_hardening"
)

// RemediationState is the state of an ADR-0010 job (data_remediation).
type RemediationState string

const (
	RemediationPendingApproval RemediationState = "PENDING_APPROVAL"
	RemediationApproved        RemediationState = "APPROVED"
	RemediationDelivered       RemediationState = "DELIVERED"
	RemediationAcked           RemediationState = "ACKED"
	RemediationApplied         RemediationState = "APPLIED"
	RemediationFailed          RemediationState = "FAILED"
	RemediationVerified        RemediationState = "VERIFIED"
	RemediationExpired         RemediationState = "EXPIRED"
	RemediationRejected        RemediationState = "REJECTED"
)

// ScopeSource says where a tenant's scope comes from (data_scope).
type ScopeSource string

const (
	ScopeTenantsRegistry ScopeSource = "tenants_registry"
	ScopeLocalEnv        ScopeSource = "local_env"
)

// AuditStream is one of the two local audit streams (audit_entry.stream).
type AuditStream string

const (
	StreamExec   AuditStream = "exec"
	StreamReject AuditStream = "reject"
)

// AuditEvent is the event of one local audit line (audit_entry.event).
type AuditEvent string

const (
	AuditEventConnectorStarted AuditEvent = "connector_started"
	AuditEventIdentityChanged  AuditEvent = "identity_changed"
	AuditEventPolicyChanged    AuditEvent = "policy_changed"
	AuditEventReceived         AuditEvent = "received"
	AuditEventExecuted         AuditEvent = "executed"
	AuditEventResult           AuditEvent = "result"
	AuditEventRejected         AuditEvent = "rejected"
	AuditEventDeferred         AuditEvent = "deferred"
	AuditEventUnauthenticated  AuditEvent = "unauthenticated"
	AuditEventRedelivered      AuditEvent = "redelivered"
	AuditEventVersionMismatch  AuditEvent = "version_mismatch"
)

// FeedSyncStatus is output_feed_sync_now.status.
type FeedSyncStatus string

const (
	SyncStarted        FeedSyncStatus = "started"
	SyncAlreadyRunning FeedSyncStatus = "already_running"
)

// TaskModifyField is an entry of output_task_modify.changed.
type TaskModifyField string

const (
	TaskFieldName         TaskModifyField = "name"
	TaskFieldComment      TaskModifyField = "comment"
	TaskFieldTargetID     TaskModifyField = "target_id"
	TaskFieldScanConfigID TaskModifyField = "scan_config_id"
	TaskFieldScheduleID   TaskModifyField = "schedule_id"
)

// TargetModifyField is an entry of output_target_modify.changed.
type TargetModifyField string

const (
	TargetFieldName         TargetModifyField = "name"
	TargetFieldComment      TargetModifyField = "comment"
	TargetFieldHosts        TargetModifyField = "hosts"
	TargetFieldExcludeHosts TargetModifyField = "exclude_hosts"
	TargetFieldPortListID   TargetModifyField = "port_list_id"
	TargetFieldAliveTest    TargetModifyField = "alive_test"
)

// ScheduleModifyField is an entry of output_schedule_modify.changed.
type ScheduleModifyField string

const (
	ScheduleFieldName      ScheduleModifyField = "name"
	ScheduleFieldComment   ScheduleModifyField = "comment"
	ScheduleFieldICalendar ScheduleModifyField = "icalendar"
	ScheduleFieldTimezone  ScheduleModifyField = "timezone"
)
