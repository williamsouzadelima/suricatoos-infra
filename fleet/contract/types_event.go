package contract

import "encoding/json"

// EventBatch is the body of POST /fleet/v1/events (fleet-event.schema.json): 1–100 events, at least once.
type EventBatch struct {
	SchemaVersion string  `json:"schema_version"`
	NodeID        string  `json:"node_id"`
	Events        []Event `json:"events"`
}

// Event is fleet-event.schema.json#/$defs/event. Node-scoped events (connector.*, feed.*) carry no tenant;
// tenant-scoped ones always do. Data holds the exact bytes of the type's data_* object.
type Event struct {
	EventID    string          `json:"event_id"`
	Type       EventType       `json:"type"`
	OccurredAt string          `json:"occurred_at"`
	Tenant     *string         `json:"tenant,omitzero"`
	Data       json.RawMessage `json:"data"`
}

// DataConnectorStarted is the data of connector.started.
type DataConnectorStarted struct {
	ConnectorVersion string   `json:"connector_version"`
	NodeKind         NodeKind `json:"node_kind"`
	PolicySHA256     string   `json:"policy_sha256"`
}

// DataTaskStatusChanged is the data of task.status_changed (From "" when the task was not seen before).
type DataTaskStatusChanged struct {
	TaskID   string  `json:"task_id"`
	From     string  `json:"from"`
	To       string  `json:"to"`
	ReportID *string `json:"report_id,omitzero"`
	Progress *int    `json:"progress,omitzero"`
}

// DataReportCompleted is the data of report.completed: counts only.
type DataReportCompleted struct {
	ReportID   string         `json:"report_id"`
	TaskID     string         `json:"task_id"`
	ScanStart  string         `json:"scan_start"`
	ScanEnd    string         `json:"scan_end"`
	Counts     SeverityCounts `json:"counts"`
	HostsCount int64          `json:"hosts_count"`
}

// DataAgentPresence is the data of agent.online and agent.offline.
type DataAgentPresence struct {
	AgentID  string  `json:"agent_id"`
	LastSeen *string `json:"last_seen,omitzero"`
}

// DataFeedStale is the data of feed.stale.
type DataFeedStale struct {
	Feed            FeedType `json:"feed"`
	Version         string   `json:"version"`
	AgeHours        float64  `json:"age_hours"`
	StaleAfterHours int64    `json:"stale_after_hours"`
}

// DataFeedUpdated is the data of feed.updated.
type DataFeedUpdated struct {
	Feed            FeedType `json:"feed"`
	Version         string   `json:"version"`
	PreviousVersion *string  `json:"previous_version,omitzero"`
}

// DataRemediationPending is the data of remediation.pending_approval.
type DataRemediationPending struct {
	JobID     string          `json:"job_id"`
	AgentID   string          `json:"agent_id"`
	Type      RemediationType `json:"type"`
	CreatedAt string          `json:"created_at"`
	ExpiresAt *string         `json:"expires_at,omitzero"`
}

// DataCommandRejected is the data of command.rejected_by_policy: an AUTHENTIC command refused at lines 6–9.
type DataCommandRejected struct {
	CommandID string       `json:"command_id"`
	Type      CommandType  `json:"type"`
	Reason    RejectReason `json:"reason"`
	Detail    *string      `json:"detail,omitzero"`
}
