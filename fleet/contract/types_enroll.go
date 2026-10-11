package contract

// EnrollRequest is the body of POST /fleet/v1/enroll (fleet-enroll.schema.json#/$defs/enroll_request).
type EnrollRequest struct {
	SchemaVersion    string   `json:"schema_version"`
	Token            string   `json:"token"`
	NodeID           string   `json:"node_id"`
	NodeKind         NodeKind `json:"node_kind"`
	CSR              string   `json:"csr"`
	ConnectorVersion string   `json:"connector_version"`
	SchemaVersions   []string `json:"schema_versions"`
}

// RenewRequest is the body of POST /fleet/v1/renew (fleet-enroll.schema.json#/$defs/renew_request).
type RenewRequest struct {
	SchemaVersion  string   `json:"schema_version"`
	NodeID         string   `json:"node_id"`
	CSR            string   `json:"csr"`
	SchemaVersions []string `json:"schema_versions"`
}

// EnrollResponse is the 200 body of /enroll and /renew (fleet-enroll.schema.json#/$defs/enroll_response).
type EnrollResponse struct {
	SchemaVersion      string   `json:"schema_version"`
	NodeID             string   `json:"node_id"`
	Certificate        string   `json:"certificate"`
	CACert             string   `json:"ca_cert"`
	CommandPubkey      string   `json:"command_pubkey"`
	ServerTime         string   `json:"server_time"`
	HeartbeatIntervalS int      `json:"heartbeat_interval_s"`
	PollWaitS          int      `json:"poll_wait_s"`
	SchemaVersions     []string `json:"schema_versions"`
}

// HeartbeatRequest is the body of POST /fleet/v1/heartbeat (fleet-heartbeat.schema.json#/$defs/heartbeat_request).
type HeartbeatRequest struct {
	SchemaVersion             string               `json:"schema_version"`
	NodeID                    string               `json:"node_id"`
	SentAt                    string               `json:"sent_at"`
	ConnectorVersion          string               `json:"connector_version"`
	SchemaVersions            []string             `json:"schema_versions"`
	ReplayFloor               string               `json:"replay_floor"`
	StateHashes               map[StateKind]string `json:"state_hashes"`
	OutboxEvents              int64                `json:"outbox_events"`
	OutboxDropped             int64                `json:"outbox_dropped"`
	PendingResults            int64                `json:"pending_results"`
	UnauthenticatedRejections int64                `json:"unauthenticated_rejections"`
	Redeliveries              int64                `json:"redeliveries"`
}

// HeartbeatResponse is the 200 body of /heartbeat (fleet-heartbeat.schema.json#/$defs/heartbeat_response).
// Resync items only match the kind PATTERN (state_kind_any): the node ignores, and alerts on, a kind it does not
// know — the one exception to strict validation — so they stay plain strings.
type HeartbeatResponse struct {
	SchemaVersion      string   `json:"schema_version"`
	ServerTime         string   `json:"server_time"`
	Resync             []string `json:"resync"`
	HeartbeatIntervalS int      `json:"heartbeat_interval_s"`
	PollWaitS          int      `json:"poll_wait_s"`
	SchemaVersions     []string `json:"schema_versions"`
}

// VersionUnsupported is the JSON body of a 426 on any route (fleet-heartbeat.schema.json#/$defs/version_unsupported):
// only the hub's announcement. Version-invariant: this shape never changes, not even in a new MAJOR.
type VersionUnsupported struct {
	SchemaVersions []string `json:"schema_versions"`
}
