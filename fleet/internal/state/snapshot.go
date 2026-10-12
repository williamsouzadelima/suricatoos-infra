package state

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/williamsouzadelima/suricatoos-infra/fleet/contract"
)

const (
	// bodyReserve is what the PUT body adds around data — schema_version, node_id (at most 64 characters), kind,
	// collected_at and content_sha256 come to ~260 bytes —, kept free under the 16 MiB of ADR-0011 "Limites".
	bodyReserve = 1 << 10
	// maxDataBytes is the cap on the data of one kind: a kind that would go over it is cut (truncated), never sent
	// whole nor invalid.
	maxDataBytes = contract.MaxStateBytes - bodyReserve
)

// Snapshot is the current state of one kind: the exact bytes of its data_<kind> and their SHA-256.
type Snapshot struct {
	Kind contract.StateKind
	// Data is the compact JSON of the kind's data (contract.MarshalCompact), the bytes content_sha256 covers.
	Data []byte
	// SHA256 is the lowercase hex SHA-256 of Data: the content_sha256 of the PUT and the hash of the heartbeat.
	SHA256 string
	// CollectedAt is the last collection that found this content (UTC, whole seconds): an unchanged kind keeps its
	// bytes and its hash, and only this moves.
	CollectedAt time.Time
}

// encode serializes the data of a kind — a contract.Data* value — compact, and hashes the exact bytes.
func encode(kind contract.StateKind, v any, collectedAt time.Time) (Snapshot, error) {
	b, err := contract.MarshalCompact(v)
	if err != nil {
		return Snapshot{}, fmt.Errorf("state: serializar %s: %w", kind, err)
	}
	return snapshotOf(kind, b, collectedAt), nil
}

func snapshotOf(kind contract.StateKind, data []byte, collectedAt time.Time) Snapshot {
	sum := sha256.Sum256(data)
	return Snapshot{Kind: kind, Data: data, SHA256: hex.EncodeToString(sum[:]),
		CollectedAt: collectedAt.UTC().Truncate(time.Second)}
}

// bodyHeader is the PUT body without data, in the schema's member order.
type bodyHeader struct {
	SchemaVersion string             `json:"schema_version"`
	NodeID        string             `json:"node_id"`
	Kind          contract.StateKind `json:"kind"`
	CollectedAt   string             `json:"collected_at"`
	ContentSHA256 string             `json:"content_sha256"`
}

var nodeIDRule = newRule(3, 64, contract.PatternNodeID, nil)

// Body returns the body of PUT /fleet/v1/state/{kind} (fleet-state.schema.json, schema_version 1.0.0) for this
// snapshot and node_id. data is spliced in byte for byte — no JSON encoder touches it after the hash (ADR-0011
// "Codificação JSON": "Payload embutido sem re-codificar", which holds for data too) —, so the hub, hashing the raw
// span, finds content_sha256. It refuses what must never be sent: an invalid node_id, a Data that is not one
// compact JSON object or does not hash to SHA256, a body over 16 MiB.
func (s Snapshot) Body(nodeID string) ([]byte, error) {
	if !nodeIDRule.ok(nodeID) {
		return nil, errors.New("state: node_id inválido para o corpo do estado")
	}
	if !isCompactObject(s.Data) {
		return nil, fmt.Errorf("state: o data de %s não é um objeto JSON compacto", s.Kind)
	}
	if sum := sha256.Sum256(s.Data); hex.EncodeToString(sum[:]) != s.SHA256 {
		return nil, fmt.Errorf("state: o data de %s não confere com o seu content_sha256", s.Kind)
	}
	head, err := contract.MarshalCompact(bodyHeader{SchemaVersion: contract.SchemaVersion, NodeID: nodeID, Kind: s.Kind,
		CollectedAt: contract.FormatUTCTime(s.CollectedAt), ContentSHA256: s.SHA256})
	if err != nil {
		return nil, err
	}
	body := make([]byte, 0, len(head)+len(s.Data)+16)
	body = append(body, head[:len(head)-1]...) // without the closing brace
	body = append(body, `,"data":`...)
	body = append(body, s.Data...)
	body = append(body, '}')
	if len(body) > contract.MaxStateBytes {
		return nil, fmt.Errorf("state: corpo de %s com %d bytes, acima do teto de %d", s.Kind, len(body), contract.MaxStateBytes)
	}
	return body, nil
}

// isCompactObject reports whether b is exactly one JSON object without insignificant whitespace.
func isCompactObject(b []byte) bool {
	if len(b) == 0 || b[0] != '{' || !json.Valid(b) {
		return false
	}
	var c bytes.Buffer
	if err := json.Compact(&c, b); err != nil {
		return false
	}
	return bytes.Equal(c.Bytes(), b)
}
