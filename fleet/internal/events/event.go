package events

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"time"

	"github.com/williamsouzadelima/suricatoos-infra/fleet/contract"
	"github.com/williamsouzadelima/suricatoos-infra/fleet/internal/state"
)

// DefaultStaleHours and MaxStaleHours are FLEET_FEED_STALE_HOURS's default (ADR-0011 "Configuração do nó") and
// ceiling: a feed is stale once its age passes this many hours. A value past a year would only turn feed.stale off,
// so it is refused like a typo.
const (
	DefaultStaleHours = 72
	MaxStaleHours     = 365 * 24
)

// ErrInvalidStaleHours: FLEET_FEED_STALE_HOURS is not a number of hours the connector accepts. The connector does not
// start with it.
var ErrInvalidStaleHours = errors.New("events: FLEET_FEED_STALE_HOURS inválido")

var reStaleHours = regexp.MustCompile(`^[1-9][0-9]{0,3}$`)

// ParseStaleHours parses FLEET_FEED_STALE_HOURS: empty (unset) is DefaultStaleHours; anything else is a whole number of
// hours in decimal, without sign or leading zero, from 1 to MaxStaleHours, or ErrInvalidStaleHours.
func ParseStaleHours(s string) (int, error) {
	if s == "" {
		return DefaultStaleHours, nil
	}
	if !reStaleHours.MatchString(s) {
		return 0, fmt.Errorf("%w: %.32q (horas inteiras de 1 a %d)", ErrInvalidStaleHours, s, MaxStaleHours)
	}
	n, _ := strconv.Atoi(s)
	if n > MaxStaleHours {
		return 0, fmt.Errorf("%w: %d (horas inteiras de 1 a %d)", ErrInvalidStaleHours, n, MaxStaleHours)
	}
	return n, nil
}

// maxEventBytes caps the encoding of one event. The largest valid one — a rejection whose detail has 512 runes of
// four bytes — stays under 3 KiB, so a hundred of them fill less than a quarter of a batch's 1 MiB.
const maxEventBytes = 16 << 10

// pending is an event before it has an id: its type, its tenant ("" for a node-scoped type), the instant it happened
// and its data, one of the contract.Data* values.
type pending struct {
	typ    contract.EventType
	tenant string
	at     time.Time
	data   any
}

// nodeScoped reports whether events of type t are of the node's scope, which carry no tenant (connector.*, feed.*);
// every other type is tenant-scoped and always carries one (fleet-event.schema.json).
func nodeScoped(t contract.EventType) bool {
	switch t {
	case contract.EventConnectorStarted, contract.EventFeedStale, contract.EventFeedUpdated:
		return true
	}
	return false
}

// newEventID returns a random UUIDv4 in the contract's lowercase form: the hub's dedup key.
func newEventID() string {
	var b [16]byte
	_, _ = rand.Read(b[:]) // crypto/rand.Read never fails (it aborts the program instead)
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

// build makes the event id of p: its data serialized compact (contract.MarshalCompact), then the whole event, which
// must pass checkEventBytes — so a value the schema would refuse never becomes an event. It returns the event and its
// encoding, the exact bytes that go to disk and to the hub.
func build(id string, p pending) (contract.Event, []byte, error) {
	if p.at.Year() < 1 || p.at.Year() > 9999 {
		return contract.Event{}, nil, fmt.Errorf("events: instante fora dos anos 0001–9999 em %s", p.typ)
	}
	data, err := contract.MarshalCompact(p.data)
	if err != nil {
		return contract.Event{}, nil, fmt.Errorf("events: serializar o data de %s: %w", p.typ, err)
	}
	ev := contract.Event{EventID: id, Type: p.typ, OccurredAt: contract.FormatUTCTime(p.at), Data: data}
	if !nodeScoped(p.typ) || p.tenant != "" {
		tenant := p.tenant
		ev.Tenant = &tenant
	}
	enc, err := contract.MarshalCompact(ev)
	if err != nil {
		return contract.Event{}, nil, fmt.Errorf("events: serializar %s: %w", p.typ, err)
	}
	if err := checkEventBytes(enc); err != nil {
		return contract.Event{}, nil, err
	}
	return ev, enc, nil
}

// checkEventBytes reports whether b is exactly the compact encoding of an event the schema accepts
// (fleet-event.schema.json#/$defs/event, with the data_* of its type): the strict decode of the contract, every value
// under the schema's rules (the state's string rules: state.ValidUUID...), the scope (a node-scoped type without
// tenant, any other with one) and no byte that a re-encoding would not produce. It is the check of every event that
// enters the outbox, and of every event the boot reads back from the disk.
func checkEventBytes(b []byte) error {
	if len(b) > maxEventBytes {
		return fmt.Errorf("events: evento de %d bytes acima do teto de %d", len(b), maxEventBytes)
	}
	var ev contract.Event
	if err := contract.DecodeStrict(b, &ev); err != nil {
		return fmt.Errorf("events: evento fora do contrato: %w", err)
	}
	if err := checkEvent(ev); err != nil {
		return err
	}
	again, err := contract.MarshalCompact(ev)
	if err != nil || !bytes.Equal(again, b) {
		return errors.New("events: o evento não está na forma compacta do contrato")
	}
	return nil
}

// checkEvent checks a decoded event: its members, its scope and its data.
func checkEvent(ev contract.Event) error {
	switch {
	case !state.ValidUUID(ev.EventID):
		return errors.New("events: event_id fora do padrão")
	case !state.ValidUTCTime(ev.OccurredAt):
		return fmt.Errorf("events: occurred_at inválido em %.32q", ev.Type)
	case nodeScoped(ev.Type) && ev.Tenant != nil:
		return fmt.Errorf("events: %s é de escopo nó e não leva tenant", ev.Type)
	case !nodeScoped(ev.Type) && (ev.Tenant == nil || !state.ValidTenant(*ev.Tenant)):
		return fmt.Errorf("events: %.32q é de escopo tenant e precisa de um tenant válido", ev.Type)
	}
	if err := checkData(ev.Type, ev.Data); err != nil {
		return fmt.Errorf("events: data de %.32q: %w", ev.Type, err)
	}
	return nil
}

var (
	errValue    = errors.New("valor fora do schema")
	feedTypes   = []contract.FeedType{contract.FeedNVT, contract.FeedSCAP, contract.FeedCERT, contract.FeedGVMDData}
	remediTypes = []contract.RemediationType{contract.RemediationPackagePatch, contract.RemediationConfigHardening}
)

func oneOf[T comparable](v T, set ...T) bool {
	for _, s := range set {
		if v == s {
			return true
		}
	}
	return false
}

func optUTC(s *string) bool { return s == nil || state.ValidUTCTime(*s) }

// dataOf returns a new value of the contract type of the data of events of type t; nil for an unknown type.
func dataOf(t contract.EventType) any {
	switch t {
	case contract.EventConnectorStarted:
		return &contract.DataConnectorStarted{}
	case contract.EventTaskStatusChanged:
		return &contract.DataTaskStatusChanged{}
	case contract.EventReportCompleted:
		return &contract.DataReportCompleted{}
	case contract.EventAgentOnline, contract.EventAgentOffline:
		return &contract.DataAgentPresence{}
	case contract.EventFeedStale:
		return &contract.DataFeedStale{}
	case contract.EventFeedUpdated:
		return &contract.DataFeedUpdated{}
	case contract.EventRemediationPendingApproval:
		return &contract.DataRemediationPending{}
	case contract.EventCommandRejectedByPolicy:
		return &contract.DataCommandRejected{}
	}
	return nil
}

// checkData decodes the data of an event of type t strictly into its contract type, checks every value and requires
// the bytes to be the compact serialization of what they decode to.
func checkData(t contract.EventType, raw []byte) error {
	v := dataOf(t)
	if v == nil {
		return errors.New("tipo de evento desconhecido")
	}
	if err := contract.DecodeStrict(raw, v); err != nil {
		return err
	}
	if !validData(v) {
		return errValue
	}
	again, err := contract.MarshalCompact(v)
	if err != nil || !bytes.Equal(again, raw) {
		return errors.New("o data não está na forma compacta do contrato")
	}
	return nil
}

// validData checks every value of a decoded data_* against its schema.
func validData(v any) bool {
	switch d := v.(type) {
	case *contract.DataConnectorStarted:
		return state.ValidVersion(d.ConnectorVersion) &&
			oneOf(d.NodeKind, contract.NodeCentral, contract.NodeStandalone, contract.NodeSensor) &&
			state.ValidSHA256(d.PolicySHA256)
	case *contract.DataTaskStatusChanged:
		return state.ValidUUID(d.TaskID) && (d.From == "" || state.ValidGVMStatus(d.From)) &&
			state.ValidGVMStatus(d.To) && (d.ReportID == nil || state.ValidUUID(*d.ReportID)) &&
			(d.Progress == nil || (*d.Progress >= -1 && *d.Progress <= 100))
	case *contract.DataReportCompleted:
		n := d.Counts
		return state.ValidUUID(d.ReportID) && state.ValidUUID(d.TaskID) && state.ValidUTCTime(d.ScanStart) &&
			state.ValidUTCTime(d.ScanEnd) && n.Critical >= 0 && n.High >= 0 && n.Medium >= 0 && n.Low >= 0 &&
			n.Log >= 0 && n.FalsePositive >= 0 && d.HostsCount >= 0
	case *contract.DataAgentPresence:
		return state.ValidAgentID(d.AgentID) && optUTC(d.LastSeen)
	case *contract.DataFeedStale:
		return oneOf(d.Feed, feedTypes...) && state.ValidVersion(d.Version) && d.AgeHours >= 0 &&
			!math.IsInf(d.AgeHours, 0) && d.StaleAfterHours >= 1
	case *contract.DataFeedUpdated:
		return oneOf(d.Feed, feedTypes...) && state.ValidVersion(d.Version) &&
			(d.PreviousVersion == nil || state.ValidVersion(*d.PreviousVersion))
	case *contract.DataRemediationPending:
		return state.ValidJobID(d.JobID) && state.ValidAgentID(d.AgentID) && oneOf(d.Type, remediTypes...) &&
			state.ValidUTCTime(d.CreatedAt) && optUTC(d.ExpiresAt)
	case *contract.DataCommandRejected:
		return state.ValidUUID(d.CommandID) && state.ValidCommandType(string(d.Type)) && d.Reason.PolicyEvent() &&
			(d.Detail == nil || state.ValidDetail(*d.Detail))
	}
	return false
}
