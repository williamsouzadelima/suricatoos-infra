package events

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/williamsouzadelima/suricatoos-infra/fleet/contract"
)

// Valores fictícios dos testes (UUIDs inventados, nomes de exemplo).
const (
	uuidTask1   = "11111111-1111-4111-8111-111111111111"
	uuidTask2   = "22222222-2222-4222-8222-222222222222"
	uuidTask3   = "33333333-3333-4333-8333-333333333333"
	uuidReport1 = "77777777-7777-4777-8777-777777777777"
	uuidReport2 = "88888888-8888-4888-8888-888888888888"
	uuidReport3 = "99999999-9999-4999-8999-999999999999"
	policySHA   = "202e584626515573d531f5508c9094f8d6b705e0fc0fe6fbf29c76969fef313f"
)

var testAt = time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)

func uuidN(n int) string {
	s := strconv.FormatInt(int64(n), 16)
	return "00000000-0000-4000-8000-" + strings.Repeat("0", 12-len(s)) + s
}

func strp(s string) *string { return &s }
func intp(i int) *int       { return &i }

func sha(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

type validEvent struct{ pending pending }

// validEvents tem um evento válido de cada tipo, com os membros opcionais preenchidos.
func validEvents() []validEvent {
	at := testAt
	return []validEvent{
		{pending{typ: contract.EventConnectorStarted, at: at, data: contract.DataConnectorStarted{
			ConnectorVersion: "1.0.0", NodeKind: contract.NodeCentral, PolicySHA256: policySHA}}},
		{pending{typ: contract.EventTaskStatusChanged, tenant: "acme", at: at, data: contract.DataTaskStatusChanged{
			TaskID: uuidTask1, From: "Running", To: "Done", ReportID: strp(uuidReport1), Progress: intp(100)}}},
		{pending{typ: contract.EventTaskStatusChanged, tenant: "acme", at: at, data: contract.DataTaskStatusChanged{
			TaskID: uuidTask2, From: "", To: "New", Progress: intp(-1)}}},
		{pending{typ: contract.EventReportCompleted, tenant: "acme", at: at, data: contract.DataReportCompleted{
			ReportID: uuidReport1, TaskID: uuidTask1, ScanStart: "2026-10-11T02:00:00Z",
			ScanEnd:    "2026-10-11T03:10:00Z",
			Counts:     contract.SeverityCounts{Critical: 1, High: 2, Medium: 3, Low: 4, Log: 5, FalsePositive: 6},
			HostsCount: 7}}},
		{pending{typ: contract.EventAgentOnline, tenant: "globex", at: at, data: contract.DataAgentPresence{
			AgentID: "DESKTOP-EXEMPLO-01", LastSeen: strp("2026-10-11T11:58:00Z")}}},
		{pending{typ: contract.EventAgentOffline, tenant: "globex", at: at, data: contract.DataAgentPresence{
			AgentID: "win-exemplo-02"}}},
		{pending{typ: contract.EventFeedStale, at: at, data: contract.DataFeedStale{
			Feed: contract.FeedNVT, Version: "202610070600", AgeHours: 96.5, StaleAfterHours: 72}}},
		{pending{typ: contract.EventFeedUpdated, at: at, data: contract.DataFeedUpdated{
			Feed: contract.FeedSCAP, Version: "202610110600", PreviousVersion: strp("202610040600")}}},
		{pending{typ: contract.EventFeedUpdated, at: at, data: contract.DataFeedUpdated{
			Feed: contract.FeedGVMDData, Version: "202610110600"}}},
		{pending{typ: contract.EventRemediationPendingApproval, tenant: "acme", at: at,
			data: contract.DataRemediationPending{
				JobID: "job-0001", AgentID: "win-exemplo-01", Type: contract.RemediationConfigHardening,
				CreatedAt: "2026-10-11T11:50:00Z", ExpiresAt: strp("2026-10-12T11:50:00Z")}}},
		{pending{typ: contract.EventCommandRejectedByPolicy, tenant: "acme", at: at, data: contract.DataCommandRejected{
			CommandID: uuidN(9), Type: contract.TypeTargetCreate, Reason: contract.ReasonScopeDenied,
			Detail: strp("host fora do escopo do tenant")}}},
		{pending{typ: contract.EventCommandRejectedByPolicy, tenant: "desconhecido", at: at,
			data: contract.DataCommandRejected{
				CommandID: uuidN(10), Type: "foo.bar", Reason: contract.ReasonTenantUnknown}}},
	}
}

// decodeEventData exige que o data do evento passe no DecodeStrict do tipo do contrato e seja a serialização compacta
// dele, e o devolve decodificado.
func decodeEventData(t *testing.T, ev contract.Event) any {
	t.Helper()
	var v any
	switch ev.Type {
	case contract.EventConnectorStarted:
		v = &contract.DataConnectorStarted{}
	case contract.EventTaskStatusChanged:
		v = &contract.DataTaskStatusChanged{}
	case contract.EventReportCompleted:
		v = &contract.DataReportCompleted{}
	case contract.EventAgentOnline, contract.EventAgentOffline:
		v = &contract.DataAgentPresence{}
	case contract.EventFeedStale:
		v = &contract.DataFeedStale{}
	case contract.EventFeedUpdated:
		v = &contract.DataFeedUpdated{}
	case contract.EventRemediationPendingApproval:
		v = &contract.DataRemediationPending{}
	case contract.EventCommandRejectedByPolicy:
		v = &contract.DataCommandRejected{}
	default:
		t.Fatalf("tipo %q", ev.Type)
	}
	if err := contract.DecodeStrict(ev.Data, v); err != nil {
		t.Fatalf("data de %s não passa no DecodeStrict: %v\n%s", ev.Type, err, ev.Data)
	}
	again, err := contract.MarshalCompact(v)
	if err != nil || string(again) != string(ev.Data) {
		t.Fatalf("data de %s não é a serialização compacta do tipo:\n%s\n%s", ev.Type, ev.Data, again)
	}
	return v
}
