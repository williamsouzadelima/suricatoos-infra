package events

import (
	"encoding/json"
	"math"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/williamsouzadelima/suricatoos-infra/fleet/contract"
)

var reUUIDv4 = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

// O event_id é um UUIDv4 aleatório na forma do contrato (hex minúsculo), diferente a cada evento.
func TestEventIDEUUIDv4Aleatorio(t *testing.T) {
	seen := map[string]bool{}
	for range 1000 {
		id := newEventID()
		if !reUUIDv4.MatchString(id) {
			t.Fatalf("event_id %q não é UUIDv4", id)
		}
		if seen[id] {
			t.Fatalf("event_id repetido: %s", id)
		}
		seen[id] = true
	}
}

// Cada tipo de evento é montado no escopo certo — nó sem tenant, tenant com tenant — e o data é a serialização
// compacta do tipo do contrato, que passa no DecodeStrict dele.
func TestMontaCadaTipoNoEscopoCerto(t *testing.T) {
	for _, c := range validEvents() {
		ev, enc, err := build(uuidN(1), c.pending)
		if err != nil {
			t.Fatalf("%s: %v", c.pending.typ, err)
		}
		if ev.EventID != uuidN(1) || ev.Type != c.pending.typ || ev.OccurredAt != "2026-10-11T12:00:00Z" {
			t.Fatalf("%s: cabeçalho %+v", c.pending.typ, ev)
		}
		if nodeScoped(ev.Type) != (ev.Tenant == nil) {
			t.Fatalf("%s: escopo errado (tenant %v)", ev.Type, ev.Tenant)
		}
		if ev.Tenant != nil && *ev.Tenant != c.pending.tenant {
			t.Fatalf("%s: tenant %q", ev.Type, *ev.Tenant)
		}
		decodeEventData(t, ev)
		again, err := contract.MarshalCompact(ev)
		if err != nil || string(again) != string(enc) {
			t.Fatalf("%s: a codificação guardada não é a do evento:\n%s\n%s", ev.Type, enc, again)
		}
		if err := checkEventBytes(enc); err != nil {
			t.Fatalf("%s: o evento montado não passa na própria checagem: %v", ev.Type, err)
		}
	}
}

// Um valor que o schema recusaria nunca vira evento: a montagem falha (o evento não entra na outbox).
func TestValorForaDoSchemaNaoViraEvento(t *testing.T) {
	at := testAt
	cases := map[string]pending{
		"tenant num evento de nó": {typ: contract.EventConnectorStarted, tenant: "acme", at: at,
			data: contract.DataConnectorStarted{ConnectorVersion: "1.0.0", NodeKind: contract.NodeCentral,
				PolicySHA256: policySHA}},
		"evento de tenant sem tenant": {typ: contract.EventAgentOnline, at: at,
			data: contract.DataAgentPresence{AgentID: "win-01"}},
		"tenant fora do padrão": {typ: contract.EventAgentOnline, tenant: "acme corp", at: at,
			data: contract.DataAgentPresence{AgentID: "win-01"}},
		"versão do conector inválida": {typ: contract.EventConnectorStarted, at: at,
			data: contract.DataConnectorStarted{ConnectorVersion: "1.0 beta", NodeKind: contract.NodeCentral,
				PolicySHA256: policySHA}},
		"node_kind inválido": {typ: contract.EventConnectorStarted, at: at,
			data: contract.DataConnectorStarted{ConnectorVersion: "1.0.0", NodeKind: "hub", PolicySHA256: policySHA}},
		"policy_sha256 maiúsculo": {typ: contract.EventConnectorStarted, at: at,
			data: contract.DataConnectorStarted{ConnectorVersion: "1.0.0", NodeKind: contract.NodeCentral,
				PolicySHA256: strings.ToUpper(policySHA)}},
		"task_id inválido": {typ: contract.EventTaskStatusChanged, tenant: "acme", at: at,
			data: contract.DataTaskStatusChanged{TaskID: "x", From: "", To: "Done"}},
		"status com dígito": {typ: contract.EventTaskStatusChanged, tenant: "acme", at: at,
			data: contract.DataTaskStatusChanged{TaskID: uuidTask1, From: "Running", To: "Done2"}},
		"from fora do padrão": {typ: contract.EventTaskStatusChanged, tenant: "acme", at: at,
			data: contract.DataTaskStatusChanged{TaskID: uuidTask1, From: " ", To: "Done"}},
		"progresso 101": {typ: contract.EventTaskStatusChanged, tenant: "acme", at: at,
			data: contract.DataTaskStatusChanged{TaskID: uuidTask1, From: "Running", To: "Done", Progress: intp(101)}},
		"contagem negativa": {typ: contract.EventReportCompleted, tenant: "acme", at: at,
			data: contract.DataReportCompleted{ReportID: uuidReport1, TaskID: uuidTask1,
				ScanStart: "2026-10-11T02:00:00Z", ScanEnd: "2026-10-11T03:00:00Z",
				Counts: contract.SeverityCounts{High: -1}}},
		"fim inexistente": {typ: contract.EventReportCompleted, tenant: "acme", at: at,
			data: contract.DataReportCompleted{ReportID: uuidReport1, TaskID: uuidTask1,
				ScanStart: "2026-10-11T02:00:00Z", ScanEnd: "2026-02-30T03:00:00Z"}},
		"agent_id com vírgula": {typ: contract.EventAgentOffline, tenant: "acme", at: at,
			data: contract.DataAgentPresence{AgentID: "a,b"}},
		"feed desconhecido": {typ: contract.EventFeedUpdated, at: at,
			data: contract.DataFeedUpdated{Feed: "nasl", Version: "202610110600"}},
		"idade negativa": {typ: contract.EventFeedStale, at: at,
			data: contract.DataFeedStale{Feed: contract.FeedNVT, Version: "1", AgeHours: -1, StaleAfterHours: 72}},
		"idade infinita": {typ: contract.EventFeedStale, at: at,
			data: contract.DataFeedStale{Feed: contract.FeedNVT, Version: "1", AgeHours: math.Inf(1),
				StaleAfterHours: 72}},
		"limiar zero": {typ: contract.EventFeedStale, at: at,
			data: contract.DataFeedStale{Feed: contract.FeedNVT, Version: "1", AgeHours: 80, StaleAfterHours: 0}},
		"job_id com ponto": {typ: contract.EventRemediationPendingApproval, tenant: "acme", at: at,
			data: contract.DataRemediationPending{JobID: "job.1", AgentID: "win-01",
				Type: contract.RemediationPackagePatch, CreatedAt: "2026-10-11T11:00:00Z"}},
		"tipo de remediação desconhecido": {typ: contract.EventRemediationPendingApproval, tenant: "acme", at: at,
			data: contract.DataRemediationPending{JobID: "job-1", AgentID: "win-01", Type: "reboot",
				CreatedAt: "2026-10-11T11:00:00Z"}},
		"motivo das linhas 0–5": {typ: contract.EventCommandRejectedByPolicy, tenant: "acme", at: at,
			data: contract.DataCommandRejected{CommandID: uuidN(9), Type: contract.TypeTaskStart,
				Reason: contract.ReasonReplay}},
		"motivo unavailable": {typ: contract.EventCommandRejectedByPolicy, tenant: "acme", at: at,
			data: contract.DataCommandRejected{CommandID: uuidN(9), Type: contract.TypeTaskStart,
				Reason: contract.ReasonUnavailable}},
		"tipo de comando malformado": {typ: contract.EventCommandRejectedByPolicy, tenant: "acme", at: at,
			data: contract.DataCommandRejected{CommandID: uuidN(9), Type: "Task.Start",
				Reason: contract.ReasonUnsupported}},
		"detalhe com quebra de linha": {typ: contract.EventCommandRejectedByPolicy, tenant: "acme", at: at,
			data: contract.DataCommandRejected{CommandID: uuidN(9), Type: contract.TypeTaskStart,
				Reason: contract.ReasonScopeDenied, Detail: strp("a\nb")}},
		"detalhe de 513 runas": {typ: contract.EventCommandRejectedByPolicy, tenant: "acme", at: at,
			data: contract.DataCommandRejected{CommandID: uuidN(9), Type: contract.TypeTaskStart,
				Reason: contract.ReasonScopeDenied, Detail: strp(strings.Repeat("é", 513))}},
		"tipo de evento desconhecido": {typ: "task.created", tenant: "acme", at: at,
			data: contract.DataTaskStatusChanged{TaskID: uuidTask1, From: "", To: "New"}},
		"data de outro tipo": {typ: contract.EventAgentOnline, tenant: "acme", at: at,
			data: contract.DataTaskStatusChanged{TaskID: uuidTask1, From: "", To: "New"}},
		"instante antes do ano 1": {typ: contract.EventAgentOnline, tenant: "acme",
			at:   time.Date(0, 1, 1, 0, 0, 0, 0, time.UTC),
			data: contract.DataAgentPresence{AgentID: "win-01"}},
	}
	for name, p := range cases {
		if _, _, err := build(uuidN(1), p); err == nil {
			t.Errorf("%s: virou evento", name)
		}
	}
	if _, _, err := build("não é uuid", validEvents()[0].pending); err == nil {
		t.Error("event_id inválido virou evento")
	}
}

// A checagem dos bytes de um evento (a mesma que o boot aplica ao que lê do disco) recusa o que não é exatamente a
// forma compacta de um evento válido.
func TestChecagemDosBytesDoEvento(t *testing.T) {
	_, enc, err := build(uuidN(1), validEvents()[1].pending)
	if err != nil {
		t.Fatal(err)
	}
	head, _, _ := strings.Cut(string(enc), `"data":`)
	bad := map[string]string{
		"com espaço":             strings.Replace(string(enc), `":"`, `": "`, 1),
		"membro a mais":          strings.Replace(string(enc), `{"event_id"`, `{"x":1,"event_id"`, 1),
		"data com membro a mais": strings.Replace(string(enc), `"data":{`, `"data":{"comment":"x",`, 1),
		"sem tenant":             strings.Replace(string(enc), `"tenant":"acme",`, ``, 1),
		"tenant nulo":            strings.Replace(string(enc), `"tenant":"acme"`, `"tenant":null`, 1),
		"data que não é objeto":  head + `"data":[]}`,
		"data vazio":             head + `"data":{}}`,
		"chave repetida":         strings.Replace(string(enc), `{"event_id"`, `{"type":"agent.online","event_id"`, 1),
		"vazio":                  "",
	}
	// valores válidos escritos de outro jeito: decodificam igual, mas não são os bytes que a montagem produz
	_, rej, err := build(uuidN(2), validEvents()[10].pending)
	if err != nil {
		t.Fatal(err)
	}
	esc := func(hex string) string { return `\` + "u" + hex } // o escape \uXXXX montado em tempo de execução
	bad["escape de um caractere comum no data"] = strings.Replace(string(rej), `"host fora`,
		`"`+esc("0068")+`ost fora`, 1)
	bad["escape de um caractere comum no evento"] = strings.Replace(string(rej), `"tenant":"acme"`,
		`"tenant":"`+esc("0061")+`cme"`, 1)
	bad["espaço no fim"] = string(rej) + " "
	if err := checkEventBytes(rej); err != nil {
		t.Fatal(err)
	}
	for name, b := range bad {
		if err := checkEventBytes([]byte(b)); err == nil {
			t.Errorf("%s: passou", name)
		}
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(head+`"data":[]}`), &m); err != nil {
		t.Fatalf("o caso do data que não é objeto precisa ser JSON válido: %v", err)
	}
}

func TestParseStaleHours(t *testing.T) {
	ok := map[string]int{"": DefaultStaleHours, "72": 72, "1": 1, "8760": MaxStaleHours, "24": 24}
	for in, want := range ok {
		if got, err := ParseStaleHours(in); err != nil || got != want {
			t.Errorf("ParseStaleHours(%q) = %d, %v", in, got, err)
		}
	}
	for _, in := range []string{"0", "-1", "8761", "072", "+72", "72h", " 72", "1e2", "72.0", "três dias",
		"99999999999999999999"} {
		if _, err := ParseStaleHours(in); err == nil {
			t.Errorf("ParseStaleHours(%q) aceitou", in)
		}
	}
	if DefaultStaleHours != 72 {
		t.Fatal("o FLEET_FEED_STALE_HOURS tem padrão 72")
	}
}
