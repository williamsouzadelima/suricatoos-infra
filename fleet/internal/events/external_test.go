package events

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/williamsouzadelima/suricatoos-infra/fleet/contract"
	"github.com/williamsouzadelima/suricatoos-infra/fleet/internal/tenant"
	"github.com/williamsouzadelima/suricatoos-infra/fleet/internal/verifier"
)

// connector.started é de escopo nó: sem tenant, com a versão do conector, o node_kind da outbox e o policy_sha256.
func TestConnectorStarted(t *testing.T) {
	b := newBox(t)
	if err := b.ConnectorStarted(testAt, "1.4.0", policySHA); err != nil {
		t.Fatal(err)
	}
	b.expect(`connector.started - {"connector_version":"1.4.0","node_kind":"central","policy_sha256":"` +
		policySHA + `"}`)
	beforeYear1 := time.Time{}.Add(-time.Hour)
	for name, call := range map[string]func() error{
		"versão inválida":    func() error { return b.ConnectorStarted(testAt, "1.4 beta", policySHA) },
		"política inválida":  func() error { return b.ConnectorStarted(testAt, "1.4.0", "abc") },
		"instante sem ano 1": func() error { return b.ConnectorStarted(beforeYear1, "1.4.0", policySHA) },
	} {
		if err := call(); err == nil {
			t.Errorf("%s: enfileirou", name)
		}
	}
	if b.Len() != 0 {
		t.Fatal("um connector.started inválido entrou na outbox")
	}
	// gravação que falha: o chamador sabe e nada entra
	b.faults.set(func(f *faults) { f.syncErr = errDisco })
	if err := b.ConnectorStarted(testAt, "1.4.0", policySHA); err == nil || b.Len() != 0 {
		t.Fatalf("gravação que falhou: erro %v, Len %d", err, b.Len())
	}
}

// command.rejected_by_policy sai do sinal da pipeline (Outcome.PolicyEvent), com o tenant do envelope, o data do
// sinal tal como veio e occurred_at = received_at do ack; outcome sem sinal não vira evento.
func TestRejectedByPolicyDoSinal(t *testing.T) {
	b := newBox(t)
	detail := "orçamento esgotado (reconferido ao consumir)"
	out := verifier.Outcome{Kind: verifier.Ack,
		Ack: contract.Ack{SchemaVersion: contract.SchemaVersion, CommandID: uuidN(9), NodeID: testNode,
			Decision: contract.DecisionRejected, ReceivedAt: "2026-10-11T12:34:56Z"},
		PolicyEvent: &contract.DataCommandRejected{CommandID: uuidN(9), Type: contract.TypeReportExport,
			Reason: contract.ReasonRateLimited, Detail: &detail},
		PolicyEventTenant: "acme"}
	queued, err := b.RejectedByPolicy(out)
	if err != nil || !queued {
		t.Fatalf("queued %v, erro %v", queued, err)
	}
	got := b.expect(`command.rejected_by_policy acme {"command_id":"` + uuidN(9) +
		`","type":"report.export","reason":"rate_limited","detail":"orçamento esgotado (reconferido ao consumir)"}`)
	if got[0].OccurredAt != "2026-10-11T12:34:56Z" {
		t.Fatalf("occurred_at %s", got[0].OccurredAt)
	}
	for name, o := range map[string]verifier.Outcome{
		"aceito":    {Kind: verifier.Ack, Ack: contract.Ack{Decision: contract.DecisionAccepted}},
		"reentrega": {Kind: verifier.Redelivery, Ack: contract.Ack{Decision: contract.DecisionRejected}},
		"sem ack":   {Kind: verifier.NoAck},
	} {
		if queued, err := b.RejectedByPolicy(o); queued || err != nil {
			t.Errorf("%s: queued %v, erro %v", name, queued, err)
		}
	}
	// um sinal fora do contrato não vira evento
	for name, mutate := range map[string]func(o *verifier.Outcome){
		"sem tenant":          func(o *verifier.Outcome) { o.PolicyEventTenant = "" },
		"motivo da linha 5":   func(o *verifier.Outcome) { o.PolicyEvent.Reason = contract.ReasonReplay },
		"received_at ruim":    func(o *verifier.Outcome) { o.Ack.ReceivedAt = "2026-10-11 12:34:56" },
		"detalhe com quebra":  func(o *verifier.Outcome) { d := "a\nb"; o.PolicyEvent.Detail = &d },
		"command_id inválido": func(o *verifier.Outcome) { o.PolicyEvent.CommandID = "x" },
	} {
		o := out
		ev := *out.PolicyEvent
		o.PolicyEvent = &ev
		mutate(&o)
		if queued, err := b.RejectedByPolicy(o); queued || err == nil {
			t.Errorf("%s: queued %v, erro %v", name, queued, err)
		}
	}
	if b.Len() != 0 {
		t.Fatal("um sinal inválido entrou na outbox")
	}
}

// O caminho inteiro com a pipeline de verdade: um comando autêntico para um tenant que o nó não conhece é recusado na
// linha 6, e o sinal dele vira um command.rejected_by_policy desse tenant, com o motivo e o detalhe do ack; a
// reentrega do mesmo envelope devolve a decisão gravada e não gera outro evento.
func TestRejectedByPolicyComAPipelineDeVerdade(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
	st, err := verifier.OpenState(dir, now, verifier.StateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Store.Close() })
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	src, err := tenant.Open(contract.NodeStandalone, tenant.Config{Tenant: "acme", Scope: "192.0.2.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	v, err := verifier.New(verifier.Config{CommandKey: pub, NodeID: testNode, NodeKind: contract.NodeStandalone,
		Skew: 2 * time.Minute, StateDir: dir, Tenants: src, Scope: noScope{},
		ReportFormats: func() ([]contract.ReportFormatCapability, error) { return nil, nil }}, st)
	if err != nil {
		t.Fatal(err)
	}
	cmd := contract.Command{SchemaVersion: contract.SchemaVersion, CommandID: uuidN(42), NodeID: testNode,
		Tenant: "outro-cliente", Type: contract.TypeTaskStart, IssuedBy: "op-ficticio",
		IssuedAt: contract.FormatUTCTime(now.Add(-time.Minute)), NotAfter: contract.FormatUTCTime(now.Add(time.Hour)),
		Nonce: "4b1d9c0e7a3f5e2d8c6b4a29f7e5d3c1b9a8f6e4d2c0b8a6f4e2d0c8b6a4f2e0"}
	raw, err := contract.Sign(priv, cmd, []byte(`{"task_id":"`+uuidTask1+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	out := v.Process(raw, now)
	if out.Kind != verifier.Ack || out.Ack.Reason == nil || *out.Ack.Reason != contract.ReasonTenantUnknown {
		t.Fatalf("a pipeline não recusou na linha 6: %+v", out)
	}

	b := newBox(t)
	queued, err := b.RejectedByPolicy(out)
	if err != nil || !queued {
		t.Fatalf("queued %v, erro %v", queued, err)
	}
	got := b.drain()
	if len(got) != 1 || got[0].Type != contract.EventCommandRejectedByPolicy || got[0].Tenant == nil ||
		*got[0].Tenant != "outro-cliente" || got[0].OccurredAt != out.Ack.ReceivedAt {
		t.Fatalf("evento %+v", got)
	}
	d := decodeEventData(t, got[0]).(*contract.DataCommandRejected)
	if d.CommandID != cmd.CommandID || d.Type != cmd.Type || d.Reason != contract.ReasonTenantUnknown ||
		(d.Detail == nil) != (out.Ack.Detail == nil) || (d.Detail != nil && *d.Detail != *out.Ack.Detail) {
		t.Fatalf("data %+v, ack %+v", d, out.Ack)
	}
	again := v.Process(raw, now.Add(time.Minute))
	if again.Kind != verifier.Redelivery {
		t.Fatalf("a reentrega não foi reconhecida: %v", again.Kind)
	}
	if queued, err := b.RejectedByPolicy(again); queued || err != nil {
		t.Fatalf("reentrega virou evento: %v, %v", queued, err)
	}
}

// noScope é a linha 9 de um teste que não chega nela.
type noScope struct{}

var errNoScope = errors.New("linha 9 fora deste teste")

func (noScope) Gate(tenant.Standing) (verifier.Gate, error) { return nil, errNoScope }
func (noScope) Target(string, string) (verifier.TargetHosts, error) {
	return verifier.TargetHosts{}, errNoScope
}
func (noScope) Task(string, string) (verifier.TaskInfo, error) {
	return verifier.TaskInfo{}, errNoScope
}
func (noScope) ScheduleTasks(string, string) ([]string, error) { return nil, errNoScope }
