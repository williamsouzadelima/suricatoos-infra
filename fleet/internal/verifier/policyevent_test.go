package verifier

import (
	"strings"
	"testing"
	"time"

	"github.com/williamsouzadelima/suricatoos-infra/fleet/contract"
)

// O sinal de command.rejected_by_policy leva o tenant do envelope (o evento é de escopo tenant), em toda rejeição
// final das linhas 6–9 — inclusive tenant_unknown, cujo tenant é o que o hub assinou; sem sinal, sem tenant.
func TestSinalDoEventoLevaOTenantDoEnvelope(t *testing.T) {
	n := newNode(t)
	withTenant := func(name, tenantName string, typ contract.CommandType) contract.Command {
		c := command(name, typ)
		c.Tenant = tenantName
		return c
	}
	outside := strings.Replace(payloads[contract.TypeTargetCreate], `"198.51.100.10"`, `"203.0.113.10"`, 1)
	for _, c := range []struct {
		name    string
		cmd     contract.Command
		payload string
		reason  contract.RejectReason
	}{
		{"linha 6, desconhecido", withTenant("l6a", "desconhecido", contract.TypeTaskStart),
			payloads[contract.TypeTaskStart], contract.ReasonTenantUnknown},
		{"linha 6, desabilitado", withTenant("l6b", "initech", contract.TypeTaskStart),
			payloads[contract.TypeTaskStart], contract.ReasonTenantUnknown},
		{"linha 7", withTenant("l7", "globex", "foo.bar"), `{}`, contract.ReasonUnsupported},
		{"linha 8", withTenant("l8", "globex", contract.TypeTaskStart), `{"task_id":"x"}`, contract.ReasonBadPayload},
		{"linha 9", withTenant("l9", "acme", contract.TypeTargetCreate), outside, contract.ReasonScopeDenied},
	} {
		raw := signed(c.cmd, c.payload)
		o := n.process(raw, tv)
		expectAck(t, o, Ack, contract.DecisionRejected, c.reason)
		if o.PolicyEvent == nil || o.PolicyEvent.CommandID != c.cmd.CommandID || o.PolicyEventTenant != c.cmd.Tenant {
			t.Errorf("%s: evento %+v, tenant %q", c.name, o.PolicyEvent, o.PolicyEventTenant)
		}
		// a reentrega devolve a decisão gravada, sem sinal (o evento sai uma vez, da decisão nova)
		re := n.process(raw, tv.Add(time.Minute))
		if re.Kind != Redelivery || re.PolicyEvent != nil || re.PolicyEventTenant != "" {
			t.Errorf("%s: reentrega %v, evento %+v, tenant %q", c.name, re.Kind, re.PolicyEvent, re.PolicyEventTenant)
		}
	}
	o := n.process(env("aceito", contract.TypeTaskStart), tv)
	expectAck(t, o, Ack, contract.DecisionAccepted, "")
	if o.PolicyEvent != nil || o.PolicyEventTenant != "" {
		t.Fatalf("aceito com sinal: %+v, %q", o.PolicyEvent, o.PolicyEventTenant)
	}
	c := command("outro nó", contract.TypeTaskStart)
	c.NodeID = "node-lab-0002"
	if o := n.process(signed(c, payloads[contract.TypeTaskStart]), tv); o.PolicyEvent != nil || o.PolicyEventTenant != "" {
		t.Fatalf("linha 4 com sinal: %+v, %q", o.PolicyEvent, o.PolicyEventTenant)
	}
}
