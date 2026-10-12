package events

import (
	"errors"
	"fmt"
	"time"

	"github.com/williamsouzadelima/suricatoos-infra/fleet/contract"
	"github.com/williamsouzadelima/suricatoos-infra/fleet/internal/verifier"
)

// ConnectorStarted enqueues connector.started (node scope, without tenant): the connector calls it once, at its start,
// with its version and the policy_sha256 of the local policy in force (policy.Load); the node kind is the outbox's.
// An error means the event is not in the outbox: a value outside the schema, or a write that was not confirmed.
func (o *Outbox) ConnectorStarted(at time.Time, connectorVersion, policySHA256 string) error {
	return o.add(pending{typ: contract.EventConnectorStarted, at: at, data: contract.DataConnectorStarted{
		ConnectorVersion: connectorVersion, NodeKind: o.nodeKind, PolicySHA256: policySHA256}})
}

// RejectedByPolicy enqueues command.rejected_by_policy for an outcome of the verification pipeline that carries its
// signal — a final rejection of an authentic command at lines 6–9 (verifier.Outcome.PolicyEvent) —: the tenant of the
// envelope (PolicyEventTenant, also for tenant_unknown: the tenant the hub signed), the signal's data as the pipeline
// built it (command_id, type, reason and the fixed detail of the ack, never anything from the payload) and
// occurred_at = the ack's received_at, the verification clock of the decision. queued is false, with no error, for an
// outcome without the signal: an acceptance, a deferral, a rejection of lines 3–5, a redelivery (the event went with
// the decision, once) or no ack at all.
//
// The connector calls it before it sends the ack. An error means the event is not in the outbox (a signal outside the
// contract, or a write that was not confirmed); the ack still goes — it carries the same decision —, and the
// redelivery of that envelope gets the recorded decision without a new signal, so the event is lost, never doubled.
func (o *Outbox) RejectedByPolicy(out verifier.Outcome) (queued bool, err error) {
	if out.PolicyEvent == nil {
		return false, nil
	}
	if out.PolicyEventTenant == "" {
		return false, errors.New("events: sinal de rejeição sem o tenant do envelope")
	}
	at, err := contract.ParseUTCTime(out.Ack.ReceivedAt)
	if err != nil {
		return false, fmt.Errorf("events: received_at do ack inválido: %w", err)
	}
	d := *out.PolicyEvent
	d.Detail = clonePtr(d.Detail)
	if err := o.add(pending{typ: contract.EventCommandRejectedByPolicy, tenant: out.PolicyEventTenant, at: at,
		data: d}); err != nil {
		return false, err
	}
	return true, nil
}
