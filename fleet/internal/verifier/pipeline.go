package verifier

import (
	"errors"
	"slices"
	"time"

	"github.com/williamsouzadelima/suricatoos-infra/fleet/contract"
	"github.com/williamsouzadelima/suricatoos-infra/fleet/internal/admission"
	"github.com/williamsouzadelima/suricatoos-infra/fleet/internal/audit"
	"github.com/williamsouzadelima/suricatoos-infra/fleet/internal/budget"
	"github.com/williamsouzadelima/suricatoos-infra/fleet/internal/policy"
	"github.com/williamsouzadelima/suricatoos-infra/fleet/internal/replay"
	"github.com/williamsouzadelima/suricatoos-infra/fleet/internal/tenant"
)

// check is one authenticated envelope going through lines 2a–9.
type check struct {
	v   *Verifier
	ver *contract.Verified
	cmd contract.Command // one copy of the envelope, for every line
	t   time.Time        // the verification clock

	decodedOnce bool
	payload     any   // contract.DecodePayload's result
	payloadErr  error // its error (bad_payload, or ErrUnknownType)
	hosts       []string
	exclude     []string // the canonical lists of line 9, once it passed
}

// decoded decodes the payload once: line 8 refuses it, and every audit line takes its evidence from it.
func (c *check) decoded() (any, error) {
	if !c.decodedOnce {
		c.decodedOnce = true
		c.payload, c.payloadErr = contract.DecodePayload(c.cmd.Type, c.cmd.Payload)
	}
	return c.payload, c.payloadErr
}

// run is lines 3–9, then the acceptance.
func (c *check) run(recorded []string) Outcome {
	v := c.v

	// lines 3–4
	if err := c.ver.CheckAt(c.t, v.nodeID, v.skew); err != nil {
		var re *contract.RejectError
		if !errors.As(err, &re) {
			return c.unavailable(detailClock, err) // unreachable: the skew and the seal were checked
		}
		return c.refuse(re.Reason, re.Detail)
	}

	// line 5: another canonical form under the nonce or the command_id, then the replay floor
	if contract.ClassifyReplay(c.ver.CanonicalSHA256(), recorded) == contract.ReplayConflict {
		return c.refuse(contract.ReasonReplay, detailConflict)
	}
	if floor, ok := v.d.store.Floor(); ok && c.ver.IssuedAt().Before(ceilSecond(floor).Add(v.skew)) {
		return c.refuse(contract.ReasonReplay, detailFloor)
	}

	// lines 6–7. The policy is read only when the verdict needs it — the tenant (6) and the catalog and node kind
	// (7) do not —, so an unreadable policy.json never hides an earlier refusal; admission.Check decides all of them.
	st, err := v.tenants.Resolve(c.cmd.Tenant, c.cmd.Type)
	if err != nil {
		return c.unavailable(detailTenants, err)
	}
	var snap policy.Snapshot
	entry, inCatalog := contract.LookupType(c.cmd.Type)
	needPolicy := st.OK && inCatalog && entry.Supports(v.kind)
	if needPolicy {
		if snap, err = v.d.policy(); err != nil {
			return c.unavailable(detailPolicy, err)
		}
	}
	err = admission.Check(admission.Request{
		Type: c.cmd.Type, NodeKind: v.kind, LinksTasks: admission.LinksTasks(c.cmd.Type, c.cmd.Payload),
		Tenant: st, Policy: snap.Policy, Budgets: v.d.ledger, At: c.t,
	})
	var re *contract.RejectError
	refused := errors.As(err, &re)
	switch {
	case !needPolicy && !(refused && (re.Reason == contract.ReasonTenantUnknown || re.Reason == contract.ReasonUnsupported)):
		// without the policy only those two verdicts can come out: anything else would be a verdict on an empty policy
		return c.unavailable(detailPolicy, errors.New("verifier: veredito das linhas 6–7 sem a política"))
	case refused:
		return c.refuse(re.Reason, re.Detail)
	case err != nil:
		return c.unavailable(detailBudgets, err)
	}

	// line 8
	payload, err := c.decoded()
	if err != nil {
		return c.refuse(contract.ReasonBadPayload, detailBadPayload)
	}
	if export, ok := payload.(*contract.PayloadReportExport); ok {
		caps, err := v.formats()
		if err != nil {
			return c.unavailable(detailFormats, err)
		}
		if !advertised(caps, export) {
			return c.refuse(contract.ReasonUnsupportedReportVariant, detailVariant)
		}
	}

	// line 9
	sc, err := c.scope(st, payload)
	if err != nil {
		var d *deniedError
		if errors.As(err, &d) {
			return c.refuse(contract.ReasonScopeDenied, d.detail)
		}
		var u *unavailableError
		if errors.As(err, &u) {
			return c.unavailable(u.detail, u.err)
		}
		return c.unavailable(detailScopeRead, err)
	}
	c.hosts, c.exclude = sc.hosts, sc.exclude
	return c.accept(st, snap.Policy.TotalPerHour, snap.Policy.SensitivePerHour, payload)
}

// ceilSecond rounds t UP to the whole second: the floor as published (contract.FormatReplayFloor), so that the node
// compares in whole seconds what the hub sees.
func ceilSecond(t time.Time) time.Time {
	f := t.Truncate(time.Second)
	if f.Before(t) {
		f = f.Add(time.Second)
	}
	return f
}

// advertised reports whether the node advertises the (format, lang, variant) of an export.
func advertised(caps []contract.ReportFormatCapability, p *contract.PayloadReportExport) bool {
	for _, c := range caps {
		if c.Format == p.Format && c.Lang == p.Lang && slices.Contains(c.Variants, p.Variant) {
			return true
		}
	}
	return false
}

// refuse sends a refusal of lines 3–9 to its destination (contract.RejectReason.Class).
func (c *check) refuse(reason contract.RejectReason, detail string) Outcome {
	v := c.v
	switch reason.Class() {
	case contract.ClassFinalNotRecorded: // line 3: bad_window, expired
		// not recorded, so the watermark must be durable before the ack: a clock that went back across a reboot
		// must not answer this envelope differently
		if err := v.d.clock.Persist(); err != nil {
			return c.unavailable(detailClock, err)
		}
		if err := v.d.audit.Rejected(c.t, c.auditCommand(), reason, detail); err != nil {
			return c.noAck(err)
		}
		return c.ack(contract.DecisionRejected, reason, detail)

	case contract.ClassDeferred: // not_yet_valid
		if err := v.d.audit.Deferred(c.t, c.auditCommand(), reason, detail); err != nil {
			return c.noAck(err)
		}
		c.persistClock()
		return c.ack(contract.DecisionDeferred, reason, detail)

	case contract.ClassFinalRecorded: // lines 4–9: audited, then recorded, then acked
		if err := v.d.audit.Rejected(c.t, c.auditCommand(), reason, detail); err != nil {
			return c.noAck(err)
		}
		if _, err := v.d.store.Record(c.ver, replay.Decision{Decision: contract.DecisionRejected, Reason: reason}, c.t); err != nil {
			return c.unavailable(detailStore, err)
		}
		c.persistClock()
		out := c.ack(contract.DecisionRejected, reason, detail)
		if reason.PolicyEvent() {
			ev := &contract.DataCommandRejected{CommandID: c.cmd.CommandID, Type: c.cmd.Type, Reason: reason}
			if out.Ack.Detail != nil {
				d := *out.Ack.Detail // its own copy: the event and the ack travel apart
				ev.Detail = &d
			}
			out.PolicyEvent = ev
		}
		return out
	}
	return c.noAck(errors.New("verifier: motivo sem destino: " + string(reason))) // unreachable
}

// unavailable is the deferred answer to a local dependency that failed: nothing recorded, the audit line before the
// ack, and the cause in the log (never in the ack).
func (c *check) unavailable(detail string, cause error) Outcome {
	c.v.log.Warn("verificação: dependência local falhou; comando adiado (unavailable)",
		"command_id", c.cmd.CommandID, "causa", detail, "erro", errText(cause))
	if err := c.v.d.audit.Deferred(c.t, c.auditCommand(), contract.ReasonUnavailable, detail); err != nil {
		return c.noAck(err)
	}
	c.persistClock()
	return c.ack(contract.DecisionDeferred, contract.ReasonUnavailable, detail)
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// noAck is a decision whose audit line could not be written: no ack, so the hub redelivers.
func (c *check) noAck(err error) Outcome {
	c.v.log.Error("verificação: a linha de auditoria não foi gravada; sem ack", "command_id", c.cmd.CommandID, "erro", err.Error())
	return Outcome{Kind: NoAck, Err: err}
}

// persistClock makes the watermark durable when the decision does not depend on it (best effort; Tick keeps it).
func (c *check) persistClock() {
	if err := c.v.d.clock.Persist(); err != nil {
		c.v.log.Warn("verificação: marca d'água não gravada", "erro", err.Error())
	}
}

// accept consumes the budget, writes the received line and records the decision — in this order — and only then
// returns the accepted ack. The command runs if and only if all three succeeded.
func (c *check) accept(st tenant.Standing, total, sensitive int, payload any) Outcome {
	v := c.v
	if err := v.d.ledger.Consume(c.t, c.cmd.Type, budget.Limits{Total: total, Sensitive: sensitive}); err != nil {
		if errors.Is(err, budget.ErrOverBudget) {
			return c.refuse(contract.ReasonRateLimited, detailOverBudget)
		}
		return c.unavailable(detailBudgetWrite, err)
	}
	// the budget slot is spent: from here on a failure loses it (fail-closed)
	if err := v.d.audit.Received(c.t, c.auditCommand()); err != nil {
		return c.noAck(err)
	}
	e, err := v.d.store.Record(c.ver, replay.Decision{Decision: contract.DecisionAccepted}, c.t)
	if err != nil {
		return c.unavailable(detailStore, err)
	}
	if e.Job == nil {
		return c.unavailable(detailStore, errors.New("o store gravou o aceite sem journal")) // unreachable
	}
	c.persistClock()
	out := c.ack(contract.DecisionAccepted, "", "")
	out.Accepted = &Accepted{Command: c.cmd, Payload: payload, Hosts: c.hosts, ExcludeHosts: c.exclude, Tenant: st,
		Job: *e.Job, At: c.t}
	return out
}

// ack is the ack of a new decision, received at the verification clock.
func (c *check) ack(d contract.Decision, reason contract.RejectReason, detail string) Outcome {
	a := contract.Ack{SchemaVersion: contract.SchemaVersion, CommandID: c.cmd.CommandID, NodeID: c.v.nodeID,
		Decision: d, ReceivedAt: contract.FormatUTCTime(c.t)}
	if reason != "" {
		r := reason
		a.Reason = &r
	}
	if detail != "" {
		s := cleanDetail(detail)
		a.Detail = &s
	}
	return Outcome{Kind: Ack, Ack: a}
}

// redelivery is line 2a: the recorded ack (received_at = the recorded decision) and the recorded result — none for
// enroll_token.create, whose result is never kept. Nothing else is evaluated, nothing runs again; it only counts.
func (c *check) redelivery(e *replay.Entry) Outcome {
	v := c.v
	v.redeliveries.Add(1)
	if err := v.d.audit.Redelivered(c.t); err != nil {
		v.log.Warn("verificação: a contagem de reentrega não foi à auditoria (o total do heartbeat conta)", "erro", err.Error())
	}
	a := contract.Ack{SchemaVersion: contract.SchemaVersion, CommandID: c.cmd.CommandID, NodeID: v.nodeID,
		Decision: e.Decision, ReceivedAt: contract.FormatUTCTime(e.DecidedAt)}
	if e.Reason != "" {
		r := e.Reason
		a.Reason = &r
	}
	out := Outcome{Kind: Redelivery, Ack: a}
	if e.Job != nil && e.Job.Type != contract.TypeEnrollTokenCreate {
		r, ok, err := v.d.store.Result(*e.Job, c.t)
		switch {
		case err != nil:
			v.log.Warn("verificação: o resultado gravado não pôde ser relido; reentrega só com o ack",
				"command_id", c.cmd.CommandID, "erro", err.Error())
		case ok:
			out.Result = &r
		}
	}
	return out
}

// auditCommand is the envelope as its audit lines record it: who issued it, the hash of its payload and, when the
// payload decodes, the bounded evidence of ADR-0011 "Auditoria local" (object ids, hosts, report parameters).
func (c *check) auditCommand() audit.Command {
	ac := audit.Command{
		Ref:      audit.Ref{CommandID: c.cmd.CommandID, Type: c.cmd.Type, Tenant: c.cmd.Tenant},
		IssuedBy: c.cmd.IssuedBy, PayloadSHA256: c.cmd.PayloadSHA256,
	}
	payload, err := c.decoded()
	if err != nil {
		return ac
	}
	ac.ObjectIDs, ac.Hosts, ac.Report = evidence(payload, c.hosts)
	return ac
}
