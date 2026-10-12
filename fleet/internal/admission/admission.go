// Package admission is the gate of verification lines 6 and 7 of ADR-0011 ("Verificação no nó"): it takes what
// the node knows locally — the tenant, the catalog, the local policy, the two budgets — and says which is the
// FIRST reason, in the ADR's order, to refuse an authenticated command, or lets it through:
//
//	6  tenant known and enabled here (and, for a write, with a gvmd user and password)   tenant_unknown
//	7  type in the v1 catalog and supported by this node kind                            unsupported
//	7  type in the local policy's allow list                                             type_not_allowed
//	7  one more accepted command fits in both budgets                                    rate_limited
//
// The decision is a pure function of its Request: no clock (the instant is a field), no file (the tenant is
// already resolved, the policy already loaded), no write. The budgets are only ASKED (Budgets.Fits); consuming
// them is a separate step that belongs to the "accepted" decision (slice F2.4c), after lines 8 and 9 pass.
//
// The connector (F2.6) fills a Request like this, once per command, from ONE Command() of the envelope (it
// clones the payload at each call):
//
//	st, err := tenants.Resolve(cmd.Tenant, cmd.Type)             // err: answer unavailable (deferred)
//	snap, err := policy.Load(stateDir, kind)                     // err: answer unavailable (deferred)
//	err = admission.Check(admission.Request{
//	    Type: cmd.Type, NodeKind: kind, Tenant: st, Policy: snap.Policy, Budgets: ledger, At: t,
//	    LinksTasks: admission.LinksTasks(cmd.Type, cmd.Payload),
//	})                                                           // *contract.RejectError: ack it
//
// Lines 0–5 (contract.Verify, CheckAt, the anti-replay store) come before it; lines 8 and 9 (payload, scope) after.
package admission

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/williamsouzadelima/suricatoos-infra/fleet/contract"
	"github.com/williamsouzadelima/suricatoos-infra/fleet/internal/budget"
	"github.com/williamsouzadelima/suricatoos-infra/fleet/internal/policy"
	"github.com/williamsouzadelima/suricatoos-infra/fleet/internal/tenant"
)

// Budgets is the read-only question of line 7; *budget.Ledger implements it.
type Budgets interface {
	// Fits says which budgets have room for one more command of type typ at t. The implementation, not the gate,
	// decides which budgets that command counts in (the catalog says whether the type is sensitive), so the gate
	// and the later consumption cannot disagree. It must not consume anything.
	Fits(t time.Time, typ contract.CommandType, lim budget.Limits) (budget.Room, error)
}

var _ Budgets = (*budget.Ledger)(nil)

// Request is everything lines 6 and 7 look at, for one authenticated command.
type Request struct {
	// Type is the command type as received; it may be outside the v1 catalog (line 7 answers unsupported).
	Type contract.CommandType
	// NodeKind is the kind of this node.
	NodeKind contract.NodeKind
	// LinksTasks is true when the command is a schedule.create that carries task_ids (see LinksTasks).
	LinksTasks bool
	// Tenant is what the node's tenant source resolved for THIS Type (tenant.Source.Resolve). Its zero value is a
	// refusal.
	Tenant tenant.Standing
	// Policy is the local policy in force, loaded once for this command.
	Policy contract.Policy
	// Budgets is asked with the limits of Policy at the instant At.
	Budgets Budgets
	// At is the node's verification clock for this command.
	At time.Time
}

// Check returns nil when the command passes lines 6 and 7, or the first refusal in the ADR's order as a
// *contract.RejectError (Reason tenant_unknown, unsupported, type_not_allowed or rate_limited, and a short fixed
// Detail that never echoes the type or any other raw input; the caller adds the Envelope it is acking). Any other
// error is a misuse of Check (missing budgets), not a verdict.
func Check(r Request) error {
	if r.Budgets == nil {
		return errors.New("admission: Request.Budgets ausente")
	}

	// line 6
	if !r.Tenant.OK {
		return reject(contract.ReasonTenantUnknown, tenantDetail(r.Tenant.Why))
	}

	// line 7, in the ADR's order: catalog and node kind, then allow, then the budgets
	entry, ok := contract.LookupType(r.Type)
	if !ok {
		return reject(contract.ReasonUnsupported, "tipo fora do catálogo v1")
	}
	if !entry.Supports(r.NodeKind) {
		return reject(contract.ReasonUnsupported, "tipo não suportado por este node_kind")
	}
	if missing, absent := policy.Missing(r.Policy, r.Type, r.LinksTasks); absent {
		// missing is a catalog type here (r.Type passed the lookup above, or it is task.modify): safe to print
		return reject(contract.ReasonTypeNotAllowed, string(missing)+" fora de allow na política local")
	}
	lim := budget.Limits{Total: r.Policy.TotalPerHour, Sensitive: r.Policy.SensitivePerHour}
	room, err := r.Budgets.Fits(r.At, r.Type, lim)
	if err != nil {
		// the type was just found in the catalog, so this is not a verdict: the budgets could not answer
		return fmt.Errorf("admission: orçamentos: %w", err)
	}
	switch {
	case !room.Total:
		return reject(contract.ReasonRateLimited, "orçamento global de comandos aceitos esgotado")
	case !room.Sensitive:
		return reject(contract.ReasonRateLimited, "orçamento de comandos sensíveis esgotado")
	}
	return nil
}

func reject(reason contract.RejectReason, detail string) error {
	return &contract.RejectError{Reason: reason, Detail: detail}
}

func tenantDetail(w tenant.Why) string {
	switch w {
	case tenant.WhyDisabled:
		return "tenant desabilitado neste nó"
	case tenant.WhyNoGVMUser:
		return "tenant sem usuário gvmd de escrita neste nó"
	case tenant.WhyNoSecret:
		return "tenant sem senha gvmd neste nó"
	}
	return "tenant desconhecido neste nó" // WhyUnknown, and a Standing nobody filled
}

// LinksTasks tells line 7 whether a command is a schedule.create that carries task_ids — a member PRESENT, even
// as an empty list, since the schema reads "when task_ids is present" — from the raw payload bytes. Line 7 runs
// before line 8 validates the payload, so this is a lenient look at the top-level members, not a decode; after
// Verify the payload is already known to be a JSON object without duplicate members. The member name is
// compared exactly (line 8 refuses any other case). A payload that cannot be read at all counts as "carries
// task_ids": line 8 refuses it anyway, and a doubtful payload must never skip the rule. Any other type is false.
func LinksTasks(typ contract.CommandType, payload []byte) bool {
	if typ != contract.TypeScheduleCreate {
		return false
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(payload, &members); err != nil {
		return true
	}
	_, present := members["task_ids"]
	return present
}
