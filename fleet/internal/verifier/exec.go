package verifier

import (
	"errors"
	"time"

	"github.com/williamsouzadelima/suricatoos-infra/fleet/internal/audit"
	"github.com/williamsouzadelima/suricatoos-infra/fleet/internal/replay"
)

// Begin records that an accepted command is about to run: the executed line (exec stream), then the journal step
// executing — both BEFORE the execution, the audit line first (a line never follows its effect). The executor runs
// the command if and only if Begin returned nil; a command whose Begin failed is reported failed, never run.
func (v *Verifier) Begin(j replay.Job, now time.Time) error {
	t := v.d.clock.Now(now)
	if err := v.d.audit.Executed(t, audit.Ref{CommandID: j.CommandID, Type: j.Type, Tenant: j.Tenant}); err != nil {
		return err
	}
	return v.d.store.MarkExecuting(j, t)
}

// Finish records how a command ended — the result line (exec stream), then the journal result (without the secret:
// the store keeps only status, code and token_id of an enroll_token.create) — before the result is reported. The
// connector reports it only once Finish returned nil. It also records the interrupted and secret_lost results the
// connector reports for what the boot exposed (replay.Recovery). o and r must describe the same outcome.
func (v *Verifier) Finish(j replay.Job, r replay.Result, o audit.Outcome, now time.Time) error {
	code := ""
	if r.Error != nil {
		code = string(r.Error.Code)
	}
	if o.Status != r.Status || string(o.ErrorCode) != code {
		return errors.New("verifier: a linha de auditoria e o resultado descrevem desfechos diferentes")
	}
	t := v.d.clock.Now(now)
	if err := v.d.audit.Result(t, audit.Ref{CommandID: j.CommandID, Type: j.Type, Tenant: j.Tenant}, o); err != nil {
		return err
	}
	return v.d.store.RecordResult(j, r, t)
}
