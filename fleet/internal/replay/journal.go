package replay

import (
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"regexp"
	"time"

	"github.com/williamsouzadelima/suricatoos-infra/fleet/contract"
)

// JobState is the step of the journal of an accepted command (ADR-0011 "Ack antes, resultado depois").
type JobState int

const (
	// StateReceived: accepted and recorded, not started.
	StateReceived JobState = iota + 1
	// StateExecuting: recorded right BEFORE the execution. At boot, a command still here never runs again: it is
	// reported failed with error.code = interrupted.
	StateExecuting
	// StateResult: how it ended is recorded (never the secret); the hub has not accepted the result yet.
	StateResult
	// StateDelivered: the hub accepted the result (2xx).
	StateDelivered
)

func (s JobState) String() string {
	switch s {
	case StateReceived:
		return "received"
	case StateExecuting:
		return "executing"
	case StateResult:
		return "result"
	case StateDelivered:
		return "delivered"
	}
	return "?"
}

// resultRef locates a result record in the current file, with the checksum the memory kept when it was confirmed.
type resultRef struct {
	off int64
	n   int32 // the whole line, '\n' included
	crc uint32
}

// job is the journal of an accepted entry, in memory.
type job struct {
	typ                           contract.CommandType
	tenant                        string
	state                         JobState
	execAt, resultAt, deliveredAt int64 // Unix ns; 0 = not there
	res                           resultRef
	status                        contract.ResultStatus
	code                          contract.ErrorCode
	tokenID                       string // enroll_token.create: the id of the token it created
	// restored: the job was loaded at boot — accepted by an earlier run of the connector. It never becomes executing:
	// after a restart such a command is reported (interrupted), never run late.
	restored bool
}

// Job is the journal of one accepted command, as the store answers it. CanonicalSHA256 and CommandID are its key in
// the journal methods.
type Job struct {
	CanonicalSHA256 string
	CommandID       string
	Type            contract.CommandType
	Tenant          string
	State           JobState
	Status          contract.ResultStatus // with a result
	ErrorCode       contract.ErrorCode    // with a failed result
	TokenID         string                // enroll_token.create with a result: the id of its token — never the token
}

func (s *Store) jobViewLocked(e *entry) Job {
	j := e.job
	return Job{CanonicalSHA256: hexOf(e.canon), CommandID: uuidString(e.cmd), Type: j.typ, Tenant: j.tenant,
		State: j.state, Status: j.status, ErrorCode: j.code, TokenID: j.tokenID}
}

// Result is the outcome of an accepted command as the journal keeps it: the body of the result report without what
// the entry already holds (command_id, node_id, type) and without contains_secret. For enroll_token.create the store
// keeps only the status, the error code and the token_id read from Output; the Output itself — the token, the only
// secret of the contract — never reaches a file, and Result does not give that type's result back (on a redelivery
// the node resends only the ack).
type Result struct {
	Status     contract.ResultStatus
	StartedAt  string
	FinishedAt string
	Error      *contract.ResultError
	Output     json.RawMessage
	Artifacts  []contract.Artifact
}

var (
	reTokenID  = regexp.MustCompile(contract.PatternTokenID)
	errorCodes = map[contract.ErrorCode]bool{
		contract.ErrorNotFound: true, contract.ErrorConflict: true, contract.ErrorGVM: true, contract.ErrorTimeout: true,
		contract.ErrorInterrupted: true, contract.ErrorUnavailable: true, contract.ErrorArtifactTooLarge: true,
		contract.ErrorArtifactUploadFailed: true, contract.ErrorSecretLost: true, contract.ErrorInternal: true,
	}
)

// checkOutcome checks what every stored result needs: a status, with an error (and a known code) exactly when it
// failed, and its instants as utc_time.
func checkOutcome(status contract.ResultStatus, code contract.ErrorCode, started, finished string, needTimes bool) error {
	switch status {
	case contract.StatusSucceeded:
		if code != "" {
			return invalid("resultado succeeded com erro")
		}
	case contract.StatusFailed:
		if !errorCodes[code] {
			return invalid("resultado failed sem código de erro do contrato")
		}
	default:
		return invalid("status de resultado fora do contrato")
	}
	if needTimes {
		if _, err := contract.ParseUTCTime(started); err != nil {
			return invalid("started_at fora da forma utc_time")
		}
		if _, err := contract.ParseUTCTime(finished); err != nil {
			return invalid("finished_at fora da forma utc_time")
		}
	}
	return nil
}

// replacesWithSecretLost reports whether a result of j may replace the one it has: only for enroll_token.create whose
// succeeded result the hub has not accepted, by failed with secret_lost — the authoritative revocation the node
// reports after a restart lost the token.
func replacesWithSecretLost(j *job, status contract.ResultStatus, code contract.ErrorCode) bool {
	return j.state == StateResult && j.typ == contract.TypeEnrollTokenCreate && j.status == contract.StatusSucceeded &&
		status == contract.StatusFailed && code == contract.ErrorSecretLost
}

// applyJournalLocked takes one journal record of the boot read, under the order of the steps.
func (s *Store) applyJournalLocked(e *entry, r record, off, n int64, crc uint32) error {
	j := e.job
	if r.Nonce != "" || r.Cmd != "" || r.Type != "" || r.Tenant != "" || r.Decision != "" || r.Reason != "" || r.Expires != 0 || r.Version != 0 {
		return errors.New("passo do journal com membros fora do lugar")
	}
	switch r.K {
	case kindExec:
		if j.state != StateReceived || r.Result != nil || r.Status != "" || r.Code != "" || r.TokenID != "" {
			return errors.New("executing fora de ordem")
		}
		j.state, j.execAt = StateExecuting, r.At
	case kindDelivered:
		if j.state != StateResult || r.Result != nil || r.Status != "" || r.Code != "" || r.TokenID != "" {
			return errors.New("delivered sem resultado")
		}
		j.state, j.deliveredAt = StateDelivered, r.At
		s.pending--
	case kindResult:
		var status contract.ResultStatus
		var code contract.ErrorCode
		if j.typ == contract.TypeEnrollTokenCreate {
			status, code = contract.ResultStatus(r.Status), contract.ErrorCode(r.Code)
			if r.Result != nil || checkOutcome(status, code, "", "", false) != nil ||
				(r.TokenID != "" && (len(r.TokenID) < 8 || len(r.TokenID) > 64 || !reTokenID.MatchString(r.TokenID))) ||
				(status == contract.StatusSucceeded && r.TokenID == "") {
				return errors.New("resultado de enroll_token.create fora da forma sem segredo")
			}
		} else {
			if r.Result == nil || r.Status != "" || r.Code != "" || r.TokenID != "" {
				return errors.New("resultado fora da forma")
			}
			status = r.Result.Status
			if r.Result.Error != nil {
				code = r.Result.Error.Code
			}
			if checkOutcome(status, code, r.Result.StartedAt, r.Result.FinishedAt, true) != nil ||
				(status == contract.StatusFailed) != (r.Result.Error != nil) {
				return errors.New("resultado fora do contrato")
			}
		}
		switch {
		case j.state == StateReceived || j.state == StateExecuting:
			s.pending++
		case replacesWithSecretLost(j, status, code):
		default:
			return errors.New("resultado fora de ordem")
		}
		j.state, j.resultAt, j.status, j.code = StateResult, r.At, status, code
		if r.TokenID != "" {
			j.tokenID = r.TokenID
		}
		j.res = resultRef{off: off, n: int32(n), crc: crc}
	}
	return nil
}

// findJobLocked returns the live accepted entry with j's canonical form, found through its command_id.
func (s *Store) findJobLocked(j Job, t time.Time) (*entry, error) {
	canon, cmd := canonKey(j.CanonicalSHA256), cmdKey(j.CommandID)
	head, ok := s.byCmd[cmd]
	if !ok {
		return nil, ErrNoJob
	}
	for i := head; i >= 0; i = s.entries[i].nextCmd {
		if e := &s.entries[i]; e.canon == canon && e.job != nil && alive(e, t) {
			return e, nil
		}
	}
	return nil, ErrNoJob
}

// journalStep appends line for the job j and, once it is durable, applies step to the job in memory (found again:
// an append may rewrite the file, and the entries move).
func (s *Store) journalStep(j Job, t time.Time, line []byte, step func(e *entry, off int64)) error {
	off, err := s.appendLocked(line, true, t)
	if err != nil {
		return err
	}
	e, err := s.findJobLocked(j, t)
	if err != nil {
		return err // unreachable: a rewrite keeps every live entry
	}
	step(e, off)
	return nil
}

// MarkExecuting records that the accepted command j is about to run (received → executing): the executor calls it
// BEFORE the execution and runs the command only when it returns nil. A command accepted by an earlier run of the
// connector (loaded at boot: Recovery.Interrupted) is ErrJobState — it is reported interrupted, never run late.
func (s *Store) MarkExecuting(j Job, t time.Time) error {
	if !validInstant(t) {
		return invalid("instante inválido")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	e, err := s.findJobLocked(j, t)
	if err != nil {
		return err
	}
	if e.job.restored {
		return fmt.Errorf("%w: aceito antes do reinício do conector; nunca roda (reportar interrupted)", ErrJobState)
	}
	if e.job.state != StateReceived {
		return ErrJobState
	}
	at := t.UnixNano()
	line, err := encodeLine(record{K: kindExec, Canon: hexOf(e.canon), At: at})
	if err != nil {
		return err
	}
	return s.journalStep(j, t, line, func(e *entry, _ int64) { e.job.state, e.job.execAt = StateExecuting, at })
}

// RecordResult records how the accepted command j ended (received or executing → result), before the result is
// reported. For enroll_token.create it keeps only the status, the error code and the token_id of Output (the token
// never reaches the file); a succeeded result whose Output does not hold a token_id is ErrInvalid. A result is
// recorded once — except that a succeeded enroll_token.create the hub has not accepted may be replaced by failed with
// secret_lost, the report after a restart lost the token.
func (s *Store) RecordResult(j Job, r Result, t time.Time) error {
	if !validInstant(t) {
		return invalid("instante inválido")
	}
	var code contract.ErrorCode
	if r.Error != nil {
		code = r.Error.Code
	}
	if err := checkOutcome(r.Status, code, r.StartedAt, r.FinishedAt, true); err != nil {
		return err
	}
	if (r.Status == contract.StatusFailed) != (r.Error != nil) {
		return invalid("error só (e sempre) num resultado failed")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	e, err := s.findJobLocked(j, t)
	if err != nil {
		return err
	}
	ej := e.job
	replacing := replacesWithSecretLost(ej, r.Status, code)
	if ej.state != StateReceived && ej.state != StateExecuting && !replacing {
		return ErrJobState
	}
	at := t.UnixNano()
	rec := record{K: kindResult, Canon: hexOf(e.canon), At: at}
	tokenID := ej.tokenID
	if ej.typ == contract.TypeEnrollTokenCreate {
		rec.Status, rec.Code = string(r.Status), string(code)
		if r.Status == contract.StatusSucceeded {
			var out contract.OutputEnrollTokenCreate
			if err := contract.DecodeStrict(r.Output, &out); err != nil || len(out.TokenID) < 8 || len(out.TokenID) > 64 ||
				!reTokenID.MatchString(out.TokenID) {
				return invalid("saída de enroll_token.create sem token_id válido")
			}
			tokenID = out.TokenID
		}
		rec.TokenID = tokenID
	} else {
		if len(r.Output) > 0 && !json.Valid(r.Output) {
			return invalid("output não é JSON")
		}
		rec.Result = &wireResult{Status: r.Status, StartedAt: r.StartedAt, FinishedAt: r.FinishedAt, Error: r.Error,
			Output: r.Output, Artifacts: r.Artifacts}
	}
	line, err := encodeLine(rec)
	if err != nil {
		return err
	}
	crc := crc32.Checksum(line[9:len(line)-1], castagnoli)
	return s.journalStep(j, t, line, func(e *entry, off int64) {
		if !replacing {
			s.pending++
		}
		ej := e.job
		ej.state, ej.resultAt, ej.status, ej.code, ej.tokenID = StateResult, at, r.Status, code, tokenID
		ej.res = resultRef{off: off, n: int32(len(line)), crc: crc}
	})
}

// MarkDelivered records that the hub accepted the result of j (result → delivered). now is the wall clock; the step
// is dated, and the job looked up, by the verification clock t = max(now, watermark).
func (s *Store) MarkDelivered(j Job, now time.Time) error {
	t := s.clk.Now(now)
	if !validInstant(t) {
		return invalid("instante inválido")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	e, err := s.findJobLocked(j, t)
	if err != nil {
		return err
	}
	if e.job.state != StateResult {
		return ErrJobState
	}
	at := t.UnixNano()
	line, err := encodeLine(record{K: kindDelivered, Canon: hexOf(e.canon), At: at})
	if err != nil {
		return err
	}
	return s.journalStep(j, t, line, func(e *entry, _ int64) {
		e.job.state, e.job.deliveredAt = StateDelivered, at
		s.pending--
	})
}

// Result returns the recorded result of j, to resend it (a redelivery, or a result the hub has not accepted yet). ok
// is false when j has no result yet, and always for enroll_token.create (its result is never kept: only the ack is
// resent). The record is read back from the file and must carry the checksum the memory kept when it was confirmed.
func (s *Store) Result(j Job, t time.Time) (Result, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.unconfirmed { // like Lookup: nothing the boot read is given back before it is durable
		if err := s.readyLocked(t); err != nil {
			return Result{}, false, err
		}
	}
	e, err := s.findJobLocked(j, t)
	if err != nil {
		return Result{}, false, err
	}
	if e.job.state < StateResult || e.job.typ == contract.TypeEnrollTokenCreate {
		return Result{}, false, nil
	}
	f, err := s.cfg.ops.openRead(s.path)
	if err != nil {
		return Result{}, false, err
	}
	defer f.Close()
	line, err := readRecordAt(f, e.job.res)
	if err != nil {
		return Result{}, false, err
	}
	r, err := decodeLine(line[:len(line)-1])
	if err != nil || r.K != kindResult || r.Result == nil {
		return Result{}, false, errors.New("replay: o registro do resultado não é um resultado")
	}
	w := r.Result
	return Result{Status: w.Status, StartedAt: w.StartedAt, FinishedAt: w.FinishedAt, Error: w.Error, Output: w.Output,
		Artifacts: w.Artifacts}, true, nil
}

// secretFreeRecord is the result record of an enroll_token.create, from memory: status, code and token_id only.
func secretFreeRecord(e *entry) record {
	j := e.job
	return record{K: kindResult, Canon: hexOf(e.canon), At: j.resultAt, Status: string(j.status), Code: string(j.code),
		TokenID: j.tokenID}
}
