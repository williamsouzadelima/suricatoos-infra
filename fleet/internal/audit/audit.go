// Package audit keeps the fleet node's local audit (ADR-0011 "Auditoria local"): two append-only streams of JSON
// lines, each its own hash chain, that the hub later witnesses through the audit_tail state.
//
// # Streams
//
// FLEET_STATE_DIR/audit-exec.jsonl (stream exec) records connector_started, identity_changed and policy_changed,
// and, for each ACCEPTED command, received → executed → result. FLEET_STATE_DIR/audit-reject.jsonl (stream reject)
// records rejected and deferred, with their reason, the periodic unauthenticated and redelivered counts, and
// version_mismatch. Each line is one fleet-state.schema.json#/$defs/audit_entry, compact (contract.MarshalCompact),
// and is checked with contract.DecodeStrict against contract.AuditEntry before it is written. The members follow
// the order of the contract's examples (status and error_code right after payload_sha256), so the examples come out
// byte for byte; the order is not normative.
//
// # Chain and durability
//
// seq grows by one per line of the same stream, across rotation; prev_sha256 is the SHA-256 of the exact bytes of
// the previous line of the same stream, without its '\n'; the first line of each stream carries 64 zeros. A line
// goes to the current file with O_APPEND and is fsynced (and, in a file with no line yet, the directory is synced
// first) BEFORE the method returns: an error means the line does not count, and the caller must not proceed to the
// effect it records. After a failed write or fsync the file is cut back to its size before the write; when that
// cut fails too — or the file changed underneath, or any other failure leaves its state unknown — the stream is
// poisoned: it refuses every append (ErrPoisoned) until the next Open, so no line is ever appended after garbage.
// An error from the fsutil primitives, ErrNotDurable included, is such a failure. A COMPLETE line whose fsync never
// returned before a crash survives as a valid line: a line records the intent, written before the effect.
//
// # Rotation
//
// Each stream rotates before the line that would take its current file past MaxFileBytes: the current file becomes
// ".1", the older ones move up and the oldest goes, so that exec keeps at most ExecFiles files (256 MiB) and reject
// RejectFiles (128 MiB) — separate budgets: a flood of rejections never rotates away what was executed. The chain
// continues into the new file. A line is at most MaxLineBytes: the fields are bounded first (object_ids at most 17
// distinct, the first 64 hosts plus hosts_count, texts cut), and a line still over the cap is the caller's error,
// never cut in the middle of its JSON.
//
// # Anti-flood
//
// unauthenticated and redelivered are counts, never one line per envelope: at most one line of each per minute,
// and at most one version_mismatch per 10 minutes. Time is always a parameter — the verification clock of the
// caller. See Unauthenticated, Redelivered, VersionMismatch and Flush.
//
// # Boot
//
// Open reads every file of each stream, from the oldest, and resumes seq and the hash of the last COMPLETE line. A
// partial last line in the current file — a crash in the middle of an append — is cut away: it was written before
// its effect and never confirmed, so the effect never happened, and its seq and hash never left the node. The v1
// contract has no audit event for that, so it is reported outside the stream: Status (Recovery.DiscardedBytes and
// DiscardedAt) and one log line. A chain broken in the middle (tampering, corruption) is not repaired: the stream
// goes on from its last line and the break is exposed in Status (Recovery.Breaks, FirstBreak) and in one log line;
// the hub, which has seen the earlier tails, is the witness. The files are read without following a symbolic link
// (fsutil.OpenRegularNoFollow): a link in place of one of them, like a file that cannot be read, makes Open fail.
//
// # Tail
//
// Tail returns, for the audit_tail state, the last TailLines lines of each stream verbatim with first_seq,
// last_seq and head_sha256. It comes from memory — the lines this Log confirmed plus those Open read — never from
// re-reading a file after a write that was not confirmed. Only audit lines of the stream get there: a line Open
// found that is not one (another file's content, say) makes the tail restart after it.
//
// # No secret
//
// The input types (Ref, Command, Outcome) have no field for a payload, an output or a secret: the only secret of
// the contract, the token in the output of enroll_token.create, cannot reach the audit.
//
// A Log is safe for concurrent use; each stream has its own lock.
package audit

import (
	"errors"
	"log/slog"
	"time"

	"github.com/williamsouzadelima/suricatoos-infra/fleet/contract"
)

// Options are what only the caller knows.
type Options struct {
	// Logger receives one line for each fact of the boot recovery (a partial last line discarded, a broken chain)
	// and one when a stream starts refusing appends. nil discards them; Status reports the same facts.
	Logger *slog.Logger
}

// Log is the node's local audit: the exec and reject streams of FLEET_STATE_DIR.
type Log struct {
	exec, reject *stream
}

// config is the fixed shape of the two streams and the file system calls (a test shrinks the budgets and makes
// calls fail).
type config struct {
	exec, reject streamSpec
	ops          fileOps
}

func defaultConfig() config {
	return config{
		exec:   streamSpec{name: contract.StreamExec, file: ExecFileName, maxBytes: MaxFileBytes, maxFiles: ExecFiles},
		reject: streamSpec{name: contract.StreamReject, file: RejectFileName, maxBytes: MaxFileBytes, maxFiles: RejectFiles},
		ops:    defaultOps(),
	}
}

// Open reads the audit in stateDir (FLEET_STATE_DIR) and returns it ready to append. boot is the verification
// clock at start (it dates what the recovery found). See the package documentation for what the recovery does;
// the only errors are an empty stateDir, an invalid boot and a file that cannot be read.
func Open(stateDir string, boot time.Time, opts Options) (*Log, error) {
	return open(stateDir, boot, opts, defaultConfig())
}

func open(stateDir string, boot time.Time, opts Options, cfg config) (*Log, error) {
	if stateDir == "" {
		return nil, errors.New("audit: FLEET_STATE_DIR vazio")
	}
	bootAt, _, err := stamp(boot)
	if err != nil {
		return nil, errors.New("audit: boot não é um instante válido: precisa ser o relógio de verificação")
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	l := &Log{
		exec:   newStream(stateDir, cfg.exec, cfg.ops, logger),
		reject: newStream(stateDir, cfg.reject, cfg.ops, logger),
	}
	if _, err := l.exec.recover(boot.UTC()); err != nil {
		return nil, err
	}
	sc, err := l.reject.recover(boot.UTC())
	if err != nil {
		return nil, err
	}
	l.reject.flood = newFlood(bootAt, sc.last)
	return l, nil
}

// stamp renders t as the at of a line — utc_time: UTC, whole seconds — and returns that instant too. The zero time
// and instants outside the years 0001–9999 are ErrInvalid.
func stamp(t time.Time) (time.Time, string, error) {
	if t.IsZero() {
		return time.Time{}, "", invalid("instante zero")
	}
	s := contract.FormatUTCTime(t)
	v, err := contract.ParseUTCTime(s)
	if err != nil {
		return time.Time{}, "", invalid("instante fora dos anos 0001–9999")
	}
	return v, s, nil
}

// append writes e to the stream under its lock.
func (s *stream) append(e *entry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.appendLocked(e)
}

// build stamps t and appends the line build makes for it to s.
func (s *stream) build(t time.Time, build func(at string) (*entry, error)) error {
	_, at, err := stamp(t)
	if err != nil {
		return err
	}
	e, err := build(at)
	if err != nil {
		return err
	}
	return s.append(e)
}

func lifecycle(ev contract.AuditEvent, detail string) func(string) (*entry, error) {
	return func(at string) (*entry, error) { return newLifecycle(at, ev, detail), nil }
}

// ConnectorStarted records, in the exec stream, that the connector started (detail: its version and node kind,
// say).
func (l *Log) ConnectorStarted(t time.Time, detail string) error {
	return l.exec.build(t, lifecycle(contract.AuditEventConnectorStarted, detail))
}

// IdentityChanged records, in the exec stream, a new identity of the node (an enroll or a renew).
func (l *Log) IdentityChanged(t time.Time, detail string) error {
	return l.exec.build(t, lifecycle(contract.AuditEventIdentityChanged, detail))
}

// PolicyChanged records, in the exec stream, that the local policy changed (detail: its new policy_sha256, say).
func (l *Log) PolicyChanged(t time.Time, detail string) error {
	return l.exec.build(t, lifecycle(contract.AuditEventPolicyChanged, detail))
}

// Received records, in the exec stream, an ACCEPTED command, before its ack and before any effect.
func (l *Log) Received(t time.Time, c Command) error {
	return l.exec.build(t, func(at string) (*entry, error) { return newReceived(at, c) })
}

// Executed records, in the exec stream, that the command is about to run: it is written before the execution.
func (l *Log) Executed(t time.Time, r Ref) error {
	return l.exec.build(t, func(at string) (*entry, error) { return newExecuted(at, r) })
}

// Result records, in the exec stream, how an accepted command ended, before the result is reported.
func (l *Log) Result(t time.Time, r Ref, o Outcome) error {
	return l.exec.build(t, func(at string) (*entry, error) { return newResult(at, r, o) })
}

// Rejected records, in the reject stream, a final rejection (verification lines 3–9) before its ack.
func (l *Log) Rejected(t time.Time, c Command, reason contract.RejectReason, detail string) error {
	return l.reject.build(t, func(at string) (*entry, error) { return newRejected(at, c, reason, detail) })
}

// Deferred records, in the reject stream, a retryable refusal (not_yet_valid, unavailable) before its ack.
func (l *Log) Deferred(t time.Time, c Command, reason contract.RejectReason, detail string) error {
	return l.reject.build(t, func(at string) (*entry, error) { return newDeferred(at, c, reason, detail) })
}

// StreamStatus is what the audit knows about one stream, for the node's state, heartbeat and logs.
type StreamStatus struct {
	Seq        int64    // seq of the last line; 0 = none yet
	HeadSHA256 string   // sha256 of the last line; "" = none yet
	Recovery   Recovery // what Open found
	Poisoned   error    // non-nil: the stream refuses every append until the next Open, and why
}

// Status is the state of both streams.
type Status struct {
	Exec, Reject StreamStatus
}

// Status returns the state of both streams.
func (l *Log) Status() Status { return Status{Exec: l.exec.status(), Reject: l.reject.status()} }

func (s *stream) status() StreamStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.recovery
	if r.FirstBreak != nil {
		b := *r.FirstBreak
		r.FirstBreak = &b
	}
	return StreamStatus{Seq: s.seq, HeadSHA256: s.head, Recovery: r, Poisoned: s.poisoned}
}
