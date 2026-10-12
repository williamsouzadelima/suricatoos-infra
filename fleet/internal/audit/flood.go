package audit

import (
	"errors"
	"time"

	"github.com/williamsouzadelima/suricatoos-infra/fleet/contract"
)

// The anti-flood windows (ADR-0011 "Limites"), measured on the at of the lines.
const (
	// CountWindow: at most one unauthenticated line and one redelivered line per minute.
	CountWindow = time.Minute
	// VersionMismatchWindow: at most one version_mismatch line per 10 minutes.
	VersionMismatchWindow = 10 * time.Minute
)

// flood is the anti-flood state of the reject stream, guarded by its lock: the decision to write a line and the
// write are one step, so the limits hold under concurrent calls too.
type flood struct {
	unauth      contract.AuditUnauthenticated // the counts not written yet (Since unused here)
	unauthStart time.Time                     // start of the current period: the since of the next line
	redel       int64
	redelStart  time.Time
	lastVM      time.Time // at of the latest version_mismatch line; zero = none known
}

// newFlood starts the periods at boot or, when the stream holds a later line of the kind (a clock that went back),
// at that line; it resumes the last version_mismatch from the stream. So the limits hold across restarts.
func newFlood(boot time.Time, last map[contract.AuditEvent]chainFields) *flood {
	lastAt := func(ev contract.AuditEvent) time.Time {
		if p, ok := last[ev]; ok {
			if t, err := contract.ParseUTCTime(p.At); err == nil {
				return t
			}
		}
		return time.Time{}
	}
	later := func(a, b time.Time) time.Time {
		if b.After(a) {
			return b
		}
		return a
	}
	return &flood{
		unauthStart: later(boot, lastAt(contract.AuditEventUnauthenticated)),
		redelStart:  later(boot, lastAt(contract.AuditEventRedelivered)),
		lastVM:      lastAt(contract.AuditEventVersionMismatch),
	}
}

// Unauthenticated counts one envelope refused at verification lines 0–2 (bad_envelope, payload_mismatch,
// bad_signature; any other reason is ErrInvalid): such an envelope never gets a line of its own. The counts add up
// over a period that starts when the Log opens, or at the previous unauthenticated line, and go to the reject stream
// as one unauthenticated line — since = the start of the period — at the first count or Flush once the period is
// at least CountWindow long. Two such lines are therefore at least a minute apart (on their at) under any pattern
// of calls and across restarts. A line that cannot be written leaves its counts pending for the next one; the
// counts pending when the process stops are lost (the heartbeat's unauthenticated_rejections counts them too).
func (l *Log) Unauthenticated(t time.Time, reason contract.RejectReason) error {
	at, _, err := stamp(t)
	if err != nil {
		return err
	}
	s := l.reject
	s.mu.Lock()
	defer s.mu.Unlock()
	switch reason {
	case contract.ReasonBadEnvelope:
		s.flood.unauth.BadEnvelope++
	case contract.ReasonPayloadMismatch:
		s.flood.unauth.PayloadMismatch++
	case contract.ReasonBadSignature:
		s.flood.unauth.BadSignature++
	default:
		return invalid("unauthenticated só com bad_envelope, payload_mismatch ou bad_signature")
	}
	return s.flushUnauthenticatedLocked(at)
}

// Redelivered counts one envelope recognized at verification line 2a (its canonical form already recorded): it is
// answered with the recorded decision and never gets a line of its own. Same periods and limit as Unauthenticated,
// in redelivered lines.
func (l *Log) Redelivered(t time.Time) error {
	at, _, err := stamp(t)
	if err != nil {
		return err
	}
	s := l.reject
	s.mu.Lock()
	defer s.mu.Unlock()
	s.flood.redel++
	return s.flushRedeliveredLocked(at)
}

// Flush writes the pending counts of each kind whose period is at least CountWindow long. The connector calls it
// on a timer, so that the counts of a flood that stopped do not wait for the next envelope.
func (l *Log) Flush(t time.Time) error {
	at, _, err := stamp(t)
	if err != nil {
		return err
	}
	s := l.reject
	s.mu.Lock()
	defer s.mu.Unlock()
	return errors.Join(s.flushUnauthenticatedLocked(at), s.flushRedeliveredLocked(at))
}

// VersionMismatch records, in the reject stream, that the node entered blocked_version, with both announcements —
// at most one line per VersionMismatchWindow (measured from the last such line, also across restarts): one inside
// the window is dropped without a trace, since the line carries no count.
func (l *Log) VersionMismatch(t time.Time, node, hub []string) error {
	at, stamped, err := stamp(t)
	if err != nil {
		return err
	}
	e, err := newVersionMismatch(stamped, node, hub)
	if err != nil {
		return err
	}
	s := l.reject
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.flood.lastVM.IsZero() && at.Sub(s.flood.lastVM) < VersionMismatchWindow {
		return nil
	}
	if err := s.appendLocked(e); err != nil {
		return err
	}
	s.flood.lastVM = at
	return nil
}

func (s *stream) flushUnauthenticatedLocked(at time.Time) error {
	f := s.flood
	n := f.unauth
	if n.BadEnvelope+n.PayloadMismatch+n.BadSignature == 0 || at.Sub(f.unauthStart) < CountWindow {
		return nil
	}
	n.Since = contract.FormatUTCTime(f.unauthStart)
	if err := s.appendLocked(newUnauthenticated(contract.FormatUTCTime(at), n)); err != nil {
		return err
	}
	f.unauth, f.unauthStart = contract.AuditUnauthenticated{}, at
	return nil
}

func (s *stream) flushRedeliveredLocked(at time.Time) error {
	f := s.flood
	if f.redel == 0 || at.Sub(f.redelStart) < CountWindow {
		return nil
	}
	n := contract.AuditRedelivered{Since: contract.FormatUTCTime(f.redelStart), Count: f.redel}
	if err := s.appendLocked(newRedelivered(contract.FormatUTCTime(at), n)); err != nil {
		return err
	}
	f.redel, f.redelStart = 0, at
	return nil
}
