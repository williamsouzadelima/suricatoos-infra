package audit

import (
	"crypto/sha256"
	"encoding/hex"

	"github.com/williamsouzadelima/suricatoos-infra/fleet/contract"
)

// Tail returns the data of the audit_tail state (fleet-state.schema.json#/$defs/data_audit_tail): for each stream,
// its last TailLines lines verbatim, first_seq and last_seq (the seq of the first and of the last line) and
// head_sha256 (the SHA-256 of the last line); a stream with no line has "lines": [] and none of the three. It comes
// from memory — the lines this Log confirmed and those Open read — so it never carries a line whose write was not
// confirmed, and every line of it decodes as a contract.AuditEntry of its stream. A line Open found that is no
// audit line of this stream (another file's content, the other stream's line, JSON that is not an audit_entry) or
// that the tail cannot carry as it is (over 8 KiB, invalid UTF-8, a control character) makes the tail restart after
// it: such a line never goes to the hub, which sees a jump in seq instead — its gap rule alerts.
func (l *Log) Tail() contract.DataAuditTail {
	return contract.DataAuditTail{Exec: l.exec.tailState(), Reject: l.reject.tailState()}
}

func (s *stream) tailState() contract.AuditStreamTail {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := contract.AuditStreamTail{Lines: make([]string, 0, len(s.tail))}
	for _, l := range s.tail {
		out.Lines = append(out.Lines, l.text)
	}
	if n := len(s.tail); n > 0 {
		sum := sha256.Sum256([]byte(s.tail[n-1].text))
		first, last, head := s.tail[0].seq, s.tail[n-1].seq, hex.EncodeToString(sum[:])
		out.FirstSeq, out.LastSeq, out.HeadSHA256 = &first, &last, &head
	}
	return out
}
