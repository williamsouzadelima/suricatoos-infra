package state

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/williamsouzadelima/suricatoos-infra/fleet/contract"
)

// collectAuditTail is the audit_tail kind: audit.Tail() verbatim — the last lines of both local audit streams, as
// the files hold them, with first_seq, last_seq and head_sha256. Nothing is rewritten: the hub witnesses the
// chains, so a line is never cut or dropped here. A tail the schema would refuse (or whose head is not the hash of
// its last line) is an error of the kind, which keeps its last snapshot.
func (c *Collector) collectAuditTail() ([]byte, error) {
	tail := c.cfg.Audit.Tail()
	for _, s := range []*contract.AuditStreamTail{&tail.Exec, &tail.Reject} {
		if s.Lines == nil {
			s.Lines = []string{}
		}
		if err := checkStreamTail(*s); err != nil {
			return nil, err
		}
	}
	data, err := contract.MarshalCompact(tail)
	if err != nil {
		return nil, err
	}
	if len(data) > c.dataLimit { // unreachable: 2 × 200 lines of at most 8 KiB
		return nil, fmt.Errorf("state: audit_tail com %d bytes acima do teto", len(data))
	}
	return data, nil
}

// checkStreamTail applies fleet-state.schema.json#/$defs/audit_stream_tail.
func checkStreamTail(s contract.AuditStreamTail) error {
	if len(s.Lines) > maxAuditLines {
		return fmt.Errorf("state: cauda com %d linhas, acima de %d", len(s.Lines), maxAuditLines)
	}
	for _, l := range s.Lines {
		if !ruleAuditLine.ok(l) {
			return errors.New("state: linha de auditoria fora do schema na cauda")
		}
	}
	if len(s.Lines) == 0 {
		if s.FirstSeq != nil || s.LastSeq != nil || s.HeadSHA256 != nil {
			return errors.New("state: cauda vazia com seq ou cabeça")
		}
		return nil
	}
	if s.FirstSeq == nil || s.LastSeq == nil || s.HeadSHA256 == nil || *s.FirstSeq < 1 || *s.LastSeq < *s.FirstSeq {
		return errors.New("state: cauda sem first_seq, last_seq ou head_sha256 coerentes")
	}
	sum := sha256.Sum256([]byte(s.Lines[len(s.Lines)-1]))
	if *s.HeadSHA256 != hex.EncodeToString(sum[:]) {
		return errors.New("state: head_sha256 da cauda não é o hash da última linha")
	}
	return nil
}
