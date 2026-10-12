package replay

import (
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"

	"github.com/williamsouzadelima/suricatoos-infra/fleet/contract"
)

// The kinds of record of the log.
const (
	kindHead      = "head"      // the first record of every file: the format version
	kindFloor     = "floor"     // a replay floor (the latest one wins)
	kindEntry     = "entry"     // a decision, recorded before its ack
	kindExec      = "exec"      // journal: an accepted command is about to run
	kindResult    = "result"    // journal: how it ended (never the secret)
	kindDelivered = "delivered" // journal: the hub accepted the result (2xx)
)

// maxLineBytes caps one line (checksum, space, JSON, '\n'): a result record carries a result body of at most
// contract.MaxResultBytes plus its own members, with room to spare. A longer line is refused when written and is
// corruption when read.
const maxLineBytes = contract.MaxResultBytes + 16<<10

// ErrInvalid: an input the store refuses — a caller's bug or a value outside the contract. Nothing is written.
var ErrInvalid = errors.New("replay: entrada recusada pelo store")

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrInvalid}, args...)...)
}

// record is one line of the log. One flat shape for every kind keeps the strict decode simple; which members each
// kind carries is checked when the log is read (apply) and fixed when it is written. Every member is optional for
// the decoder (omitzero): the kind decides.
type record struct {
	K        string      `json:"k"`
	Version  int         `json:"version,omitzero"`  // head
	At       int64       `json:"at,omitzero"`       // Unix ns: the floor, the decision, the journal step
	Canon    string      `json:"canon,omitzero"`    // sha256 hex of the canonical form: the key of the entry
	Nonce    string      `json:"nonce,omitzero"`    // entry
	Cmd      string      `json:"cmd,omitzero"`      // entry: command_id
	Type     string      `json:"type,omitzero"`     // entry: the type as received
	Tenant   string      `json:"tenant,omitzero"`   // entry
	Decision string      `json:"decision,omitzero"` // entry: accepted | rejected
	Reason   string      `json:"reason,omitzero"`   // entry: the reason of a rejection
	Expires  int64       `json:"expires,omitzero"`  // entry: Unix seconds, the end of its life
	Result   *wireResult `json:"result,omitzero"`   // result of a type other than enroll_token.create
	Status   string      `json:"status,omitzero"`   // result of enroll_token.create: the status only...
	Code     string      `json:"code,omitzero"`     // ...the error code, when it failed...
	TokenID  string      `json:"token_id,omitzero"` // ...and the id (not the secret) of the token it created
}

// wireResult is a stored result (the body of the result report minus what the entry already holds).
type wireResult struct {
	Status     contract.ResultStatus `json:"status"`
	StartedAt  string                `json:"started_at"`
	FinishedAt string                `json:"finished_at"`
	Error      *contract.ResultError `json:"error,omitzero"`
	Output     json.RawMessage       `json:"output,omitzero"`
	Artifacts  []contract.Artifact   `json:"artifacts,omitzero"`
}

var castagnoli = crc32.MakeTable(crc32.Castagnoli)

// checksum is the CRC-32C of the JSON of a line, in 8 lowercase hex digits. It detects corruption (a torn or
// flipped write, a bad sector), not tampering: whoever can write FLEET_STATE_DIR can recompute it.
func checksum(js []byte) string { return fmt.Sprintf("%08x", crc32.Checksum(js, castagnoli)) }

// parseChecksum reads exactly 8 lowercase hex digits.
func parseChecksum(b []byte) (uint32, bool) {
	if len(b) != 8 {
		return 0, false
	}
	var v uint32
	for _, c := range b {
		switch {
		case c >= '0' && c <= '9':
			v = v<<4 | uint32(c-'0')
		case c >= 'a' && c <= 'f':
			v = v<<4 | uint32(c-'a'+10)
		default:
			return 0, false
		}
	}
	return v, true
}

// encodeLine renders r as one line: checksum, a space, the compact JSON (contract.MarshalCompact: the same bytes on
// every Go toolchain) and '\n'. A line over maxLineBytes is ErrInvalid.
func encodeLine(r record) ([]byte, error) {
	js, err := contract.MarshalCompact(r)
	if err != nil {
		return nil, invalid("serializar o registro: %v", err)
	}
	if len(js)+10 > maxLineBytes {
		return nil, invalid("registro de %d bytes acima do teto de uma linha", len(js))
	}
	line := make([]byte, 0, len(js)+10)
	line = append(line, checksum(js)...)
	line = append(line, ' ')
	line = append(line, js...)
	return append(line, '\n'), nil
}

// decodeLine reads one line without its '\n': the checksum must match the JSON, and the JSON must decode strictly
// (contract.DecodeStrict: no unknown or duplicate member, exact case, no null, integers only) as a record.
func decodeLine(line []byte) (record, error) {
	var r record
	if len(line) < 10 || line[8] != ' ' {
		return r, errors.New("linha sem checksum")
	}
	sum, ok := parseChecksum(line[:8])
	if !ok {
		return r, errors.New("checksum fora da forma de 8 hex minúsculos")
	}
	js := line[9:]
	if crc32.Checksum(js, castagnoli) != sum {
		return r, errors.New("checksum não confere")
	}
	if err := contract.DecodeStrict(js, &r); err != nil {
		return record{}, fmt.Errorf("registro: %w", err)
	}
	return r, nil
}
