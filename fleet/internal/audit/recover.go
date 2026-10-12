package audit

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"time"
	"unicode/utf8"

	"github.com/williamsouzadelima/suricatoos-infra/fleet/contract"
)

// Recovery is what Open found in a stream's files. The v1 contract has no audit event for either fact, so they are
// reported here (and in one log line each), never as a line of the stream.
type Recovery struct {
	// DiscardedBytes is the size of a partial last line — bytes after the last '\n' of the current file: a crash in
	// the middle of an append — that Open cut away. Each line is written before its effect, and that append never
	// returned, so the effect never happened; the partial line's seq and hash never left the node, so the chain
	// goes on from the last complete line and the hub sees no gap. 0 = nothing was discarded.
	DiscardedBytes int64
	// DiscardedAt is the boot instant given to Open when bytes were discarded; the zero time otherwise.
	DiscardedAt time.Time
	// Breaks counts the complete lines that do not chain to the line before them (or are no audit line of this
	// stream at all), plus a partial line left in a rotated file. Nothing is repaired — the hub, which has seen
	// the earlier tails, is the witness — and the stream goes on from its last line. FirstBreak is the first one.
	Breaks     int
	FirstBreak *Break
}

// Break locates one broken link of a stream.
type Break struct {
	File   string // the file inside FLEET_STATE_DIR
	Line   int    // the line number in that file, from 1
	Seq    int64  // the seq the line carries, or the one it should have had when it carries none
	Reason string
}

// segment is one '\n'-terminated line of a file, or the partial bytes after the last '\n'.
type segment struct {
	text     []byte   // the line without its '\n'; nil when it is longer than MaxLineBytes
	sum      [32]byte // sha256 of the line without its '\n'
	n        int64    // length of the line without its '\n'
	complete bool     // it ended with '\n'
}

// lineReader splits a file into segments with bounded memory: a line longer than MaxLineBytes is hashed as it
// streams by and never held.
type lineReader struct {
	r   *bufio.Reader
	buf []byte
	h   hash.Hash
}

func newLineReader(r io.Reader) *lineReader {
	return &lineReader{r: bufio.NewReaderSize(r, 64<<10), buf: make([]byte, 0, MaxLineBytes), h: sha256.New()}
}

// next returns the next segment, or io.EOF when the file has no more bytes.
func (lr *lineReader) next() (segment, error) {
	var seg segment
	lr.buf = lr.buf[:0]
	lr.h.Reset()
	overlong := false
	for {
		chunk, err := lr.r.ReadSlice('\n')
		data := chunk
		if err == nil {
			data = chunk[:len(chunk)-1]
		}
		lr.h.Write(data)
		seg.n += int64(len(data))
		if !overlong {
			if len(lr.buf)+len(data) > MaxLineBytes {
				overlong = true
			} else {
				lr.buf = append(lr.buf, data...)
			}
		}
		switch {
		case err == nil:
			seg.complete = true
		case errors.Is(err, bufio.ErrBufferFull):
			continue
		case errors.Is(err, io.EOF):
			if seg.n == 0 {
				return segment{}, io.EOF
			}
		default:
			return segment{}, err
		}
		copy(seg.sum[:], lr.h.Sum(nil))
		if !overlong {
			seg.text = append([]byte(nil), lr.buf...)
		}
		return seg, nil
	}
}

// chainFields are the members the boot reads from each line: what the chain is made of (stream, seq,
// prev_sha256), and the event and its instant. A lenient decode is enough: any change to a line's bytes already
// breaks the prev_sha256 of the next one, and the schema validation of the lines is the hub's (each line this
// package writes passed DecodeStrict before it was written).
type chainFields struct {
	Stream contract.AuditStream `json:"stream"`
	Seq    int64                `json:"seq"`
	At     string               `json:"at"`
	Event  contract.AuditEvent  `json:"event"`
	Prev   string               `json:"prev_sha256"`
}

func parseChain(text []byte) (chainFields, bool) {
	var p chainFields
	if text == nil || json.Unmarshal(text, &p) != nil {
		return p, false
	}
	ok := (p.Stream == contract.StreamExec || p.Stream == contract.StreamReject) &&
		p.Seq >= 1 && p.Seq <= maxSeq && reSHA256.MatchString(p.Prev)
	return p, ok
}

// tailable reports whether a line can go into the audit_tail state as it is: the tail item's schema (2 to 8192
// characters, no_control) and valid UTF-8 (a JSON string carries nothing else verbatim).
func tailable(text []byte) bool {
	if len(text) < 2 || len(text) > MaxLineBytes || !utf8.Valid(text) {
		return false
	}
	for _, r := range string(text) {
		if isControl(r) {
			return false
		}
	}
	return true
}

// chainScan follows one stream's chain through its files, from the oldest line kept.
type chainScan struct {
	stream contract.AuditStream
	have   bool   // a complete line was seen
	seq    int64  // seq of the last complete line (the one it carries, or the one it should have had)
	head   string // hex sha256 of the last complete line
	tail   []tailLine
	breaks int
	first  *Break
	// last holds, for each event, the chain fields of its latest line (the anti-flood resumes from them)
	last map[contract.AuditEvent]chainFields
}

func (sc *chainScan) brk(file string, line int, seq int64, reason string) {
	sc.breaks++
	if sc.first == nil {
		sc.first = &Break{File: file, Line: line, Seq: seq, Reason: reason}
	}
}

// add takes one complete line: it checks the link to the line before — the hub's witness rule: this stream, seq
// +1, prev_sha256 = sha256 of the previous line, 64 zeros before seq 1; the first line kept may follow lines that
// were rotated away — and keeps the line for the tail.
func (sc *chainScan) add(seg segment, file string, line int) {
	want := sc.seq + 1
	p, ok := parseChain(seg.text)
	reason := ""
	switch {
	case seg.text == nil:
		reason = "linha acima do teto de 8 KiB"
	case !ok:
		reason = "não é uma linha de auditoria"
	case p.Stream != sc.stream:
		reason = "linha de outro fluxo"
	case !sc.have:
		if p.Seq == 1 && p.Prev != zeroSHA256 {
			reason = "1ª linha do fluxo sem os 64 zeros"
		}
	case p.Seq != want:
		reason = "seq fora de ordem"
	case p.Prev != sc.head:
		reason = "prev_sha256 não é o sha256 da linha anterior"
	}
	seq := want
	if ok {
		seq = p.Seq
	}
	if reason != "" {
		sc.brk(file, line, seq, reason)
	}
	sc.have, sc.seq, sc.head = true, seq, hex.EncodeToString(seg.sum[:])
	if ok && p.Stream == sc.stream {
		sc.last[p.Event] = p
	}
	if seg.text == nil || !tailable(seg.text) {
		sc.tail = sc.tail[:0] // the tail restarts after a line it cannot carry: the hub sees a gap, not a fix
		return
	}
	if len(sc.tail) == TailLines {
		copy(sc.tail, sc.tail[1:])
		sc.tail = sc.tail[:TailLines-1]
	}
	sc.tail = append(sc.tail, tailLine{seq: seq, text: string(seg.text)})
}

// scan reads one file: it returns the offset just after its last complete line, how many complete lines it has and
// the size of the partial bytes after them (0 when the file ends with '\n').
func (sc *chainScan) scan(r io.Reader, file string) (end int64, lines int, partial int64, err error) {
	lr := newLineReader(r)
	for {
		seg, err := lr.next()
		if err == io.EOF {
			return end, lines, 0, nil
		}
		if err != nil {
			return 0, 0, 0, err
		}
		if !seg.complete {
			return end, lines, seg.n, nil
		}
		lines++
		sc.add(seg, file, lines)
		end += seg.n + 1
	}
}

// recover reads every file of the stream, from the oldest (the highest number) to the current one, and leaves the
// stream ready to append after its last complete line: seq, hash and the last TailLines lines, the size of the
// current file and what it found. A partial last line of the current file is cut away (if the cut fails the stream
// is poisoned); a partial line in a rotated file is a break and stays. A file that cannot be read is an error:
// without its lines the chain cannot go on. It returns the scan, whose last lines of each event the anti-flood
// resumes from.
func (s *stream) recover(boot time.Time) (*chainScan, error) {
	idx, err := s.rotatedIndexes()
	if err != nil {
		return nil, fmt.Errorf("audit: listar %s: %w", s.dir, err)
	}
	sc := &chainScan{stream: s.spec.name, last: map[contract.AuditEvent]chainFields{}}
	for i := len(idx) - 1; i >= 0; i-- {
		if err := s.recoverFile(sc, idx[i], boot); err != nil {
			return nil, err
		}
	}
	if err := s.recoverFile(sc, 0, boot); err != nil {
		return nil, err
	}
	s.seq, s.head, s.tail = sc.seq, sc.head, sc.tail
	s.recovery.Breaks, s.recovery.FirstBreak = sc.breaks, sc.first
	if sc.first != nil {
		s.log.Warn("auditoria: cadeia quebrada no boot; nada é consertado e o fluxo segue da última linha",
			"fluxo", string(s.spec.name), "quebras", sc.breaks, "arquivo", sc.first.File, "linha", sc.first.Line,
			"seq", sc.first.Seq, "motivo", sc.first.Reason)
	}
	return sc, nil
}

// recoverFile scans the file i (0 = the current one) into sc.
func (s *stream) recoverFile(sc *chainScan, i int, boot time.Time) error {
	path, name := s.path(i), s.name(i)
	f, err := s.ops.openRead(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil // no current file yet, or a rotated one gone since the listing: nothing to read
	}
	if err != nil {
		return fmt.Errorf("audit: ler %s: %w", path, err)
	}
	end, lines, partial, err := sc.scan(f, name)
	f.Close()
	if err != nil {
		return fmt.Errorf("audit: ler %s: %w", path, err)
	}
	switch {
	case partial == 0:
		if i == 0 {
			s.size = end
		}
	case i > 0:
		sc.brk(name, lines+1, sc.seq+1, "linha parcial num arquivo girado")
	default:
		// the crash in the middle of an append: the partial bytes go, and the chain goes on from the last line
		if err := s.ops.truncate(path, end); err != nil {
			s.size = end + partial
			s.poisonLocked(fmt.Errorf("descartar a linha final parcial de %s (%d bytes): %w", path, partial, err))
			return nil
		}
		s.size = end
		s.recovery.DiscardedBytes, s.recovery.DiscardedAt = partial, boot
		s.log.Warn("auditoria: linha final parcial descartada no boot (queda no meio da escrita; o efeito não aconteceu)",
			"fluxo", string(s.spec.name), "arquivo", name, "bytes", partial, "em", contract.FormatUTCTime(boot))
	}
	return nil
}
