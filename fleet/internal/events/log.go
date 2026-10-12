package events

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"io/fs"
	"os"

	"github.com/williamsouzadelima/suricatoos-infra/fleet/contract"
	"github.com/williamsouzadelima/suricatoos-infra/fleet/internal/fsutil"
)

const (
	// FileName is the log of the outbox and of the baseline inside FLEET_STATE_DIR.
	FileName = "events.log"

	fileVersion = 1
	kindHead    = "head" // the first record of every file: the format version
	kindTx      = "tx"   // one change of the outbox and of the baseline, whole or not at all

	// maxLineBytes caps one line. The largest record is the first observation of a central node at every schema cap —
	// 20 000 agents with ids of 128 four-byte runes, 5 000 tasks and jobs, 2 000 reports — with a full outbox of the
	// events of one cycle: under 32 MiB.
	maxLineBytes = 64 << 20
	// compactSlack: the log is rewritten from memory once it holds more than twice what the last rewrite wrote plus
	// this.
	compactSlack = 1 << 20
)

// record is one line of the log: "<crc32c, 8 lowercase hex> <json>\n". A tx carries, in one line — so a crash keeps
// it whole or not at all —, a change of the baseline (Delta), the events that entered the outbox (Events, with their
// seq) and Done, the seq up to which every event has left the outbox (delivered or dropped): the head of the outbox
// after the change, repeated by every tx so that a later tx makes up for one whose write failed.
type record struct {
	K       string   `json:"k"`
	Version int      `json:"version,omitzero"`
	Delta   *delta   `json:"delta,omitzero"`
	Events  []stored `json:"events,omitzero"`
	Done    int64    `json:"done,omitzero"`
}

// stored is one event of a tx: its seq (the order of the outbox) and its exact bytes.
type stored struct {
	Seq   int64           `json:"seq"`
	Event json.RawMessage `json:"event"`
}

var castagnoli = crc32.MakeTable(crc32.Castagnoli)

// encodeLine renders r as one line: the CRC-32C of the JSON (it detects a torn or flipped write, not tampering), a
// space, the compact JSON and '\n'.
func encodeLine(r record) ([]byte, error) {
	js, err := contract.MarshalCompact(r)
	if err != nil {
		return nil, fmt.Errorf("events: serializar o registro: %w", err)
	}
	if len(js)+10 > maxLineBytes {
		return nil, fmt.Errorf("events: registro de %d bytes acima do teto de uma linha", len(js))
	}
	line := make([]byte, 0, len(js)+10)
	line = fmt.Appendf(line, "%08x ", crc32.Checksum(js, castagnoli))
	line = append(line, js...)
	return append(line, '\n'), nil
}

// decodeLine reads one line without its '\n': the checksum must match the JSON, and the JSON must decode strictly
// (contract.DecodeStrict) as a record.
func decodeLine(line []byte) (record, error) {
	var r record
	if len(line) < 10 || line[8] != ' ' {
		return r, errors.New("linha sem checksum")
	}
	var sum uint32
	for _, c := range line[:8] {
		switch {
		case c >= '0' && c <= '9':
			sum = sum<<4 | uint32(c-'0')
		case c >= 'a' && c <= 'f':
			sum = sum<<4 | uint32(c-'a'+10)
		default:
			return r, errors.New("checksum fora da forma de 8 hex minúsculos")
		}
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

// readLine reads one line of at most maxLineBytes (without its '\n'); a longer one is consumed and reported overlong,
// never held. n is the number of bytes consumed; complete is false for the bytes after the last '\n'.
func readLine(r *bufio.Reader) (line []byte, overlong bool, n int64, complete bool, err error) {
	var buf []byte
	for {
		chunk, rerr := r.ReadSlice('\n')
		n += int64(len(chunk))
		if !overlong {
			if len(buf)+len(chunk) > maxLineBytes {
				overlong, buf = true, nil
			} else {
				buf = append(buf, chunk...)
			}
		}
		switch {
		case rerr == nil:
			if !overlong {
				buf = buf[:len(buf)-1]
			}
			return buf, overlong, n, true, nil
		case errors.Is(rerr, bufio.ErrBufferFull):
			continue
		case errors.Is(rerr, io.EOF):
			return buf, overlong, n, false, nil
		default:
			return nil, false, 0, false, rerr
		}
	}
}

// appendFile is what an append needs of the open log: an *os.File (a test wraps it to make it fail).
type appendFile interface {
	Write(p []byte) (int, error)
	Sync() error
	Stat() (fs.FileInfo, error)
	Close() error
}

// fileOps are the file system calls of the outbox — fsutil by default; a test swaps one to make it fail.
type fileOps struct {
	openAppend  func(path string) (appendFile, error)
	openRead    func(path string) (*os.File, error)
	truncate    func(path string, size int64) error
	syncDir     func(dir string) error
	writeStream func(path string, fill func(io.Writer) error) error
}

func defaultOps() fileOps {
	return fileOps{
		openAppend: func(path string) (appendFile, error) {
			f, err := fsutil.OpenAppend(path)
			if err != nil {
				return nil, err // never a nil *os.File inside a non-nil interface
			}
			return f, nil
		},
		openRead:    fsutil.OpenRegularNoFollow,
		truncate:    fsutil.TruncateDurable,
		syncDir:     fsutil.SyncDir,
		writeStream: fsutil.WriteAtomicStream,
	}
}

// errChanged: the log is not the file this outbox left (another file in its place, another size).
var errChanged = errors.New("o arquivo de eventos mudou por fora (outro arquivo ou outro tamanho)")

// readyLocked makes the file fit for an append: a pending rewrite from memory, then the directory sync a rewrite still
// owes. Nothing is appended — and no event is handed out — before both succeeded: until then the file is not known to
// hold, durably, what the memory holds.
func (o *Outbox) readyLocked() error {
	if o.needRewrite != nil {
		if err := o.rewriteLocked(); err != nil && !errors.Is(err, fsutil.ErrNotDurable) {
			o.needRewrite = err
			return fmt.Errorf("events: o arquivo precisa ser reescrito e a reescrita falhou: %w", err)
		}
	}
	if o.needDirSync {
		if err := o.ops.syncDir(o.dir); err != nil {
			return fmt.Errorf("events: confirmar a reescrita do arquivo: %w", err)
		}
		o.needDirSync = false
	}
	return nil
}

// appendLocked makes the file ready and appends line. A file that changed underneath is rewritten from memory, then
// the line is appended once more.
func (o *Outbox) appendLocked(line []byte) error {
	if err := o.readyLocked(); err != nil {
		return err
	}
	err := o.writeLocked(line)
	if errors.Is(err, errChanged) {
		o.log.Warn("eventos: o arquivo mudou por fora; reescrito a partir da memória")
		if err := o.readyLocked(); err != nil {
			return err
		}
		err = o.writeLocked(line)
	}
	return err
}

// writeLocked appends line with O_APPEND and fsyncs it. The file must be the one this outbox left (same file, same
// size): otherwise nothing is written and the next write rewrites it from memory (errChanged). A failed write or fsync
// is cut back to the previous size; if the cut fails too, the next write rewrites the file from memory. Only a line
// whose fsync returned counts.
func (o *Outbox) writeLocked(line []byte) error {
	f, err := o.ops.openAppend(o.path)
	if err != nil {
		return fmt.Errorf("events: abrir %s: %w", o.path, err)
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return fmt.Errorf("events: medir %s: %w", o.path, err)
	}
	if (o.ident != nil && !os.SameFile(o.ident, fi)) || fi.Size() != o.size {
		f.Close()
		o.needRewrite = errChanged
		return errChanged
	}
	pre := fi.Size()
	_, werr := f.Write(line)
	if werr == nil {
		werr = f.Sync()
	}
	f.Close()
	if werr != nil {
		if terr := o.ops.truncate(o.path, pre); terr != nil {
			o.needRewrite = fmt.Errorf("o corte de volta de uma gravação que falhou também falhou: %w", terr)
			o.log.Error("eventos: gravação falhou e o corte de volta também; "+
				"a próxima gravação reescreve o arquivo a partir da memória",
				"erro", werr.Error(), "corte", terr.Error())
		}
		return fmt.Errorf("events: gravar em %s (não conta): %w", o.path, werr)
	}
	o.size, o.ident = pre+int64(len(line)), fi
	return nil
}

// rewriteLocked replaces the file with what the memory holds — the head, the whole baseline with the outbox's Done,
// then one tx per event of the outbox — through fsutil.WriteAtomicStream (temp + rename with fsync, 0600). On success,
// or on fsutil.ErrNotDurable (the new file is in place, its directory entry not confirmed: the next write syncs the
// directory first), the outbox appends to the new file; any other error leaves the old file and the state as they were.
func (o *Outbox) rewriteLocked() error {
	var written int64
	fill := func(w io.Writer) error {
		written = 0
		bw := bufio.NewWriterSize(w, 1<<20)
		put := func(r record) error {
			line, err := encodeLine(r)
			if err != nil {
				return err
			}
			n, err := bw.Write(line)
			written += int64(n)
			return err
		}
		if err := put(record{K: kindHead, Version: fileVersion}); err != nil {
			return err
		}
		first := record{K: kindTx, Done: o.head}
		if full := o.base.full(); !full.empty() {
			first.Delta = full
		}
		if first.Delta != nil || first.Done != 0 {
			if err := put(first); err != nil {
				return err
			}
		}
		for _, q := range o.queue {
			if err := put(record{K: kindTx, Events: []stored{{Seq: q.seq, Event: q.enc}}, Done: o.head}); err != nil {
				return err
			}
		}
		return bw.Flush()
	}
	err := o.ops.writeStream(o.path, fill)
	if err != nil && !errors.Is(err, fsutil.ErrNotDurable) {
		return fmt.Errorf("events: reescrever %s: %w", o.path, err)
	}
	o.size, o.baseSize, o.needRewrite = written, written, nil
	// the identity comes from an open handle: on Windows a FileInfo from a path loads its file id only when compared,
	// from whatever is at the path by then
	o.ident = nil
	if f, oerr := o.ops.openRead(o.path); oerr == nil {
		if fi, serr := f.Stat(); serr == nil {
			o.ident = fi
		}
		f.Close()
	}
	o.needDirSync = err != nil
	if err != nil {
		return fmt.Errorf("events: reescrever %s: %w", o.path, err)
	}
	return nil
}

// maybeCompactLocked rewrites the log from memory once it holds more than twice what the last rewrite wrote (plus
// compactSlack): the appended records pile up, the memory does not. A rewrite that fails leaves the log valid; the next
// attempt waits for the file to double once more.
func (o *Outbox) maybeCompactLocked() {
	if o.size <= 2*o.baseSize+o.compactSlack {
		return
	}
	if err := o.rewriteLocked(); err != nil && !errors.Is(err, fsutil.ErrNotDurable) {
		o.baseSize = o.size
		o.log.Warn("eventos: a compactação do arquivo falhou; ele segue válido e cresce", "erro", err.Error())
	}
}

// scan is what the boot read of the log found.
type scan struct {
	absent     bool
	unreadable error
	corrupt    int
	firstBad   string // why the first corrupt record was refused
	partial    int64  // bytes after the last complete line: a write a crash cut, which never counted
	lost       bool   // the baseline read was dropped (a corrupt record broke its chain)
}

// scanLocked reads the whole log into memory, without following a symbolic link. A record whose checksum or decode
// fails, or whose events or Done break the rules (seq after the last one, each a valid event; Done between the current
// head and its last seq), is corruption and is skipped whole. A delta that does not apply to the baseline read so far
// is corruption too, but the events of its tx are still taken (each one passed every check: delivering it again is
// safer than losing it). Corruption drops the baseline — every delta after it would apply to a baseline that is not
// the one it was computed from —, while the events of the valid records that follow are still taken.
func (o *Outbox) scanLocked() scan {
	var sc scan
	f, err := o.ops.openRead(o.path)
	if errors.Is(err, fs.ErrNotExist) {
		sc.absent = true
		return sc
	}
	if err != nil {
		sc.unreadable = err
		return sc
	}
	defer f.Close()
	bad := func(reason string) {
		sc.corrupt++
		if sc.firstBad == "" {
			sc.firstBad = reason
		}
		sc.lost = true
	}
	r := bufio.NewReaderSize(f, 1<<20)
	lineNo := 1
	for ; ; lineNo++ {
		line, overlong, n, complete, err := readLine(r)
		if err != nil {
			sc.unreadable = err
			return sc
		}
		if n == 0 {
			break
		}
		if !complete {
			sc.partial = n
			break
		}
		if overlong {
			bad(fmt.Sprintf("linha %d acima do teto", lineNo))
			continue
		}
		rec, err := decodeLine(line)
		if err != nil {
			bad(fmt.Sprintf("linha %d: %v", lineNo, err))
			continue
		}
		if err := o.takeLocked(rec, lineNo, sc.lost); err != nil {
			bad(fmt.Sprintf("linha %d: %v", lineNo, err))
		}
	}
	// a file without a single complete record holds nothing: it is as good as absent
	sc.absent = lineNo == 1
	return sc
}

// takeLocked takes one record read at boot into memory, under the rules of its kind. An error is corruption: the
// record was refused whole, except for a delta that did not apply, whose events and Done were taken. lost says the
// baseline is already gone, so a delta is ignored.
func (o *Outbox) takeLocked(r record, lineNo int, lost bool) error {
	switch r.K {
	case kindHead:
		if lineNo != 1 || r.Version != fileVersion || r.Delta != nil || r.Events != nil || r.Done != 0 {
			return errors.New("cabeçalho fora do lugar ou de outra versão")
		}
		return nil
	case kindTx:
	default:
		return fmt.Errorf("tipo de registro %.16q desconhecido", r.K)
	}
	if lineNo == 1 {
		return errors.New("arquivo sem cabeçalho")
	}
	if r.Version != 0 {
		return errors.New("tx com versão")
	}
	last := o.last
	for _, s := range r.Events {
		if s.Seq <= last {
			return errors.New("seq fora de ordem")
		}
		if err := checkEventBytes(s.Event); err != nil {
			return err
		}
		last = s.Seq
	}
	if r.Done < o.head || r.Done > last {
		return errors.New("done fora do intervalo do que entrou")
	}
	var derr error
	if r.Delta != nil && !lost {
		if derr = o.base.check(r.Delta, trackedKinds); derr == nil {
			o.base.apply(r.Delta)
		}
	}
	for _, s := range r.Events {
		var id struct {
			EventID string `json:"event_id"`
		}
		_ = json.Unmarshal(s.Event, &id) // checked above
		o.queue = append(o.queue, queued{seq: s.Seq, id: id.EventID, enc: s.Event})
	}
	o.last = last
	o.leaveLocked(r.Done)
	if derr != nil {
		return fmt.Errorf("delta: %w", derr)
	}
	return nil
}

// leaveLocked takes out of the outbox every event up to seq done (they left it: delivered or dropped).
func (o *Outbox) leaveLocked(done int64) {
	n := 0
	for n < len(o.queue) && o.queue[n].seq <= done {
		n++
	}
	o.queue = o.queue[n:]
	if done > o.head {
		o.head = done
	}
}
