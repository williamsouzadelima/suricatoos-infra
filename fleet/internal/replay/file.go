package replay

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"io/fs"
	"os"
	"time"

	"github.com/williamsouzadelima/suricatoos-infra/fleet/contract"
	"github.com/williamsouzadelima/suricatoos-infra/fleet/internal/fsutil"
)

// appendFile is what an append needs from the open log: an *os.File (a test wraps it to make it fail).
type appendFile interface {
	Write(p []byte) (int, error)
	Sync() error
	Stat() (fs.FileInfo, error)
	Close() error
}

// fileOps are the file system calls of the store — fsutil by default; a test swaps one to make it fail.
type fileOps struct {
	openAppend  func(path string) (appendFile, error)
	openRead    func(path string) (*os.File, error)
	truncate    func(path string, size int64) error
	syncDir     func(dir string) error
	writeStream func(path string, fill func(io.Writer) error) error
}

// config is the fixed shape of the store: its ceilings and its file system calls (a test shrinks the ceilings).
type config struct {
	maxEntries int
	maxBytes   int64
	ops        fileOps
}

func defaultConfig() config {
	return config{
		maxEntries: MaxEntries,
		maxBytes:   MaxBytes,
		ops: fileOps{
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
		},
	}
}

// scan is what the boot read of the log found.
type scan struct {
	absent     bool
	unreadable error
	corrupt    int
	first      *Corruption
	end        int64 // offset just after the last complete line
	partial    int64 // bytes after it (no '\n'): a crash in the middle of an append
	maxAt      int64 // the latest instant of any record (Unix ns): the clock is raised to it
}

// scanLocked reads the whole log into memory, record by record, without following a symbolic link. A record that
// fails its checksum, its decode or the rules of its kind is skipped and counted; the others are kept.
func (s *Store) scanLocked() scan {
	var sc scan
	f, err := s.cfg.ops.openRead(s.path)
	if errors.Is(err, fs.ErrNotExist) {
		sc.absent = true
		return sc
	}
	if err != nil {
		sc.unreadable = err
		return sc
	}
	defer f.Close()
	if fi, err := f.Stat(); err == nil {
		s.ident = fi
	}
	b := &bootState{byCanon: map[[32]byte]int32{}}
	r := bufio.NewReaderSize(f, 1<<20)
	var off int64
	for lineNo := 1; ; lineNo++ {
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
		reason := ""
		var rec record
		switch {
		case overlong:
			reason = "linha acima do teto"
		default:
			var derr error
			if rec, derr = decodeLine(line); derr != nil {
				reason = derr.Error()
			} else if aerr := s.applyLocked(b, rec, off, n, lineNo, crc32.Checksum(line[9:], castagnoli)); aerr != nil {
				reason = aerr.Error()
			} else if rec.At > sc.maxAt {
				sc.maxAt = rec.At
			}
		}
		if reason != "" {
			sc.corrupt++
			if sc.first == nil {
				sc.first = &Corruption{Line: lineNo, Offset: off, Reason: reason}
			}
		}
		off += n
		sc.end = off
	}
	if !b.head && sc.end > 0 {
		sc.corrupt++
		if sc.first == nil {
			sc.first = &Corruption{Line: 1, Reason: "arquivo sem cabeçalho"}
		}
	}
	s.size = sc.end + sc.partial
	return sc
}

// readLine reads one line of at most maxLineBytes (without its '\n'); a longer one is consumed and reported overlong,
// never held. n is the number of bytes consumed (with the '\n'); complete is false for the bytes after the last '\n'.
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

// bootState is what applyLocked needs while the log is read.
type bootState struct {
	head    bool
	byCanon map[[32]byte]int32 // every entry read so far, live or not (only during the boot)
}

// applyLocked takes one valid record into memory, under the rules of its kind; an error refuses it (corruption).
func (s *Store) applyLocked(b *bootState, r record, off, n int64, lineNo int, crc uint32) error {
	if r.K == kindHead {
		if b.head || lineNo != 1 || r.Version != fileVersion {
			return errors.New("cabeçalho fora do lugar ou de outra versão")
		}
		b.head = true
		return nil
	}
	switch r.K {
	case kindFloor:
		if r.At <= 0 {
			return errors.New("piso sem instante")
		}
		if r.At > s.floor {
			s.floor = r.At
		}
		return nil
	case kindEntry:
		e, err := entryOf(r)
		if err != nil {
			return err
		}
		if _, dup := b.byCanon[e.canon]; dup {
			return errors.New("entrada repetida (uma entrada gravada nunca é sobrescrita)")
		}
		b.byCanon[e.canon] = s.insertLocked(e)
		return nil
	case kindExec, kindResult, kindDelivered:
		i, ok := b.byCanon[canonKey(r.Canon)]
		if !ok || !reHex64.MatchString(r.Canon) || s.entries[i].job == nil || r.At <= 0 {
			return errors.New("passo do journal sem comando aceito")
		}
		return s.applyJournalLocked(&s.entries[i], r, off, n, crc)
	}
	return fmt.Errorf("tipo de registro %.16q desconhecido", r.K)
}

// entryOf validates an entry record and builds the entry. An accepted entry carries its type (of the catalog) and
// tenant, which its journal needs; a rejected one carries neither.
func entryOf(r record) (entry, error) {
	d := Decision{Decision: contract.Decision(r.Decision), Reason: contract.RejectReason(r.Reason)}
	switch {
	case !reHex64.MatchString(r.Canon) || !reHex64.MatchString(r.Nonce) || !reUUID.MatchString(r.Cmd):
		return entry{}, errors.New("entrada com chave fora da forma")
	case r.At <= 0 || r.Expires <= 0 || r.Result != nil || r.Status != "" || r.Code != "" || r.TokenID != "" || r.Version != 0:
		return entry{}, errors.New("entrada com membros fora do lugar")
	case checkDecision(d) != nil:
		return entry{}, errors.New("entrada com decisão que não se grava")
	}
	e := entry{canon: canonKey(r.Canon), nonce: canonKey(r.Nonce), cmd: cmdKey(r.Cmd), at: r.At, expires: r.Expires,
		decision: d.Decision, reason: d.Reason}
	if d.Decision != contract.DecisionAccepted {
		if r.Type != "" || r.Tenant != "" {
			return entry{}, errors.New("rejeição gravada com tipo ou tenant")
		}
		return e, nil
	}
	typ := contract.CommandType(r.Type)
	if _, ok := contract.LookupType(typ); !ok || !reTenant.MatchString(r.Tenant) {
		return entry{}, errors.New("accepted sem tipo do catálogo ou sem tenant")
	}
	e.job = &job{typ: typ, tenant: r.Tenant, state: StateReceived}
	return e, nil
}

// readyLocked makes the file fit for an append: a pending rewrite from memory, then the directory sync a rewrite
// still owes, then the floor the file does not hold yet. Nothing is appended before all three succeed.
func (s *Store) readyLocked(t time.Time) error {
	if s.closed {
		return errors.New("replay: store fechado (a trava do FLEET_STATE_DIR foi solta)")
	}
	if s.needRewrite != nil {
		if err := s.rewriteLocked(t); err != nil && !errors.Is(err, fsutil.ErrNotDurable) {
			s.needRewrite = err
			return fmt.Errorf("replay: o store precisa ser reescrito e a reescrita falhou: %w", err)
		}
	}
	if s.needDirSync {
		if err := s.cfg.ops.syncDir(s.dir); err != nil {
			return fmt.Errorf("replay: confirmar a reescrita do store: %w", err)
		}
		s.needDirSync = false
	}
	if s.floor != 0 && !s.floorDurable {
		return s.writeFloorLocked()
	}
	return nil
}

func (s *Store) writeFloorLocked() error {
	line, err := encodeLine(record{K: kindFloor, At: s.floor})
	if err != nil {
		return err
	}
	if _, err := s.writeLocked(line); err != nil {
		return fmt.Errorf("replay: gravar o piso de replay: %w", err)
	}
	s.floorDurable = true
	return nil
}

// appendLocked makes the file ready and appends line, within the ceiling of its kind (journal lines may use
// journalSlack). It returns the offset of the line. A file that changed underneath is rewritten from memory, then the
// line is appended once more.
func (s *Store) appendLocked(line []byte, journal bool, t time.Time) (int64, error) {
	if err := s.readyLocked(t); err != nil {
		return 0, err
	}
	limit := s.cfg.maxBytes
	if journal {
		limit += journalSlack
	}
	if s.size+int64(len(line)) > limit && !journal && s.hasDeadLocked(t) {
		if err := s.rewriteLocked(t); err != nil && !errors.Is(err, fsutil.ErrNotDurable) {
			return 0, err
		}
		if err := s.readyLocked(t); err != nil {
			return 0, err
		}
	}
	if s.size+int64(len(line)) > limit {
		return 0, ErrFull
	}
	off, err := s.writeLocked(line)
	if errors.Is(err, errChanged) {
		s.log.Warn("anti-replay: o arquivo do store mudou por fora; reescrito a partir da memória")
		if err := s.readyLocked(t); err != nil {
			return 0, err
		}
		off, err = s.writeLocked(line)
	}
	return off, err
}

// writeLocked appends line to the log with O_APPEND and fsyncs it. The file must be the one this store left (same
// file, same size): otherwise nothing is written and the next write rewrites it from memory (errChanged). A failed
// write or fsync is cut back to the previous size; if the cut fails too, the next write rewrites the file from memory.
func (s *Store) writeLocked(line []byte) (int64, error) {
	f, err := s.cfg.ops.openAppend(s.path)
	if err != nil {
		return 0, fmt.Errorf("replay: abrir %s: %w", s.path, err)
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return 0, fmt.Errorf("replay: medir %s: %w", s.path, err)
	}
	if (s.ident != nil && !os.SameFile(s.ident, fi)) || fi.Size() != s.size {
		f.Close()
		s.needRewrite = errChanged
		return 0, errChanged
	}
	pre := fi.Size()
	_, werr := f.Write(line)
	if werr == nil {
		werr = f.Sync()
	}
	f.Close()
	if werr != nil {
		if terr := s.cfg.ops.truncate(s.path, pre); terr != nil {
			s.needRewrite = fmt.Errorf("o corte de volta de uma gravação que falhou também falhou: %w", terr)
			s.log.Error("anti-replay: gravação falhou e o corte de volta também; a próxima gravação reescreve o store a partir da memória",
				"erro", werr.Error(), "corte", terr.Error())
		}
		return 0, fmt.Errorf("replay: gravar em %s (não conta): %w", s.path, werr)
	}
	s.size, s.ident = pre+int64(len(line)), fi
	return pre, nil
}

// rewriteLocked replaces the file with what the memory holds at t — the head, the floor, every live entry with its
// journal (a result record is copied from the current file, checked against the checksum the memory kept) — through
// fsutil.WriteAtomicStream (temp + rename with fsync, 0600). The entries past their life are dropped. On success, or
// on fsutil.ErrNotDurable (the new file is in place, its directory entry not confirmed), the memory describes the new
// file; any other error leaves the old file and the memory as they were.
func (s *Store) rewriteLocked(t time.Time) error {
	var (
		keep    []int32
		results = map[int32]resultRef{}
		written int64
	)
	fill := func(w io.Writer) (err error) {
		keep, written = keep[:0], 0
		clear(results)
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
		var src *os.File
		defer func() {
			if src != nil {
				src.Close()
			}
		}()
		if err := put(record{K: kindHead, Version: fileVersion}); err != nil {
			return err
		}
		if s.floor != 0 {
			if err := put(record{K: kindFloor, At: s.floor}); err != nil {
				return err
			}
		}
		for i := range s.entries {
			e := &s.entries[i]
			if !alive(e, t) {
				continue
			}
			keep = append(keep, int32(i))
			if err := put(entryRecord(e)); err != nil {
				return err
			}
			j := e.job
			if j == nil {
				continue
			}
			if j.execAt != 0 {
				if err := put(record{K: kindExec, Canon: hexOf(e.canon), At: j.execAt}); err != nil {
					return err
				}
			}
			if j.state >= StateResult {
				if j.typ == contract.TypeEnrollTokenCreate {
					if err := put(secretFreeRecord(e)); err != nil {
						return err
					}
				} else {
					if src == nil {
						if src, err = s.cfg.ops.openRead(s.path); err != nil {
							return fmt.Errorf("ler os resultados do store atual: %w", err)
						}
					}
					line, err := readRecordAt(src, j.res)
					if err != nil {
						return fmt.Errorf("copiar o resultado de %s: %w", uuidString(e.cmd), err)
					}
					results[int32(i)] = resultRef{off: written, n: j.res.n, crc: j.res.crc}
					n, err := bw.Write(line)
					written += int64(n)
					if err != nil {
						return err
					}
				}
			}
			if j.state == StateDelivered {
				if err := put(record{K: kindDelivered, Canon: hexOf(e.canon), At: j.deliveredAt}); err != nil {
					return err
				}
			}
		}
		return bw.Flush()
	}
	err := s.cfg.ops.writeStream(s.path, fill)
	if err != nil && !errors.Is(err, fsutil.ErrNotDurable) {
		return fmt.Errorf("replay: reescrever %s: %w", s.path, err)
	}
	s.applyLayoutLocked(keep, results)
	s.size, s.floorDurable, s.needRewrite = written, true, nil
	s.ident = nil
	if fi, serr := os.Lstat(s.path); serr == nil {
		s.ident = fi
	}
	s.needDirSync = err != nil
	if err != nil {
		return fmt.Errorf("replay: reescrever %s: %w", s.path, err)
	}
	return nil
}

// applyLayoutLocked makes the memory describe a rewritten file: only the kept entries, in their order, with the new
// offsets of their results and rebuilt indexes.
func (s *Store) applyLayoutLocked(keep []int32, results map[int32]resultRef) {
	old := s.entries
	s.entries = make([]entry, 0, len(keep))
	s.byNonce = make(map[[32]byte]int32, len(keep))
	s.byCmd = make(map[[16]byte]int32, len(keep))
	s.pending = 0
	for _, i := range keep {
		e := old[i]
		if r, ok := results[i]; ok {
			j := *e.job
			j.res = r
			e.job = &j
		}
		s.insertLocked(e)
	}
}

func hexOf(k [32]byte) string { return hex.EncodeToString(k[:]) }

// entryRecord is the record of an entry, from memory: exactly the record Record wrote for it.
func entryRecord(e *entry) record {
	r := record{K: kindEntry, At: e.at, Canon: hexOf(e.canon), Nonce: hexOf(e.nonce), Cmd: uuidString(e.cmd),
		Decision: string(e.decision), Reason: string(e.reason), Expires: e.expires}
	if e.job != nil {
		r.Type, r.Tenant = string(e.job.typ), e.job.tenant
	}
	return r
}

// readRecordAt reads the whole line of a record at ref and checks it: its own checksum, and the one the memory kept
// when the record was confirmed — so bytes that changed since are never copied as if they were the result.
func readRecordAt(f *os.File, ref resultRef) ([]byte, error) {
	if ref.n < 11 {
		return nil, errors.New("referência de registro vazia")
	}
	line := make([]byte, ref.n)
	if _, err := f.ReadAt(line, ref.off); err != nil {
		return nil, err
	}
	if line[len(line)-1] != '\n' || line[8] != ' ' {
		return nil, errors.New("registro fora da forma")
	}
	js := line[9 : len(line)-1]
	if sum, ok := parseChecksum(line[:8]); !ok || sum != ref.crc || crc32.Checksum(js, castagnoli) != ref.crc {
		return nil, errors.New("o registro não é mais o que foi confirmado (checksum)")
	}
	if bytes.IndexByte(js, '\n') >= 0 {
		return nil, errors.New("registro fora da forma")
	}
	return line, nil
}
