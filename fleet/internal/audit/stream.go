package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/williamsouzadelima/suricatoos-infra/fleet/contract"
	"github.com/williamsouzadelima/suricatoos-infra/fleet/internal/fsutil"
)

// The files and rotation budgets of the two streams (ADR-0011 "Limites": exec 32 MiB × 8 files, reject 32 MiB × 4).
const (
	ExecFileName   = "audit-exec.jsonl"
	RejectFileName = "audit-reject.jsonl"
	// MaxFileBytes caps each file of either stream: the stream rotates before the line that would pass it.
	MaxFileBytes = 32 << 20
	// ExecFiles and RejectFiles count the current file AND the rotated ones (".1" the newest): 256 MiB and 128 MiB.
	ExecFiles   = 8
	RejectFiles = 4
	// TailLines is how many of the last lines of each stream the audit_tail state carries.
	TailLines = 200
	// maxSeq keeps every seq an exact integer for a reader that holds JSON numbers as doubles (a JS hub).
	maxSeq = 1<<53 - 1
)

var (
	// ErrPoisoned: after a failure that left the current file in a state the stream cannot vouch for — the undo of
	// a failed append failed, or the file changed underneath (replaced by another, or bytes it did not write) — the
	// stream refuses every append until the next Open (whose boot recovery reads the files again). The caller does
	// not proceed to the effect.
	ErrPoisoned = errors.New("audit: o fluxo recusa novas linhas até o próximo Open")
	// ErrSeqExhausted: the last seq is 2^53-1; only a tampered file gets there.
	ErrSeqExhausted = errors.New("audit: seq chegou ao teto de 2^53-1")
)

// streamSpec is the fixed shape of one stream: its name, its current file and its rotation budget.
type streamSpec struct {
	name     contract.AuditStream
	file     string // the current file inside FLEET_STATE_DIR; the rotated ones are file.1, file.2, ...
	maxBytes int64  // cap of each file
	maxFiles int    // the current file plus the rotated ones; at least 2
}

// appendFile is what an append needs from the open current file: an *os.File (a test wraps it to make it fail).
type appendFile interface {
	Write(p []byte) (int, error)
	Sync() error
	Stat() (fs.FileInfo, error)
	Close() error
}

// fileOps are the file system calls of the streams — fsutil and os by default; a test swaps one to make it fail.
type fileOps struct {
	openAppend func(path string) (appendFile, error)
	truncate   func(path string, size int64) error
	syncDir    func(dir string) error
	rename     func(oldpath, newpath string) error
	remove     func(path string) error
	readDir    func(dir string) ([]fs.DirEntry, error)
	openRead   func(path string) (*os.File, error)
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
		truncate: fsutil.TruncateDurable,
		syncDir:  fsutil.SyncDir,
		rename:   os.Rename,
		remove:   os.Remove,
		readDir:  os.ReadDir,
		openRead: fsutil.OpenRegularNoFollow,
	}
}

// tailLine is one line kept in memory for the tail, with its seq.
type tailLine struct {
	seq  int64
	text string
}

// stream is one append-only, hash-chained stream. Everything after mu is guarded by it.
type stream struct {
	spec streamSpec
	dir  string
	ops  fileOps
	log  *slog.Logger

	mu       sync.Mutex
	seq      int64       // seq of the last line; 0 before the first
	head     string      // hex sha256 of the last line; "" before the first
	size     int64       // size of the current file as this stream left it
	ident    fs.FileInfo // the current file as this stream last wrote (or, at boot, read) it; nil = none yet
	tail     []tailLine  // the last TailLines lines, the oldest first
	poisoned error       // non-nil: every append is refused until the next Open
	recovery Recovery    // what Open found; never changes afterwards
	flood    *flood      // the anti-flood state (reject stream only)
}

// newStream is a stream with no line yet over dir; Open fills it from the files (recover) instead.
func newStream(dir string, spec streamSpec, ops fileOps, log *slog.Logger) *stream {
	return &stream{spec: spec, dir: dir, ops: ops, log: log}
}

// name is the name of the current file (i == 0) or of the rotated file i, as Break and the logs report it.
func (s *stream) name(i int) string {
	if i == 0 {
		return s.spec.file
	}
	return s.spec.file + "." + strconv.Itoa(i)
}

// path is the path of the current file (i == 0) or of the rotated file i.
func (s *stream) path(i int) string { return filepath.Join(s.dir, s.name(i)) }

// rotatedIndex reports whether name is a rotated file of this stream — the name of the current file, a dot and a
// number from 1 written without leading zeros (at most 6 digits) — and its number.
func (s *stream) rotatedIndex(name string) (int, bool) {
	suffix, ok := strings.CutPrefix(name, s.spec.file+".")
	if !ok || suffix == "" || suffix[0] == '0' || len(suffix) > 6 {
		return 0, false
	}
	n := 0
	for i := 0; i < len(suffix); i++ {
		if suffix[i] < '0' || suffix[i] > '9' {
			return 0, false
		}
		n = n*10 + int(suffix[i]-'0')
	}
	return n, true
}

// rotatedIndexes lists the numbers of the rotated files that exist, in ascending order (the newest first).
func (s *stream) rotatedIndexes() ([]int, error) {
	entries, err := s.ops.readDir(s.dir)
	if err != nil {
		return nil, err
	}
	var idx []int
	for _, e := range entries {
		if n, ok := s.rotatedIndex(e.Name()); ok {
			idx = append(idx, n)
		}
	}
	slices.Sort(idx)
	return idx, nil
}

// appendLocked writes e as the next line of the stream: it fills seq and prev_sha256, encodes, and only after the
// line is in the file and fsynced does it advance seq, the hash of the last line and the tail. Any error means the
// line does NOT count: the caller must not proceed to the effect the line records.
func (s *stream) appendLocked(e *entry) error {
	if s.poisoned != nil {
		return fmt.Errorf("%w: %w", ErrPoisoned, s.poisoned)
	}
	if e.Stream != s.spec.name {
		return fmt.Errorf("audit: linha %s no fluxo %s", e.Event, s.spec.name) // a bug of this package
	}
	if s.seq >= maxSeq {
		return ErrSeqExhausted
	}
	e.Seq, e.PrevSHA256 = s.seq+1, s.head
	if s.head == "" {
		e.PrevSHA256 = zeroSHA256
	}
	line, err := encode(e)
	if err != nil {
		return err
	}
	if err := s.writeLocked(line); err != nil {
		return err
	}
	sum := sha256.Sum256(line)
	s.seq, s.head = e.Seq, hex.EncodeToString(sum[:])
	s.pushTail(e.Seq, string(line))
	return nil
}

// writeLocked appends line and its '\n' to the current file with O_APPEND and fsyncs it, rotating first when the
// line would take the file past its cap. On a failed write or fsync it cuts the file back to its size before the
// write (TruncateDurable); if the cut fails too, the stream is poisoned.
func (s *stream) writeLocked(line []byte) error {
	path := s.path(0)
	f, fi, err := s.openCurrentLocked()
	if err != nil {
		return err
	}
	pre := fi.Size()
	if pre > 0 && pre+int64(len(line))+1 > s.spec.maxBytes {
		f.Close()
		if err := s.rotateLocked(); err != nil {
			return fmt.Errorf("audit: girar o fluxo %s: %w", s.spec.name, err)
		}
		if f, fi, err = s.openCurrentLocked(); err != nil {
			return err
		}
		pre = fi.Size()
	}
	if pre == 0 {
		// a file with no line yet may have just been created (first line ever, or after a rotation): its directory
		// entry must be durable before a line in it counts
		if err := s.ops.syncDir(s.dir); err != nil {
			f.Close()
			return fmt.Errorf("audit: sincronizar o diretório antes da 1ª linha de %s: %w", path, err)
		}
	}
	buf := make([]byte, 0, len(line)+1)
	buf = append(append(buf, line...), '\n')
	_, werr := f.Write(buf)
	if werr == nil {
		werr = f.Sync()
	}
	// After a successful fsync the line is durable whatever Close reports; the handle goes either way, before the
	// cut below opens the file again.
	f.Close()
	if werr != nil {
		if terr := s.ops.truncate(path, pre); terr != nil {
			return s.poisonLocked(fmt.Errorf("gravar em %s falhou (%v) e o corte de volta a %d bytes também: %w", path, werr, pre, terr))
		}
		return fmt.Errorf("audit: gravar em %s (a linha não conta; o arquivo voltou a %d bytes): %w", path, pre, werr)
	}
	s.size, s.ident = pre+int64(len(buf)), fi
	return nil
}

// openCurrentLocked opens the current file for appending (creating it if needed) and returns its FileInfo. The file
// must be the one this stream last wrote to (os.SameFile, when it knows one) and have the size it left it with:
// anything else means the file changed underneath — replaced by another, or bytes this stream did not write — and
// the stream is poisoned rather than append to it.
func (s *stream) openCurrentLocked() (appendFile, fs.FileInfo, error) {
	path := s.path(0)
	f, err := s.ops.openAppend(path)
	if err != nil {
		return nil, nil, fmt.Errorf("audit: abrir %s: %w", path, err)
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, nil, fmt.Errorf("audit: medir %s: %w", path, err)
	}
	if s.ident != nil && !os.SameFile(s.ident, fi) {
		f.Close()
		return nil, nil, s.poisonLocked(fmt.Errorf("%s não é mais o arquivo em que este fluxo gravou: foi trocado por outro", path))
	}
	if fi.Size() != s.size {
		f.Close()
		return nil, nil, s.poisonLocked(fmt.Errorf("%s tem %d bytes e este fluxo o deixou com %d: o arquivo mudou por fora", path, fi.Size(), s.size))
	}
	return f, fi, nil
}

// rotateLocked renames the current file to ".1" after moving the older ones up, removing the oldest so that no
// more than maxFiles files remain, and syncs the directory after every step. It recomputes everything from the
// directory listing, so an interrupted rotation (an error, a crash) is resumed by the next one without removing
// an extra file, and the files always sort from the oldest (the highest number) to the newest.
func (s *stream) rotateLocked() error {
	idx, err := s.rotatedIndexes()
	if err != nil {
		return err
	}
	// once the current file becomes ".1" there may be at most maxFiles-1 rotated files
	for len(idx) > s.spec.maxFiles-2 {
		oldest := idx[len(idx)-1]
		if err := s.ops.remove(s.path(oldest)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		if err := s.ops.syncDir(s.dir); err != nil {
			return err
		}
		idx = idx[:len(idx)-1]
	}
	// make room at ".1": the run .1 … .k moves up by one, from the top down (.k+1 is free: the run ends there)
	k := 0
	for k < len(idx) && idx[k] == k+1 {
		k++
	}
	for i := k; i >= 1; i-- {
		if err := s.ops.rename(s.path(i), s.path(i+1)); err != nil {
			return err
		}
		if err := s.ops.syncDir(s.dir); err != nil {
			return err
		}
	}
	if err := s.ops.rename(s.path(0), s.path(1)); err != nil {
		return err
	}
	s.size, s.ident = 0, nil // the next current file is a new one
	return s.ops.syncDir(s.dir)
}

// poisonLocked makes the stream refuse every append until the next Open, logs it once, and returns the error the
// failed append reports.
func (s *stream) poisonLocked(cause error) error {
	if s.poisoned == nil {
		s.poisoned = cause
		s.log.Error("auditoria: o fluxo recusa novas linhas até o próximo Open (estado do arquivo incerto)",
			"fluxo", string(s.spec.name), "causa", cause.Error())
	}
	return fmt.Errorf("%w: %w", ErrPoisoned, cause)
}

// pushTail keeps line as the newest of the last TailLines lines.
func (s *stream) pushTail(seq int64, text string) {
	if len(s.tail) == TailLines {
		copy(s.tail, s.tail[1:])
		s.tail = s.tail[:TailLines-1]
	}
	s.tail = append(s.tail, tailLine{seq: seq, text: text})
}
