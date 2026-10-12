// Package replay is the fleet node's anti-replay store and journal (ADR-0011 "Anti-replay, idempotência e
// entrega"): every FINAL decision the verification pipeline takes on an authenticated envelope — rejected at lines
// 4–9, or accepted — is recorded here, keyed by the envelope's canonical form, BEFORE its ack; the decisions of line
// 3 (bad_window, expired) and the deferred ones are never recorded. The journal follows each accepted command from
// received to executing to its result and to the hub's acceptance of the result. It owns FLEET_STATE_DIR's anti-replay
// state: the exclusive lock of the directory, the verification clock (package clock) and the replay floor.
//
// # Log
//
// FLEET_STATE_DIR/replay.log is an append-only log, one record per line: "<crc32c, 8 lowercase hex> <json>\n". Each
// record is appended with O_APPEND and fsynced before the method returns — O(1) per decision, whatever the size of the
// store (ADR worst case ~2·10⁵ entries). The first record of a file is its head (format version); then floors,
// entries and journal steps. The indexes live in memory and are rebuilt at boot. A record is never rewritten in place:
// the file is only ever replaced whole, by a rewrite from memory (temp + rename with fsync, 0600: compaction, repair).
//
// The truth is the memory. An append counts only once its fsync returned; then the memory moves. A failed append is
// cut back (fsutil.TruncateDurable); if even the cut fails, or the file changed underneath (another file in its
// place, another size), the store does not append to it again: the next write first rewrites the whole file from
// memory. So the store never decides "already recorded" — nor replay — by reading back a write it did not confirm,
// even when the bytes of that write are visible in the file. A rewrite whose rename is in place but whose directory
// sync failed (fsutil.ErrNotDurable) leaves the memory describing the new file; the next write syncs the directory
// first, and nothing is appended until that succeeds.
//
// # Entries
//
// An entry holds the sha256 of the canonical form, the nonce, the command_id, the decision and its reason, the
// instant of the decision and the end of its life: min(not_after, issued_at + 24 h) + 7 days (EntryGrace). Two
// indexes, nonce and command_id, point to the FIRST entry recorded under each key; later entries under the same key
// (a recorded replay) are chained to it, and a replay is recorded under its own canonical form. Lookup answers lines
// 2a and 5 (contract.ClassifyReplay) from the live entries only: past its life an entry no longer exists for the
// pipeline, and Compact drops it from the file.
//
// # Boot and replay floor
//
// Open takes the exclusive lock (a second connector on the same directory gets fsutil.ErrLocked), opens the clock,
// reads the log — a partial last record (a crash in the middle of an append: written before its ack, so nobody saw it)
// is cut away; a complete record that fails its checksum, its decode or the rules of its kind is corruption —, raises
// the clock to the latest instant the log holds and then, at t = the clock, decides the replay floor. The floor is
// set to t when the store is unreadable or corrupt, when it is missing on a node that already has its identity, when
// the watermark (clock.json) is unusable — or missing on such a node —, and when such a node has a store without a
// floor; a node's every (re)enroll sets it too (SetFloor). The pipeline refuses as replay ("cache reiniciado") every
// command with issued_at < floor + skew, in whole seconds (the floor is published rounded UP to the second,
// contract.FormatReplayFloor). A store the boot could not rewrite records nothing — every decision is unavailable —
// until a rewrite succeeds.
//
// # No secret
//
// The only secret of the contract is the output of enroll_token.create. RecordResult never writes that output: for
// that type it keeps the status, the error code and the token_id (which identifies the token, so that it can be
// revoked when the hub never got it) and drops the rest; the result types the store writes have no member for it.
//
// A Store is safe for concurrent use.
package replay

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"path/filepath"
	"regexp"
	"sync"
	"time"

	"github.com/williamsouzadelima/suricatoos-infra/fleet/contract"
	"github.com/williamsouzadelima/suricatoos-infra/fleet/internal/clock"
	"github.com/williamsouzadelima/suricatoos-infra/fleet/internal/fsutil"
)

const (
	// FileName is the log inside FLEET_STATE_DIR.
	FileName = "replay.log"
	// LockFileName is the exclusive lock of FLEET_STATE_DIR: one connector per directory.
	LockFileName = "fleet.lock"
	// EntryGrace is how long an entry outlives min(not_after, issued_at + 24 h) (ADR: 7 days; the journal too).
	EntryGrace = 7 * 24 * time.Hour

	// MaxEntries and MaxBytes are the ceilings of the store: at either one a new entry is refused (ErrFull) and the
	// pipeline answers unavailable (deferred, fail-closed). They are sized for the ADR's worst case, a compromised hub
	// (~2·10⁵ entries and ~0.6 GB of journal), with margin; a legitimate hub stays orders of magnitude below. See the
	// slice report for the arithmetic.
	MaxEntries = 250_000
	MaxBytes   = 768 << 20
	// AlertPercent of either ceiling raises Stats.Alert, for the node's heartbeat and state (F2.6).
	AlertPercent = 80

	// journalSlack lets the journal of commands already accepted (executing, result, delivered) go this far past
	// MaxBytes: a command accepted just below the ceiling can still journal its outcome.
	journalSlack = 8 << 20
	// entryLineMax bounds the line of one entry record (every member at its longest; a test pins it): Stats.Full
	// says the next entry does not fit.
	entryLineMax = 512
	fileVersion  = 1
)

var (
	// ErrRecorded: the canonical form is already recorded. An entry is never overwritten.
	ErrRecorded = errors.New("replay: forma canônica já gravada (uma entrada gravada nunca é sobrescrita)")
	// ErrFull: the store is at one of its ceilings; nothing new is recorded (unavailable).
	ErrFull = errors.New("replay: store no teto de entradas ou de bytes")
	// ErrNoJob: no live accepted command under that key.
	ErrNoJob = errors.New("replay: nenhum comando aceito vivo com essa chave")
	// ErrJobState: a journal step out of order (received → executing → result → delivered).
	ErrJobState = errors.New("replay: passo do journal fora de ordem")

	errChanged = errors.New("o arquivo do store mudou por fora (outro arquivo ou outro tamanho)")
)

// Options are what only the caller knows.
type Options struct {
	// IdentityExists is true when the node's fleet certificate is present: an enroll already happened in this
	// FLEET_STATE_DIR. Then a missing store, a missing watermark or a store without a floor is a LOSS (replay floor).
	// The zero value is the first boot of a node — which must therefore open the store (and budget.json) BEFORE the
	// enroll persists the identity, so that the first start after it finds them.
	IdentityExists bool
	// Logger receives the facts of the boot and the failures of the store. nil discards them.
	Logger *slog.Logger
}

// Decision is what Record keeps: accepted, or rejected with a reason the ADR records (contract.RejectReason.Recorded:
// lines 4–9).
type Decision struct {
	Decision contract.Decision
	Reason   contract.RejectReason
}

// Entry is a recorded decision, as the store answers it.
type Entry struct {
	CanonicalSHA256 string
	CommandID       string
	Decision        contract.Decision
	Reason          contract.RejectReason // "" for accepted
	DecidedAt       time.Time             // the verification clock of the decision: the received_at of its ack
	Expires         time.Time             // the end of its life
	Job             *Job                  // accepted only: its journal
}

// Lookup is what lines 2a and 5 need about one authenticated envelope.
type Lookup struct {
	// Recorded is the canonical-form sha256 of every live entry under the envelope's nonce or command_id: the input of
	// contract.ClassifyReplay.
	Recorded []string
	// Same is the live entry with the envelope's very canonical form (line 2a: resend its ack and result), or nil.
	Same *Entry
}

// Corruption locates the first refused record of the log.
type Corruption struct {
	Line   int   // from 1
	Offset int64 // of the line in the file
	Reason string
}

// Recovery is what Open found and did. Interrupted and SecretLost are for the connector (F2.6) to report.
type Recovery struct {
	Absent         bool        // there was no store file, or one without a single complete record (0 bytes, or a partial one)
	Unreadable     error       // the file could not be read: nothing of it was kept
	Corrupt        int         // complete records refused (checksum, decode, rules) — and a file without its head
	FirstCorrupt   *Corruption // the first of them
	DiscardedBytes int64       // a partial last record cut away (a crash in the middle of an append)
	FloorReason    string      // why Open set the replay floor; "" = it did not
	RewriteErr     error       // Open could not rewrite the file: nothing is recorded until a rewrite succeeds
	// Interrupted are the accepted commands without a result (received or executing): report each as failed with
	// error.code = interrupted — never run it again.
	Interrupted []Job
	// SecretLost are the enroll_token.create commands whose succeeded result the hub never accepted: revoke only the
	// token (TokenID) and report failed with secret_lost.
	SecretLost []Job
}

// Stats is the size and health of the store, for the node's heartbeat and state.
type Stats struct {
	Entries        int   // entries in memory (the ones past their life count until the next compaction)
	Bytes          int64 // size of the file
	Alert          bool  // at AlertPercent of a ceiling
	Full           bool  // at a ceiling: the next new entry is refused
	PendingResults int   // results recorded and not yet accepted by the hub
	Writable       error // non-nil: the next write must first rewrite the file from memory, and why
}

// entry is a recorded decision in memory (~120 bytes; a result stays on disk).
type entry struct {
	canon     [32]byte
	nonce     [32]byte
	cmd       [16]byte
	at        int64 // Unix ns: the decision
	expires   int64 // Unix s: the end of its life
	decision  contract.Decision
	reason    contract.RejectReason
	nextNonce int32 // the next entry under the same nonce; -1 = none
	nextCmd   int32 // the next entry under the same command_id; -1 = none
	job       *job
}

// Store is the anti-replay store and journal of one FLEET_STATE_DIR.
type Store struct {
	dir, path string
	cfg       config
	log       *slog.Logger
	lock      *fsutil.Lock
	clk       *clock.Clock

	mu               sync.Mutex
	entries          []entry
	byNonce          map[[32]byte]int32
	byCmd            map[[16]byte]int32
	pending          int   // jobs in StateResult
	floor            int64 // Unix ns; 0 = none
	floorDurable     bool  // the floor in memory is in the file
	floorUnannounced bool
	size             int64       // the file as this store left it
	ident            fs.FileInfo // the file this store last wrote (or read at boot); nil = unknown
	needRewrite      error       // non-nil: rewrite the file from memory before any append
	needDirSync      bool        // a rewrite is in place but its directory entry is not confirmed durable
	recovery         Recovery    // set by Open
	closed           bool
}

// Open opens the anti-replay store of stateDir (FLEET_STATE_DIR) at the reading now of the wall clock: it takes the
// directory's exclusive lock, opens the verification clock, reads the log and decides the replay floor (see the
// package documentation). The errors are an empty stateDir, the lock (fsutil.ErrLocked: another connector uses the
// directory) and the clock; what the log holds is never an error — it is Recovery.
func Open(stateDir string, now time.Time, opts Options) (*Store, error) {
	return open(stateDir, now, opts, defaultConfig())
}

func open(stateDir string, now time.Time, opts Options, cfg config) (*Store, error) {
	if stateDir == "" {
		return nil, errors.New("replay: FLEET_STATE_DIR vazio")
	}
	lock, err := fsutil.LockExclusive(filepath.Join(stateDir, LockFileName))
	if err != nil {
		if errors.Is(err, fsutil.ErrLocked) {
			return nil, fmt.Errorf("replay: outro conector usa este FLEET_STATE_DIR (%s): %w", stateDir, err)
		}
		return nil, fmt.Errorf("replay: travar FLEET_STATE_DIR: %w", err)
	}
	clk, err := clock.Open(stateDir)
	if err != nil {
		lock.Close()
		return nil, err
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	s := &Store{dir: stateDir, path: filepath.Join(stateDir, FileName), cfg: cfg, log: logger, lock: lock, clk: clk}
	s.resetLocked()
	// leftovers of a rewrite that a crash interrupted; best effort, the lock says no other store writes here
	_, _ = fsutil.RemoveOrphanTemps(s.path)

	s.mu.Lock()
	defer s.mu.Unlock()
	sc := s.scanLocked()
	if sc.maxAt != 0 {
		clk.Raise(time.Unix(0, sc.maxAt))
	}
	s.bootLocked(clk.Now(now), sc, opts)
	return s, nil
}

// resetLocked empties the memory.
func (s *Store) resetLocked() {
	s.entries = nil
	s.byNonce = map[[32]byte]int32{}
	s.byCmd = map[[16]byte]int32{}
	s.pending = 0
	s.floor = 0
}

// bootLocked decides, at the verification clock t, the replay floor and what to do with the file.
func (s *Store) bootLocked(t time.Time, sc scan, opts Options) {
	rec := &s.recovery
	absent := sc.absent || sc.empty // a file without a single complete record holds nothing: it is rewritten like a missing one
	rec.Absent, rec.Unreadable, rec.Corrupt, rec.FirstCorrupt = absent, sc.unreadable, sc.corrupt, sc.first
	rec.DiscardedBytes = sc.partial
	if sc.unreadable != nil {
		s.resetLocked() // what was read before the failure cannot be told complete
	}

	reason := ""
	switch {
	case sc.unreadable != nil:
		reason = "store ilegível"
	case sc.corrupt > 0:
		reason = "store corrompido"
	case absent && opts.IdentityExists:
		reason = "store ausente num nó que já tem identidade"
	case s.clk.Lost() != nil:
		reason = "marca d'água inutilizável"
	case !s.clk.Found() && opts.IdentityExists:
		reason = "marca d'água ausente num nó que já tem identidade"
	case s.floor == 0 && opts.IdentityExists:
		reason = "nó com identidade e store sem piso"
	}
	if reason != "" {
		if at := t.UnixNano(); at > s.floor {
			s.floor = at
		}
		s.floorDurable = false
		rec.FloorReason = reason
		s.log.Warn("anti-replay: piso de replay gravado no boot; comandos emitidos antes dele + skew são recusados como replay (cache reiniciado)",
			"motivo", reason, "piso", contract.FormatReplayFloor(time.Unix(0, s.floor)))
	} else {
		s.floorDurable = true
	}
	s.floorUnannounced = s.floor != 0 // conservative: the heartbeat goes before the first poll at every start

	if sc.partial > 0 {
		s.log.Warn("anti-replay: registro final parcial descartado no boot (queda no meio da escrita; ninguém viu o ack)",
			"bytes", sc.partial)
	}
	if sc.corrupt > 0 {
		s.log.Error("anti-replay: registros corrompidos no store; o que se leu foi aproveitado e o arquivo, reescrito",
			"registros", sc.corrupt, "linha", sc.first.Line, "motivo", sc.first.Reason)
	}
	if sc.unreadable != nil {
		s.log.Error("anti-replay: store ilegível; começa vazio com piso de replay", "erro", sc.unreadable.Error())
	}

	rewrite := absent || sc.unreadable != nil || sc.corrupt > 0 || s.hasDeadLocked(t)
	if !rewrite && sc.partial > 0 {
		if err := s.cfg.ops.truncate(s.path, sc.end); err != nil {
			rewrite = true
		} else {
			s.size = sc.end
		}
	}
	if rewrite {
		if err := s.rewriteLocked(t); err != nil && !errors.Is(err, fsutil.ErrNotDurable) {
			s.needRewrite, rec.RewriteErr = err, err
			s.log.Error("anti-replay: o store não pôde ser reescrito no boot; nada se grava (unavailable) até uma reescrita dar certo",
				"erro", err.Error())
		}
	} else if !s.floorDurable {
		if err := s.writeFloorLocked(); err != nil {
			s.log.Error("anti-replay: o piso de replay não pôde ser gravado no boot; a próxima gravação tenta antes",
				"erro", err.Error())
		}
	}

	// the watermark goes to disk at every boot: the next boot of a node with identity must find it
	if err := s.clk.Persist(); err != nil {
		s.log.Warn("anti-replay: a marca d'água não pôde ser gravada no boot; sem ela o próximo boot grava um piso de replay",
			"erro", err.Error())
	}

	for i := range s.entries {
		e := &s.entries[i]
		if e.job == nil || !alive(e, t) {
			continue
		}
		switch j := e.job; {
		case j.state == StateReceived || j.state == StateExecuting:
			rec.Interrupted = append(rec.Interrupted, s.jobViewLocked(e))
		case j.state == StateResult && j.typ == contract.TypeEnrollTokenCreate && j.status == contract.StatusSucceeded:
			rec.SecretLost = append(rec.SecretLost, s.jobViewLocked(e))
		}
	}
}

// Recovery returns what Open found and did.
func (s *Store) Recovery() Recovery {
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.recovery
	if r.FirstCorrupt != nil {
		c := *r.FirstCorrupt
		r.FirstCorrupt = &c
	}
	r.Interrupted = append([]Job(nil), r.Interrupted...)
	r.SecretLost = append([]Job(nil), r.SecretLost...)
	return r
}

// Clock returns the verification clock of the directory (the pipeline's t; the boot of the budget and of the audit).
func (s *Store) Clock() *clock.Clock { return s.clk }

// Close releases the lock of the directory. A second Close does nothing.
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	return s.lock.Close()
}

// alive reports whether e still lives at t (inclusive: an entry lives until its expires, to the second).
func alive(e *entry, t time.Time) bool { return t.UnixNano() <= e.expires*int64(time.Second) }

func (s *Store) hasDeadLocked(t time.Time) bool {
	for i := range s.entries {
		if !alive(&s.entries[i], t) {
			return true
		}
	}
	return false
}

var (
	reUUID   = regexp.MustCompile(contract.PatternUUID)
	reHex64  = regexp.MustCompile(contract.PatternNonce) // 64 lowercase hex, like a sha256
	reType   = regexp.MustCompile(contract.PatternCommandTypeAny)
	reTenant = regexp.MustCompile(contract.PatternTenant)
)

// canonKey decodes a 64-hex sha256 (the zero key if it is not one).
func canonKey(s string) [32]byte {
	var k [32]byte
	if reHex64.MatchString(s) {
		hex.Decode(k[:], []byte(s))
	}
	return k
}

// cmdKey decodes a lowercase UUID (the zero key if it is not one).
func cmdKey(s string) [16]byte {
	var k [16]byte
	if reUUID.MatchString(s) {
		b := []byte(s[0:8] + s[9:13] + s[14:18] + s[19:23] + s[24:36])
		hex.Decode(k[:], b)
	}
	return k
}

func uuidString(k [16]byte) string {
	return fmt.Sprintf("%x-%x-%x-%x-%x", k[0:4], k[4:6], k[6:8], k[8:10], k[10:16])
}

// validInstant reports whether t can be held as Unix nanoseconds (years 1678 to 2262).
func validInstant(t time.Time) bool { return !t.IsZero() && t.Equal(time.Unix(0, t.UnixNano())) }

// Lookup returns, for an authenticated envelope at the verification clock t, the canonical forms recorded under its
// nonce or command_id and the entry with its very canonical form (lines 2a and 5). Entries past their life do not
// count. It reads only memory.
func (s *Store) Lookup(v *contract.Verified, t time.Time) Lookup {
	if v == nil || !reHex64.MatchString(v.CanonicalSHA256()) {
		return Lookup{}
	}
	c := v.Command()
	canon, nonce, cmd := canonKey(v.CanonicalSHA256()), canonKey(c.Nonce), cmdKey(c.CommandID)
	s.mu.Lock()
	defer s.mu.Unlock()
	var out Lookup
	// linear in the chains: an entry is in both only when it carries the nonce AND the command_id, so the walk of the
	// command_id chain skips the entries of the nonce just walked — no entry is added twice and nothing is searched
	add := func(i int32) {
		e := &s.entries[i]
		if !alive(e, t) {
			return
		}
		out.Recorded = append(out.Recorded, hex.EncodeToString(e.canon[:]))
		if e.canon == canon && out.Same == nil {
			view := s.viewLocked(i)
			out.Same = &view
		}
	}
	if i, ok := s.byNonce[nonce]; ok {
		for ; i >= 0; i = s.entries[i].nextNonce {
			add(i)
		}
	}
	if i, ok := s.byCmd[cmd]; ok {
		for ; i >= 0; i = s.entries[i].nextCmd {
			if s.entries[i].nonce != nonce {
				add(i)
			}
		}
	}
	return out
}

// findLocked returns the index of the live entry with this canonical form under the nonce or the command_id, or -1.
func (s *Store) findLocked(canon, nonce [32]byte, cmd [16]byte, t time.Time) int32 {
	for _, chain := range []struct {
		head int32
		ok   bool
		next func(*entry) int32
	}{
		{s.byNonce[nonce], hasKey(s.byNonce, nonce), func(e *entry) int32 { return e.nextNonce }},
		{s.byCmd[cmd], hasKey(s.byCmd, cmd), func(e *entry) int32 { return e.nextCmd }},
	} {
		if !chain.ok {
			continue
		}
		for i := chain.head; i >= 0; i = chain.next(&s.entries[i]) {
			if e := &s.entries[i]; e.canon == canon && alive(e, t) {
				return i
			}
		}
	}
	return -1
}

func hasKey[K comparable](m map[K]int32, k K) bool { _, ok := m[k]; return ok }

// insertLocked adds e to memory and to both indexes: the index keeps pointing to the first entry of a key, and a
// later one is chained right after it.
func (s *Store) insertLocked(e entry) int32 {
	i := int32(len(s.entries))
	e.nextNonce, e.nextCmd = -1, -1
	if head, ok := s.byNonce[e.nonce]; ok {
		e.nextNonce = s.entries[head].nextNonce
		s.entries = append(s.entries, e)
		s.entries[head].nextNonce = i
	} else {
		s.byNonce[e.nonce] = i
		s.entries = append(s.entries, e)
	}
	if head, ok := s.byCmd[e.cmd]; ok {
		s.entries[i].nextCmd = s.entries[head].nextCmd
		s.entries[head].nextCmd = i
	} else {
		s.byCmd[e.cmd] = i
	}
	if e.job != nil && e.job.state == StateResult {
		s.pending++
	}
	return i
}

func (s *Store) viewLocked(i int32) Entry {
	e := &s.entries[i]
	v := Entry{
		CanonicalSHA256: hex.EncodeToString(e.canon[:]),
		CommandID:       uuidString(e.cmd),
		Decision:        e.decision,
		Reason:          e.reason,
		DecidedAt:       time.Unix(0, e.at).UTC(),
		Expires:         time.Unix(e.expires, 0).UTC(),
	}
	if e.job != nil {
		j := s.jobViewLocked(e)
		v.Job = &j
	}
	return v
}

// checkDecision accepts only what the ADR records: accepted (no reason) or rejected with a reason of lines 4–9.
func checkDecision(d Decision) error {
	switch d.Decision {
	case contract.DecisionAccepted:
		if d.Reason != "" {
			return invalid("accepted não leva motivo")
		}
		return nil
	case contract.DecisionRejected:
		if !d.Reason.Recorded() {
			return invalid("só se grava rejeição das linhas 4–9 (motivo %q não se grava)", d.Reason)
		}
		return nil
	}
	return invalid("decisão %q não se grava (só accepted ou rejected)", d.Decision)
}

// Record records the final decision d on the authenticated envelope v at the verification clock t, under its
// canonical form, its nonce and its command_id — the pipeline calls it BEFORE the ack. It returns only once the record
// is durable (fsync); then the memory has it. ErrRecorded: the canonical form is already recorded (never
// overwritten). ErrFull: a ceiling. ErrInvalid: a decision the ADR does not record (line 3, deferred, lines 0–2), an
// envelope Verify did not produce or whose window is invalid, an accepted type outside the catalog. Any other error
// is a write that did not happen — the pipeline answers unavailable.
func (s *Store) Record(v *contract.Verified, d Decision, t time.Time) (Entry, error) {
	if err := checkDecision(d); err != nil {
		return Entry{}, err
	}
	if v == nil || !reHex64.MatchString(v.CanonicalSHA256()) {
		return Entry{}, invalid("envelope não autenticado pelo Verify")
	}
	issuedAt, notAfter := v.IssuedAt(), v.NotAfter()
	if !issuedAt.Before(notAfter) || notAfter.After(issuedAt.Add(contract.MaxWindow)) {
		return Entry{}, invalid("janela inválida (bad_window nunca se grava)")
	}
	if !validInstant(t) {
		return Entry{}, invalid("instante da decisão inválido: precisa ser o relógio de verificação")
	}
	c := v.Command()
	var j *job
	if d.Decision == contract.DecisionAccepted {
		if _, ok := contract.LookupType(c.Type); !ok {
			return Entry{}, invalid("accepted de um tipo fora do catálogo v1")
		}
		j = &job{typ: c.Type, tenant: c.Tenant, state: StateReceived}
	}
	life := notAfter
	if end := issuedAt.Add(contract.MaxWindow); end.Before(life) {
		life = end
	}
	e := entry{
		canon: canonKey(v.CanonicalSHA256()), nonce: canonKey(c.Nonce), cmd: cmdKey(c.CommandID),
		at: t.UnixNano(), expires: life.Add(EntryGrace).Unix(), decision: d.Decision, reason: d.Reason, job: j,
	}
	line, err := encodeLine(entryRecord(&e))
	if err != nil {
		return Entry{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.findLocked(e.canon, e.nonce, e.cmd, t) >= 0 {
		return Entry{}, ErrRecorded
	}
	if len(s.entries) >= s.cfg.maxEntries && s.hasDeadLocked(t) {
		if err := s.rewriteLocked(t); err != nil && !errors.Is(err, fsutil.ErrNotDurable) {
			return Entry{}, err
		}
	}
	if len(s.entries) >= s.cfg.maxEntries {
		return Entry{}, ErrFull
	}
	if _, err := s.appendLocked(line, false, t); err != nil {
		return Entry{}, err
	}
	return s.viewLocked(s.insertLocked(e)), nil
}

// Floor returns the replay floor (full precision) and whether there is one.
func (s *Store) Floor() (time.Time, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.floor == 0 {
		return time.Time{}, false
	}
	return time.Unix(0, s.floor).UTC(), true
}

// ReplayFloor is the floor as the node publishes it (heartbeat and state node: utc_time rounded UP to the whole
// second, contract.FormatReplayFloor); "" when there is none.
func (s *Store) ReplayFloor() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.floor == 0 {
		return ""
	}
	return contract.FormatReplayFloor(time.Unix(0, s.floor))
}

// FloorUnannounced reports whether the hub may not have seen the current floor yet: true at every start and after
// every new floor, until MarkFloorAnnounced. While it is true the connector sends a heartbeat before its first poll.
func (s *Store) FloorUnannounced() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.floor != 0 && s.floorUnannounced
}

// MarkFloorAnnounced records that a heartbeat carrying replayFloor got a 2xx. A heartbeat that carried an older floor
// does not clear a newer one.
func (s *Store) MarkFloorAnnounced(replayFloor string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.floor != 0 && replayFloor == contract.FormatReplayFloor(time.Unix(0, s.floor)) {
		s.floorUnannounced = false
	}
}

// SetFloor sets the replay floor to t — the verification clock at a (re)enroll — and makes it durable. The floor only
// moves forward. Call it BEFORE persisting the new identity: should the node stop in between, the next boot still
// sees the floor (or, with no identity, enrolls again). An error means the floor is in force in memory but not
// durable; the next write tries again first, and nothing is recorded before it succeeds.
func (s *Store) SetFloor(t time.Time) error {
	if !validInstant(t) {
		return invalid("piso de replay num instante inválido")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if at := t.UnixNano(); at > s.floor {
		s.floor, s.floorDurable = at, false
	}
	s.floorUnannounced = true
	return s.readyLocked(t)
}

// Stats returns the size and health of the store.
func (s *Store) Stats() Stats {
	s.mu.Lock()
	defer s.mu.Unlock()
	n, b := len(s.entries), s.size
	return Stats{
		Entries:        n,
		Bytes:          b,
		Alert:          n*100 >= s.cfg.maxEntries*AlertPercent || b*100 >= s.cfg.maxBytes*AlertPercent,
		Full:           n >= s.cfg.maxEntries || b+entryLineMax > s.cfg.maxBytes,
		PendingResults: s.pending,
		Writable:       s.needRewrite,
	}
}

// Compact rewrites the file without the entries whose life ended at t (and their journal): temp + rename with fsync.
// Nothing to drop, nothing written. The connector calls it on a timer; Record also compacts at the entries ceiling.
func (s *Store) Compact(t time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.hasDeadLocked(t) {
		return nil
	}
	return s.rewriteLocked(t)
}
