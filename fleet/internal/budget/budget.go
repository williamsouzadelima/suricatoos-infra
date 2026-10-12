// Package budget keeps the two LOCAL command budgets of the fleet connector (ADR-0011 "Catálogo de comandos v1"
// → "Política local", and "Limites"): the global budget of accepted commands (policy total_per_hour) and the
// budget of sensitive ones (sensitive_per_hour: opt-in types, report.export and report.summary), which also
// count in the global one. Each is a SLIDING window of one hour, persisted so that a restart does not refill it.
//
// Time is always a parameter: t is the node's verification clock (max(now, watermark) — it never goes back),
// supplied by the caller. The window of t is the instants ts with t − 1h < ts ≤ t: an instant exactly one hour
// old no longer counts. With a clock that never goes back no instant is later than t; should one exist anyway
// (state written under a clock that was ahead, a caller that passes an earlier t), it counts too — the window
// has no upper edge, which is the safe direction: a clock that went back must not let the budget refill. The
// limits are parameters too (they come from the policy, which can change between two commands), so a limit that
// was reduced applies at once to what is already in the window.
//
// Two operations, deliberately apart (ADR: "só comando aceito consome"):
//
//   - Fits only ASKS whether accepting one more command of a given type would exceed a budget (verification line
//     7, rate_limited). It consumes nothing and writes nothing.
//   - Consume records an accepted command: the slice F2.4c calls it together with the durable "accepted"
//     decision. It re-checks the limits under the same lock, so the budget cannot be exceeded even if a caller
//     races, and it returns only after the new state is on disk.
//
// Both take the command TYPE, not a flag: whether the type is sensitive (and so counts in the sensitive budget
// too) is read from the v1 catalog inside the ledger, and a type outside the catalog is an error. The gate that
// asks and the code that consumes therefore cannot disagree about it.
//
// Failure rules, both fail-closed:
//
//   - State that cannot be used at boot (unreadable, too big, not the expected JSON) is NOT an error: the
//     window is treated as FULL for one hour from boot, so that losing the file never reopens the door. Lost
//     tells the caller why (to log and count it) and BlockedUntil until when. The bad file is left as it is —
//     removing it would make the next boot start with an empty budget — and the first Consume after the block
//     replaces it. A file that does not exist is a first boot (an empty budget) only if the caller says so
//     (Options.FirstBoot, true while the node has no identity yet); on a node that already has one, a missing file
//     is a loss and gets the same block. The first boot writes the empty state at once, so that absence later means
//     loss.
//   - A failed write of the consumption is an error (not ErrOverBudget) and the consumption is not counted: the
//     caller answers unavailable (deferred, nothing recorded).
package budget

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"sync"
	"time"

	"github.com/williamsouzadelima/suricatoos-infra/fleet/contract"
	"github.com/williamsouzadelima/suricatoos-infra/fleet/internal/fsutil"
	"github.com/williamsouzadelima/suricatoos-infra/fleet/internal/policy"
)

const (
	// FileName is the state file inside FLEET_STATE_DIR.
	FileName = "budget.json"
	// Window is the length of both sliding windows.
	Window = time.Hour
	// MaxTotal and MaxSensitive are the schema's ceilings of total_per_hour and sensitive_per_hour, defined once
	// in package policy. They also bound the memory: no more than this many instants per window are ever kept,
	// whatever limit the caller passes.
	MaxTotal     = policy.MaxTotalPerHour
	MaxSensitive = policy.MaxSensitivePerHour

	fileVersion  = 1
	maxFileBytes = 1 << 20 // the full file is ~95 KiB
)

// ErrOverBudget: Consume found that one more accepted command does not fit (the caller asked with Fits first;
// this is the same verdict, reached again under the lock). The caller answers rate_limited.
var ErrOverBudget = errors.New("budget: o orçamento não comporta mais um comando aceito")

// Limits are the two budgets in force, taken from the policy.
type Limits struct {
	Total     int // total_per_hour: accepted commands of any type in a sliding hour
	Sensitive int // sensitive_per_hour: the opt-in types, report.export and report.summary (they also count in Total)
}

// usage is what the two windows hold at an instant.
type usage struct{ Total, Sensitive int }

// state is the content of budget.json. The instants are Unix nanoseconds (UTC), so the file round-trips
// exactly and the window edges stay exact to the nanosecond.
type state struct {
	Version     int     `json:"version"`
	TotalNS     []int64 `json:"total_ns"`
	SensitiveNS []int64 `json:"sensitive_ns"`
}

// Ledger is the persisted pair of sliding windows. It is safe for concurrent use.
type Ledger struct {
	path string

	mu        sync.Mutex
	total     []int64 // every accepted command still worth keeping, in insertion order
	sensitive []int64 // the sensitive ones among them

	// writeFile is fsutil.WriteAtomic; it is a field only so that a test can make the write fail.
	writeFile func(path string, data []byte) error

	// set once by Open, never changed afterwards
	blockedUntil int64 // Unix ns; 0 = not blocked
	lost         error
}

// Options are the facts about the node that only the caller knows.
type Options struct {
	// FirstBoot is true when this is the very first start of the node: it has no identity yet (no enroll has ever
	// happened in this FLEET_STATE_DIR), so there is nothing to lose and a missing budget.json is normal.
	//
	// The zero value is the safe one. For a node that already has its identity, a missing budget.json cannot be a
	// first boot: it means the state was lost (the file deleted, the volume rolled back), and that counts as a lost
	// window, exactly like a corrupt file. A caller derives it from the identity (`FirstBoot: !identityExists`);
	// forgetting it makes the ledger stricter, never looser. It only matters when the file is missing: it does not
	// excuse a file that exists and is unusable.
	FirstBoot bool
}

// Open reads the ledger in stateDir/budget.json (FLEET_STATE_DIR). boot is the verification clock at start: it
// dates the block that follows an unusable state, so it must be a real instant: a zero or out-of-range boot is
// refused, because the end of the block would wrap around and the "full" window would end in the past.
//
// What a missing budget.json means depends on opts.FirstBoot. On the first boot the ledger starts empty and WRITES
// the initial (empty) state at once, so that from then on the file's absence is detectable: a node that is
// enrolled but has never accepted a command would otherwise have no file at all, and every restart would look like
// a loss. If that first write fails, Open fails: the connector could not keep a budget. On any later boot, a
// missing file is a lost state (Lost explains it) and nothing is written: the first Consume after the block creates
// the file.
//
// Open also removes the budget.json.tmp-* files that a crash left between a temporary file and its rename (only
// those, since the directory is shared with the other state files; it assumes no other Ledger is writing there). A
// state read from the file is trusted only once it is confirmed on disk (fsync of the file and of the directory) or,
// failing that, written again; if neither works, it counts as lost.
//
// The only errors are therefore programming ones (an empty stateDir, an invalid boot) and the failure of the first
// boot's write; see the package comment for what an unreadable or corrupt file does.
func Open(stateDir string, boot time.Time, opts Options) (*Ledger, error) {
	if stateDir == "" {
		return nil, errors.New("budget: FLEET_STATE_DIR vazio")
	}
	if !validInstant(boot) {
		return nil, errors.New("budget: boot não é um instante válido (valor zero?): precisa ser o relógio de verificação")
	}
	path := filepath.Join(stateDir, FileName)
	// leftovers of a Consume that a crash interrupted; best effort: a file that will not go does not stop the boot
	_, _ = fsutil.RemoveOrphanTemps(path)
	l := &Ledger{path: path, writeFile: openWrite}
	data, err := fsutil.ReadBounded(path, maxFileBytes)
	switch {
	case errors.Is(err, fs.ErrNotExist) && opts.FirstBoot:
		if werr := l.write(nil, nil); werr != nil {
			return nil, fmt.Errorf("budget: gravar o estado inicial: %w", werr)
		}
		return l, nil
	case errors.Is(err, fs.ErrNotExist):
		err = errors.New("budget.json ausente num nó que já tem identidade (apagado ou volume revertido)")
	case err == nil:
		if err = l.load(data); err == nil {
			err = l.confirm()
		}
	}
	if err != nil {
		l.total, l.sensitive = nil, nil
		l.blockedUntil = boot.Add(Window).UnixNano()
		l.lost = fmt.Errorf("budget: estado %s inutilizável, janela cheia até boot+%v: %w", path, Window, err)
	}
	return l, nil
}

// openWrite is the write a ledger opened by Open uses (fsutil.WriteAtomic); a variable only so that a test can make
// the write of Open fail.
var openWrite = fsutil.WriteAtomic

// confirmState makes the state file read at Open durable: one fsync of the file and one of its directory. A variable
// only so that a test can make it fail.
var confirmState = func(path string) error {
	if _, err := fsutil.SyncFile(path); err != nil {
		return err
	}
	return fsutil.SyncDir(filepath.Dir(path))
}

// confirm makes the state just loaded durable before the ledger trusts it: after a crash of the process the page
// cache can still show a Consume whose rename or directory sync never completed. If the file cannot be confirmed,
// the state is written again (temp + rename, which confirms it); if that fails too, the error makes the state lost.
func (l *Ledger) confirm() error {
	cerr := confirmState(l.path)
	if cerr == nil {
		return nil
	}
	if werr := l.write(l.total, l.sensitive); werr != nil {
		return fmt.Errorf("o estado lido não pôde ser confirmado no disco (%v) nem regravado: %w", cerr, werr)
	}
	return nil
}

// validInstant reports whether t can be held as Unix nanoseconds, which is how the ledger stores time (years 1678
// to 2262). The zero time cannot: its nanoseconds overflow int64, and so would the end of the block it dates.
func validInstant(t time.Time) bool { return t.Equal(time.Unix(0, t.UnixNano())) }

func (l *Ledger) load(data []byte) error {
	var st state
	if err := contract.DecodeStrict(data, &st); err != nil {
		return err
	}
	switch {
	case st.Version != fileVersion:
		return fmt.Errorf("versão %d desconhecida", st.Version)
	case len(st.TotalNS) > MaxTotal:
		return fmt.Errorf("total_ns tem %d instantes, o teto é %d", len(st.TotalNS), MaxTotal)
	case len(st.SensitiveNS) > MaxSensitive:
		return fmt.Errorf("sensitive_ns tem %d instantes, o teto é %d", len(st.SensitiveNS), MaxSensitive)
	}
	l.total, l.sensitive = st.TotalNS, st.SensitiveNS
	return nil
}

// Lost is non-nil when the persisted state could not be used at Open (and says why): until BlockedUntil every
// budget is full. The caller logs and counts it.
func (l *Ledger) Lost() error { return l.lost }

// BlockedUntil is the end of the block that follows an unusable state (boot + 1h); the zero time when there was
// none.
func (l *Ledger) BlockedUntil() time.Time {
	if l.blockedUntil == 0 {
		return time.Time{}
	}
	return time.Unix(0, l.blockedUntil).UTC()
}

// Room says, for one more command of a given type, whether each budget that command counts in has room.
type Room struct {
	// Total: the global budget of accepted commands has room. It is false while the ledger is in the block that
	// follows a lost state, which counts as a full window.
	Total bool
	// Sensitive: the budget of sensitive commands has room. Only a sensitive type counts in it, so for any other
	// type it is true; while the ledger is blocked it is false for a sensitive type.
	Sensitive bool
}

// OK reports whether the command fits in every budget it counts in.
func (r Room) OK() bool { return r.Total && r.Sensitive }

// Fits asks whether accepting ONE more command of type typ at t stays inside the limits: the global budget always,
// and the sensitive one too when the catalog says the type is sensitive (opt-in types, report.export and
// report.summary). The ledger derives that from the catalog itself (contract.LookupType) — the caller does not
// pass it — so the gate that asks and the code that consumes cannot disagree about it. A type outside the v1
// catalog is an error (wrapping contract.ErrUnknownType) and Room is empty: nothing fits.
//
// It reads and consumes nothing. A limit of 0 (or negative) accepts nothing of its class, and a limit above the
// schema ceiling is held to the ceiling — which is also what bounds the memory: a window never holds more instants
// than the ceiling.
func (l *Ledger) Fits(t time.Time, typ contract.CommandType, lim Limits) (Room, error) {
	sensitive, err := isSensitive(typ)
	if err != nil {
		return Room{}, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.room(t.UnixNano(), sensitive, lim), nil
}

// isSensitive is the catalog's answer for a type (ADR "Catálogo de comandos v1": opt-in, report.export and
// report.summary count in the sensitive budget).
func isSensitive(typ contract.CommandType) (bool, error) {
	e, ok := contract.LookupType(typ)
	if !ok {
		return false, fmt.Errorf("budget: %w", contract.ErrUnknownType)
	}
	return e.Sensitive, nil
}

func (l *Ledger) room(now int64, sensitive bool, lim Limits) Room {
	lo := now - int64(Window)
	r := Room{Total: countAfter(l.total, lo) < min(lim.Total, MaxTotal), Sensitive: true}
	if sensitive {
		r.Sensitive = countAfter(l.sensitive, lo) < min(lim.Sensitive, MaxSensitive)
	}
	if now < l.blockedUntil { // the block that follows a lost state: every budget is full
		r.Total = false
		r.Sensitive = !sensitive
	}
	return r
}

// Consume records one accepted command of type typ at t, in the global budget and, when the catalog says the
// type is sensitive, in the sensitive one (see Fits: the type decides, not the caller). It returns nil only after
// the new state is durable on disk. ErrOverBudget means it did not fit (nothing changed); a type outside the
// catalog is an error wrapping contract.ErrUnknownType (nothing changed); any other error is a failed write
// (nothing changed either: the consumption does not count). If the error wraps fsutil.ErrNotDurable the file
// already holds the new state but its durability is unknown; the ledger in memory stays as it was, so a retry
// writes the state once more, from memory. Instants that left the window are dropped from memory and from the file.
func (l *Ledger) Consume(t time.Time, typ contract.CommandType, lim Limits) error {
	sensitive, err := isSensitive(typ)
	if err != nil {
		return err
	}
	now := t.UnixNano()
	l.mu.Lock()
	defer l.mu.Unlock()

	if !l.room(now, sensitive, lim).OK() {
		return ErrOverBudget
	}
	// the new state is built apart and swapped in only after the write, so a failed write leaves the ledger as it
	// was; it holds the instants of the window plus this one, which by Fits is never more than the ceiling
	total := keepAfter(l.total, now-int64(Window))
	sens := keepAfter(l.sensitive, now-int64(Window))
	total = append(total, now)
	if sensitive {
		sens = append(sens, now)
	}
	if err := l.write(total, sens); err != nil {
		return fmt.Errorf("budget: gravar %s: %w", l.path, err)
	}
	l.total, l.sensitive = total, sens
	return nil
}

// write persists a state (nil lists are written as empty ones).
func (l *Ledger) write(total, sens []int64) error {
	if total == nil {
		total = []int64{}
	}
	if sens == nil {
		sens = []int64{}
	}
	b, err := json.Marshal(state{Version: fileVersion, TotalNS: total, SensitiveNS: sens})
	if err != nil {
		return err // unreachable: a struct of ints
	}
	return l.writeFile(l.path, append(b, '\n'))
}

// usageAt returns how many instants each window holds at t. It does not apply the block that follows an unusable
// state (a lost ledger holds no instants).
func (l *Ledger) usageAt(t time.Time) usage {
	lo := t.UnixNano() - int64(Window)
	l.mu.Lock()
	defer l.mu.Unlock()
	return usage{Total: countAfter(l.total, lo), Sensitive: countAfter(l.sensitive, lo)}
}

// countAfter counts the instants later than lo (= t − 1h): the window of t.
func countAfter(list []int64, lo int64) int {
	n := 0
	for _, ts := range list {
		if ts > lo {
			n++
		}
	}
	return n
}

// keepAfter returns a NEW slice (never nil, so it serializes as []) with the instants later than lo; the old
// one is untouched, which is what lets a failed write leave the ledger as it was.
func keepAfter(list []int64, lo int64) []int64 {
	out := make([]int64, 0, len(list)+1)
	for _, ts := range list {
		if ts > lo {
			out = append(out, ts)
		}
	}
	return out
}
