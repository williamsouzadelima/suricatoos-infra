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
//   - Fits only ASKS whether accepting one more command would exceed a budget (verification line 7,
//     rate_limited). It consumes nothing and writes nothing.
//   - Consume records an accepted command: the slice F2.4c calls it together with the durable "accepted"
//     decision. It re-checks the limits under the same lock, so the budget cannot be exceeded even if a caller
//     races, and it returns only after the new state is on disk.
//
// Failure rules, both fail-closed:
//
//   - State that cannot be used at boot (unreadable, too big, not the expected JSON) is NOT an error: the
//     window is treated as FULL for one hour from boot, so that losing the file never reopens the door. Lost
//     tells the caller why (to log and count it) and BlockedUntil until when. The bad file is left as it is —
//     removing it would make the next boot start with an empty budget — and the first Consume after the block
//     replaces it. A file that does not exist is a first boot: an empty budget.
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

	// set once by Open, never changed afterwards
	blockedUntil int64 // Unix ns; 0 = not blocked
	lost         error
}

// Open reads the ledger in stateDir/budget.json (FLEET_STATE_DIR). boot is the verification clock at start: it
// dates the block that follows an unusable state, so it must be a real instant: a zero or out-of-range boot is
// refused, because the end of the block would wrap around and the "full" window would end in the past. The only
// errors are programming ones (an empty stateDir, an invalid boot); see the package comment for what an
// unreadable or corrupt file does.
func Open(stateDir string, boot time.Time) (*Ledger, error) {
	if stateDir == "" {
		return nil, errors.New("budget: FLEET_STATE_DIR vazio")
	}
	if !validInstant(boot) {
		return nil, errors.New("budget: boot não é um instante válido (valor zero?): precisa ser o relógio de verificação")
	}
	path := filepath.Join(stateDir, FileName)
	l := &Ledger{path: path}
	data, err := fsutil.ReadBounded(path, maxFileBytes)
	if errors.Is(err, fs.ErrNotExist) {
		return l, nil // first boot
	}
	if err == nil {
		err = l.load(data)
	}
	if err != nil {
		l.total, l.sensitive = nil, nil
		l.blockedUntil = boot.Add(Window).UnixNano()
		l.lost = fmt.Errorf("budget: estado %s inutilizável, janela cheia até boot+%v: %w", path, Window, err)
	}
	return l, nil
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

// Fits reports whether accepting ONE more command at t stays inside the limits: the global budget always, and the
// sensitive one too when the command is sensitive. It reads and consumes nothing. A limit of 0 (or negative)
// accepts nothing of its class, and a limit above the schema ceiling is held to the ceiling — which is also what
// bounds the memory: a window never holds more instants than the ceiling.
func (l *Ledger) Fits(t time.Time, sensitive bool, lim Limits) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.fits(t.UnixNano(), sensitive, lim)
}

func (l *Ledger) fits(now int64, sensitive bool, lim Limits) bool {
	if now < l.blockedUntil {
		return false
	}
	lo := now - int64(Window)
	if countAfter(l.total, lo) >= min(lim.Total, MaxTotal) {
		return false
	}
	if sensitive && countAfter(l.sensitive, lo) >= min(lim.Sensitive, MaxSensitive) {
		return false
	}
	return true
}

// Consume records one accepted command at t, in the global budget and, when sensitive, in the sensitive one.
// It returns nil only after the new state is durable on disk. ErrOverBudget means it did not fit (nothing
// changed); any other error is a failed write (nothing changed either: the consumption does not count).
// Instants that left the window are dropped from memory and from the file.
func (l *Ledger) Consume(t time.Time, sensitive bool, lim Limits) error {
	now := t.UnixNano()
	l.mu.Lock()
	defer l.mu.Unlock()

	if !l.fits(now, sensitive, lim) {
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
	b, err := json.Marshal(state{Version: fileVersion, TotalNS: total, SensitiveNS: sens})
	if err != nil {
		return fmt.Errorf("budget: serializar: %w", err) // unreachable: a struct of ints
	}
	if err := fsutil.WriteAtomic(l.path, append(b, '\n')); err != nil {
		return fmt.Errorf("budget: gravar %s: %w", l.path, err)
	}
	l.total, l.sensitive = total, sens
	return nil
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
