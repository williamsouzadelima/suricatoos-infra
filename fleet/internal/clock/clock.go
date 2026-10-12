// Package clock is the fleet node's verification clock (ADR-0011 "Anti-replay, idempotência e entrega" → "Relógio
// de verificação"): t = max(now, watermark), where the watermark is the largest instant the node has seen. It is
// persisted — FLEET_STATE_DIR/clock.json, temp + rename with fsync, 0600 (fsutil.WriteAtomic) — every minute (Tick,
// from the connector's timer) and at every decision (Persist, from the verification pipeline), so a clock that goes
// back across a reboot never reopens a window that was already seen expired. The hub's server_time never moves it.
//
// It also parses FLEET_CLOCK_SKEW (ParseSkew): 2m by default, at most 10m — above that the connector does not
// start.
//
// What a lost watermark means is not decided here: Open reports an unreadable or corrupt clock.json (Lost) and
// whether the file existed at all (Found), and the anti-replay store, which owns the state of FLEET_STATE_DIR, treats
// the loss as a loss of state (a replay floor). The store also raises the mark to its latest recorded decision
// (Raise), so a stale clock.json cannot pull the clock below a decision already on disk.
//
// Time is UTC with nanosecond precision and never carries Go's monotonic reading: with it, comparisons between two
// readings of time.Now() use the monotonic clock alone, and a wall clock that went back inside the process would drag
// the (wall-clock) mark back with it.
package clock

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"regexp"
	"strconv"
	"sync"
	"time"

	"github.com/williamsouzadelima/suricatoos-infra/fleet/contract"
	"github.com/williamsouzadelima/suricatoos-infra/fleet/internal/fsutil"
)

const (
	// FileName is the watermark file inside FLEET_STATE_DIR.
	FileName = "clock.json"
	// PersistEvery is the cadence of Tick: the mark is made durable at least once a minute while it moves.
	PersistEvery = time.Minute
	// DefaultSkew and MaxSkew are FLEET_CLOCK_SKEW's default and ceiling (the contract's).
	DefaultSkew = contract.DefaultClockSkew
	MaxSkew     = contract.MaxClockSkew

	fileVersion  = 1
	maxFileBytes = 4 << 10 // the file is ~40 bytes
)

// ErrInvalidSkew: FLEET_CLOCK_SKEW is not a duration the connector accepts. The connector does not start with it.
var ErrInvalidSkew = errors.New("clock: FLEET_CLOCK_SKEW inválido")

// skewForm is the strict grammar of FLEET_CLOCK_SKEW: whole hours, minutes and seconds, each at most once and in that
// order, each in decimal without a leading zero — "2m", "90s", "1m30s". No sign, fraction, space or other unit.
var skewForm = regexp.MustCompile(`^(?:(0|[1-9][0-9]*)h)?(?:(0|[1-9][0-9]*)m)?(?:(0|[1-9][0-9]*)s)?$`)

// ParseSkew parses FLEET_CLOCK_SKEW. Empty (unset) is DefaultSkew; anything else must match the strict grammar
// (skewForm) and be at most MaxSkew, or it is ErrInvalidSkew. A skew is whole seconds, so the replay floor (rounded
// up to the second) is compared in whole seconds too.
func ParseSkew(s string) (time.Duration, error) {
	if s == "" {
		return DefaultSkew, nil
	}
	m := skewForm.FindStringSubmatch(s)
	if m == nil || (m[1] == "" && m[2] == "" && m[3] == "") {
		return 0, fmt.Errorf("%w: %.32q não é uma duração em h/m/s inteiros (ex.: 2m, 90s)", ErrInvalidSkew, s)
	}
	var d time.Duration
	for i, unit := range []time.Duration{time.Hour, time.Minute, time.Second} {
		if m[i+1] == "" {
			continue
		}
		n, err := strconv.ParseInt(m[i+1], 10, 64)
		if err != nil || n > int64(MaxSkew/unit) {
			return 0, fmt.Errorf("%w: %.32q acima do teto de %v", ErrInvalidSkew, s, MaxSkew)
		}
		d += time.Duration(n) * unit
	}
	if d > MaxSkew {
		return 0, fmt.Errorf("%w: %.32q acima do teto de %v", ErrInvalidSkew, s, MaxSkew)
	}
	return d, nil
}

// fileState is the content of clock.json: the mark in Unix nanoseconds, exact across a round trip.
type fileState struct {
	Version int   `json:"version"`
	MarkNS  int64 `json:"mark_ns"`
}

// Clock is the verification clock of one FLEET_STATE_DIR. It is safe for concurrent use.
type Clock struct {
	path string
	// write is fsutil.WriteAtomic; a field only so that a test can make the write fail.
	write func(path string, data []byte) error

	mu      sync.Mutex
	mark    time.Time // the largest instant seen (UTC, no monotonic reading); zero = none
	durable time.Time // the mark last confirmed on disk; zero = none

	// set once by Open
	found bool  // clock.json existed
	lost  error // clock.json existed but could not be used
}

// Open reads stateDir/clock.json. A missing file is a clock with no mark (Found false). A file that exists but cannot
// be used — unreadable, too big, not a regular file, not the expected JSON — is not an error either: the clock starts
// with no mark and Lost says why (the caller decides what the loss costs). The only error is an empty stateDir.
//
// Open also removes the clock.json.tmp-* files that a crash left between a temporary file and its rename (only those,
// since the directory is shared with the other state files; it assumes no other Clock is writing there — the store
// opens it under the directory lock).
func Open(stateDir string) (*Clock, error) {
	if stateDir == "" {
		return nil, errors.New("clock: FLEET_STATE_DIR vazio")
	}
	c := &Clock{path: filepath.Join(stateDir, FileName), write: fsutil.WriteAtomic}
	// leftovers of a Persist that a crash interrupted; best effort: a file that will not go does not stop the boot
	_, _ = fsutil.RemoveOrphanTemps(c.path)
	data, err := fsutil.ReadBounded(c.path, maxFileBytes)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return c, nil
	case err == nil:
		err = c.load(data)
	}
	c.found = true
	if err != nil {
		c.lost = fmt.Errorf("clock: marca d'água %s inutilizável: %w", c.path, err)
	}
	return c, nil
}

func (c *Clock) load(data []byte) error {
	var st fileState
	if err := contract.DecodeStrict(data, &st); err != nil {
		return err
	}
	if st.Version != fileVersion {
		return fmt.Errorf("versão %d desconhecida", st.Version)
	}
	// the mark read is not durable yet: after a crash of the process the file may be a WriteAtomic whose directory
	// sync never completed; the first Persist (the store's boot) writes it again
	c.mark = time.Unix(0, st.MarkNS).UTC()
	return nil
}

// Found reports whether clock.json existed at Open (usable or not).
func (c *Clock) Found() bool { return c.found }

// Lost is non-nil when clock.json existed at Open but could not be used, and says why.
func (c *Clock) Lost() error { return c.lost }

// instant drops the monotonic reading and the location of t, and the instants a mark cannot hold (it is persisted as
// Unix nanoseconds: years 1678 to 2262), which become the zero time.
func instant(t time.Time) time.Time {
	t = t.Round(0).UTC()
	if !t.Equal(time.Unix(0, t.UnixNano())) {
		return time.Time{}
	}
	return t
}

// Raise lifts the mark to t when t is later (the anti-replay store raises it to its latest recorded decision); it
// never lowers it.
func (c *Clock) Raise(t time.Time) {
	t = instant(t)
	c.mu.Lock()
	defer c.mu.Unlock()
	if t.After(c.mark) {
		c.mark = t
	}
}

// Now returns the verification clock for the reading now — t = max(now, mark) — and makes t the mark. It never goes
// back. The result is UTC, without a monotonic reading.
func (c *Clock) Now(now time.Time) time.Time {
	now = instant(now)
	c.mu.Lock()
	defer c.mu.Unlock()
	if now.After(c.mark) {
		c.mark = now
	}
	return c.mark
}

// Mark returns the current mark (the zero time when none).
func (c *Clock) Mark() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.mark
}

// Persist makes the current mark durable (WriteAtomic), unless it already is. It returns nil only once the file holds
// the mark durably: any error — fsutil.ErrNotDurable included — leaves the mark not durable in memory, and the next
// Persist writes it again, from memory.
func (c *Clock) Persist() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.persistLocked()
}

func (c *Clock) persistLocked() error {
	if c.mark.IsZero() || !c.mark.After(c.durable) {
		return nil
	}
	b, err := json.Marshal(fileState{Version: fileVersion, MarkNS: c.mark.UnixNano()})
	if err != nil {
		return err // unreachable: two ints
	}
	if err := c.write(c.path, append(b, '\n')); err != nil {
		return fmt.Errorf("clock: gravar a marca d'água em %s: %w", c.path, err)
	}
	c.durable = c.mark
	return nil
}

// Tick is the connector's timer: it reads the clock (Now) and persists the mark when it moved at least PersistEvery
// beyond what is durable — so the mark is on disk at least once a minute while time passes, without a write on every
// tick. The error is the persist's.
func (c *Clock) Tick(now time.Time) error {
	now = instant(now)
	c.mu.Lock()
	defer c.mu.Unlock()
	if now.After(c.mark) {
		c.mark = now
	}
	if !c.durable.IsZero() && c.mark.Sub(c.durable) < PersistEvery {
		return nil
	}
	return c.persistLocked()
}
