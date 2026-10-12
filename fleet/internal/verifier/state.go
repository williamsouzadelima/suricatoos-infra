package verifier

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/williamsouzadelima/suricatoos-infra/fleet/internal/audit"
	"github.com/williamsouzadelima/suricatoos-infra/fleet/internal/budget"
	"github.com/williamsouzadelima/suricatoos-infra/fleet/internal/clock"
	"github.com/williamsouzadelima/suricatoos-infra/fleet/internal/replay"
)

// State is the node's local state the pipeline writes, opened by OpenState.
type State struct {
	Store  *replay.Store
	Ledger *budget.Ledger
	Audit  *audit.Log
}

// StateOptions are what only the connector knows at boot.
type StateOptions struct {
	// IdentityExists is true when the node's fleet certificate is present. On the very first start of a node it is
	// false, and OpenState creates the anti-replay store, the watermark and budget.json BEFORE the enroll persists the
	// identity: the first start after the enroll then finds them and is not a loss. With it true, a missing store,
	// watermark or budget.json IS a loss (replay floor; budget full for one hour).
	IdentityExists bool
	// Logger receives the facts of the boot. nil discards them.
	Logger *slog.Logger
}

// OpenState opens the local state of stateDir (FLEET_STATE_DIR) in the order the identity needs: first the
// anti-replay store — which takes the directory's exclusive lock (a second connector gets fsutil.ErrLocked and does
// not start), opens the verification clock and raises it to its latest decision —, then the budget ledger and the
// audit, both dated by that verification clock (never the raw wall clock). Every (re)enroll then calls
// Store.SetFloor BEFORE it persists the new identity.
func OpenState(stateDir string, now time.Time, opts StateOptions) (*State, error) {
	logger := opts.Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	st, err := replay.Open(stateDir, now, replay.Options{IdentityExists: opts.IdentityExists, Logger: logger})
	if err != nil {
		return nil, err
	}
	t := st.Clock().Now(now)
	led, err := budget.Open(stateDir, t, budget.Options{FirstBoot: !opts.IdentityExists})
	if err != nil {
		st.Close()
		return nil, err
	}
	if lost := led.Lost(); lost != nil {
		logger.Warn("orçamentos: estado perdido; janela cheia até o fim do bloqueio", "erro", lost.Error(),
			"até", led.BlockedUntil().Format(time.RFC3339))
	}
	aud, err := audit.Open(stateDir, t, audit.Options{Logger: logger})
	if err != nil {
		st.Close()
		return nil, fmt.Errorf("verifier: abrir a auditoria: %w", err)
	}
	return &State{Store: st, Ledger: led, Audit: aud}, nil
}

// Clock is the verification clock of the directory.
func (s *State) Clock() *clock.Clock { return s.Store.Clock() }

// Close releases the directory (its exclusive lock).
func (s *State) Close() error { return s.Store.Close() }

// Status is what the node's heartbeat and state report about the local state (F2.6): the replay floor and whether
// the hub may not have seen it, the store's size, alert and recovery, the audit's recovery and poisoning, and the
// losses the boot found.
type Status struct {
	ReplayFloor      string
	FloorUnannounced bool
	Store            replay.Stats
	StoreRecovery    replay.Recovery
	Audit            audit.Status
	ClockLost        error
	BudgetLost       error
}

// Status returns the state's Status.
func (s *State) Status() Status {
	return Status{
		ReplayFloor:      s.Store.ReplayFloor(),
		FloorUnannounced: s.Store.FloorUnannounced(),
		Store:            s.Store.Stats(),
		StoreRecovery:    s.Store.Recovery(),
		Audit:            s.Audit.Status(),
		ClockLost:        s.Store.Clock().Lost(),
		BudgetLost:       s.Ledger.Lost(),
	}
}
