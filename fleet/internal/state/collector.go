package state

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/williamsouzadelima/suricatoos-infra/fleet/contract"
	"github.com/williamsouzadelima/suricatoos-infra/fleet/internal/tenant"
)

// Tenants is what the state reads of the node's tenants (tenant.Source has it).
type Tenants interface {
	List() ([]tenant.Listing, error)
	WithPassword() (map[string]bool, error)
}

// AuditTail is the local audit as the state reads it (*audit.Log has it).
type AuditTail interface {
	Tail() contract.DataAuditTail
}

// ReplayFloor is the anti-replay store as the state reads it (*replay.Store has it): the floor as the node
// publishes it, "" when there is none.
type ReplayFloor interface {
	ReplayFloor() string
}

// Config is what a Collector reads. Every source is an interface, so the tests use fakes.
type Config struct {
	NodeKind         contract.NodeKind
	ConnectorVersion string // the connector's version_string
	StateDir         string // FLEET_STATE_DIR: policy.json is read there, state-sent.json written there
	// GVM is the gvmd side (Bridge over fleet_ops.py): node in part, tasks, targets, schedules, reports.
	GVM GVM
	// Tenants is the node's tenant knowledge (tenant.Open): scope, and the attribution of every list kind.
	Tenants Tenants
	// ControlPlane is the central node's admin API (slice F2.2): agents, tokens, sensors, scan_requests and
	// remediation. Required on the central node, ignored on the others.
	ControlPlane ControlPlane
	// Audit is the local audit (audit.Open): audit_tail.
	Audit AuditTail
	// Floor is the anti-replay store (replay.Open): the replay_floor of the node kind.
	Floor ReplayFloor
	// Now dates collected_at; nil = time.Now.
	Now func() time.Time
	// Logger receives one line when a kind's collection starts failing (or its error changes) and one when it
	// recovers — never one per cycle. nil discards them.
	Logger *slog.Logger
}

// Collector collects the state of a node — one snapshot per kind — and keeps the "send only when it changes"
// bookkeeping the sender (slice F2.6) uses. It is safe for concurrent use: the collection runs in its own goroutine
// while the sender reads Pending/Current and calls MarkSent.
type Collector struct {
	cfg       Config
	kinds     []contract.StateKind
	tracker   *tracker
	recovery  Recovery
	log       *slog.Logger
	now       func() time.Time
	dataLimit int // maxDataBytes; a field only so that a test can lower it

	collecting sync.Mutex // one cycle at a time

	mu     sync.Mutex
	logged map[contract.StateKind]string // the error text last logged per kind
}

// Open checks the configuration and reads FLEET_STATE_DIR/state-sent.json (see Recovery).
func Open(cfg Config) (*Collector, error) {
	kinds := KindsOf(cfg.NodeKind)
	switch {
	case kinds == nil:
		return nil, fmt.Errorf("state: node_kind %.64q inválido", cfg.NodeKind)
	case !ruleVersion.ok(cfg.ConnectorVersion):
		return nil, errors.New("state: connector_version inválida")
	case cfg.GVM == nil || cfg.Tenants == nil || cfg.Audit == nil || cfg.Floor == nil:
		return nil, errors.New("state: fonte de estado ausente na configuração")
	case cfg.NodeKind == contract.NodeCentral && cfg.ControlPlane == nil:
		return nil, errors.New("state: o nó central precisa da API admin do control-plane")
	}
	tr, rec, err := openTracker(cfg.StateDir, kinds)
	if err != nil {
		return nil, err
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	if rec.Lost != nil {
		logger.Warn("estado: arquivo do que o hub já tem inutilizável; todo kind será reenviado", "erro", rec.Lost.Error())
	}
	return &Collector{cfg: cfg, kinds: kinds, tracker: tr, recovery: rec, log: logger, now: now,
		dataLimit: maxDataBytes, logged: map[contract.StateKind]string{}}, nil
}

// cycle is what one collection shares between its kinds: the tenant listing, read once.
type cycle struct {
	tenants   []tenant.Listing
	tenantErr error
	loaded    bool
}

func (c *Collector) listing(cyc *cycle) ([]tenant.Listing, error) {
	if !cyc.loaded {
		cyc.tenants, cyc.tenantErr = c.cfg.Tenants.List()
		cyc.loaded = true
	}
	return cyc.tenants, cyc.tenantErr
}

// Collect runs one cycle: every kind of the node, each from its own source. A source that fails costs only its
// kind, which keeps its last snapshot and exposes the error (Errors). A context that ends stops the cycle between
// two kinds.
func (c *Collector) Collect(ctx context.Context) {
	c.collecting.Lock()
	defer c.collecting.Unlock()
	cyc := &cycle{}
	for _, kind := range c.kinds {
		if ctx.Err() != nil {
			return
		}
		data, err := c.collectKind(ctx, cyc, kind)
		if err != nil {
			c.tracker.fail(kind, err)
			c.note(kind, err)
			continue
		}
		c.tracker.update(snapshotOf(kind, data, c.now()))
		c.note(kind, nil)
	}
	if err := c.tracker.flush(); err != nil {
		c.log.Warn("estado: não foi possível gravar o que o hub já tem", "erro", err.Error())
	}
}

func (c *Collector) collectKind(ctx context.Context, cyc *cycle, kind contract.StateKind) ([]byte, error) {
	switch kind {
	case contract.KindScope:
		return c.collectScope(cyc)
	case contract.KindAuditTail:
		return c.collectAuditTail()
	case contract.KindTasks:
		return c.collectTasks(ctx, cyc)
	case contract.KindTargets:
		return c.collectTargets(ctx, cyc)
	case contract.KindSchedules:
		return c.collectSchedules(ctx, cyc)
	case contract.KindReports:
		return c.collectReports(ctx, cyc)
	case contract.KindAgents:
		return cpList(c, ctx, cyc, agentSpec, c.cfg.ControlPlane.Agents)
	case contract.KindTokens:
		return cpList(c, ctx, cyc, tokenSpec, c.cfg.ControlPlane.Tokens)
	case contract.KindSensors:
		return cpList(c, ctx, cyc, sensorSpec, c.cfg.ControlPlane.Sensors)
	case contract.KindScanRequests:
		return cpList(c, ctx, cyc, scanRequestSpec, c.cfg.ControlPlane.ScanRequests)
	case contract.KindRemediation:
		return cpList(c, ctx, cyc, remediationSpec, c.cfg.ControlPlane.Remediation)
	}
	return nil, fmt.Errorf("state: kind %s ainda sem coletor", kind)
}

// note logs the transitions of a kind's collection: failing, a different error, recovered.
func (c *Collector) note(kind contract.StateKind, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	last, failing := c.logged[kind]
	switch {
	case err != nil && (!failing || last != err.Error()):
		c.logged[kind] = err.Error()
		c.log.Warn("estado: coleta falhou; o kind mantém o último retrato", "kind", string(kind), "erro", err.Error())
	case err == nil && failing:
		delete(c.logged, kind)
		c.log.Info("estado: coleta voltou", "kind", string(kind))
	}
}

// Kinds returns the state kinds of this node, in the schema's order.
func (c *Collector) Kinds() []contract.StateKind { return append([]contract.StateKind(nil), c.kinds...) }

// Recovery is what Open found in state-sent.json.
func (c *Collector) Recovery() Recovery { return c.recovery }

// Pending lists, in the schema's order, the kinds whose current snapshot the hub has not accepted: changed since
// the last MarkSent, never sent, or forgotten by a Resync. A kind without any snapshot yet is not pending.
func (c *Collector) Pending() []contract.StateKind { return c.tracker.pending() }

// Current returns the kind's current snapshot (its own copy of the bytes); false when it has none yet.
func (c *Collector) Current(kind contract.StateKind) (Snapshot, bool) { return c.tracker.snapshot(kind) }

// MarkSent records that the hub accepted (2xx) the PUT of kind whose content_sha256 was sha256 — the hash of the
// snapshot that was actually sent, which may be older than the current one (then the kind stays pending). It counts
// in memory at once; an error says only that FLEET_STATE_DIR/state-sent.json could not be written (the next cycle
// writes it again; until then a restart would send the kind once more).
func (c *Collector) MarkSent(kind contract.StateKind, sha256 string) error {
	return c.tracker.markSent(kind, sha256)
}

// Resync forces kinds to go again (the heartbeat's resync, the state.resync command): it returns those of this node,
// in the schema's order, and ignores any other. Like MarkSent, it counts in memory at once and an error only says the
// file is behind.
func (c *Collector) Resync(kinds []contract.StateKind) ([]contract.StateKind, error) {
	return c.tracker.resync(kinds)
}

// Hashes returns the content_sha256 of every kind's current snapshot: the heartbeat's state_hashes.
func (c *Collector) Hashes() map[contract.StateKind]string { return c.tracker.hashes() }

// Errors returns the kinds whose last collection failed, with the error.
func (c *Collector) Errors() map[contract.StateKind]error { return c.tracker.errors() }
