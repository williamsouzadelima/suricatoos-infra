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

// DefaultInterval and MinInterval are FLEET_STATE_INTERVAL's default and floor (ADR-0011 "Configuração do nó").
const (
	DefaultInterval = 60 * time.Second
	MinInterval     = 30 * time.Second
)

// ErrInvalidInterval: FLEET_STATE_INTERVAL is not a duration the connector accepts. The connector does not start
// with it.
var ErrInvalidInterval = errors.New("state: FLEET_STATE_INTERVAL inválido")

// ParseInterval parses FLEET_STATE_INTERVAL: empty (unset) is DefaultInterval; anything else is a Go duration
// ("60s", "1m", "1m30s") of whole seconds, at least MinInterval, or ErrInvalidInterval.
func ParseInterval(s string) (time.Duration, error) {
	if s == "" {
		return DefaultInterval, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil || !validInterval(d) {
		return 0, fmt.Errorf("%w: %.32q (mínimo %s, em segundos inteiros)", ErrInvalidInterval, s, MinInterval)
	}
	return d, nil
}

func validInterval(d time.Duration) bool { return d >= MinInterval && d%time.Second == 0 }

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
	// Interval is the collection period (FLEET_STATE_INTERVAL, ParseInterval): zero means DefaultInterval, and
	// below MinInterval — or with a fraction of a second — Open refuses it.
	Interval time.Duration
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
	// Local returns what the connector knows of its node on its own (versions it is told, health it measures), read
	// at every collection of the node kind. nil = nothing.
	Local func() Local
	// Formats is report-formats/manifest.json (slice R5) as the image ships it (LoadManifest). nil = before R5: only
	// the technical edition of suricatoos-pdf is advertised.
	Formats *Manifest
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
	interval  time.Duration
	kinds     []contract.StateKind
	tracker   *tracker
	recovery  Recovery
	log       *slog.Logger
	now       func() time.Time
	dataLimit int // maxDataBytes; a field only so that a test can lower it
	// newTicker is the clock of Run (a time.Ticker); a field only so that a test can drive the cycles.
	newTicker func(d time.Duration) (<-chan time.Time, func())

	collecting sync.Mutex // one cycle at a time

	mu         sync.Mutex
	logged     map[contract.StateKind]string // the error text last logged per kind
	formats    []contract.ReportFormatCapability
	formatsErr error // the failure of gvmd in the node snapshot of formats
	hasNode    bool
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
	interval := cfg.Interval
	if interval == 0 {
		interval = DefaultInterval
	}
	if !validInterval(interval) {
		return nil, fmt.Errorf("%w: %s (mínimo %s, em segundos inteiros)", ErrInvalidInterval, interval, MinInterval)
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
		logger.Warn("estado: arquivo do que o hub já tem inutilizável; todo kind será reenviado",
			"erro", rec.Lost.Error())
	}
	return &Collector{cfg: cfg, interval: interval, kinds: kinds, tracker: tr, recovery: rec, log: logger, now: now,
		dataLimit: maxDataBytes, newTicker: realTicker, logged: map[contract.StateKind]string{}}, nil
}

func realTicker(d time.Duration) (<-chan time.Time, func()) {
	t := time.NewTicker(d)
	return t.C, t.Stop
}

// Run collects at once and then every Interval until ctx ends, and returns ctx.Err(). A cycle never overlaps the
// next: a slow one (gvmd slow, every read up to its timeout) delays it, and the ticks missed meanwhile are dropped.
func (c *Collector) Run(ctx context.Context) error {
	c.Collect(ctx)
	tick, stop := c.newTicker(c.interval)
	defer stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick:
			c.Collect(ctx)
		}
	}
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
	for _, kind := range c.order() {
		if ctx.Err() != nil {
			return
		}
		data, warn, err := c.collectKind(ctx, cyc, kind)
		if err != nil {
			c.tracker.fail(kind, err)
			c.note(kind, err)
			continue
		}
		c.tracker.update(snapshotOf(kind, data, c.now()))
		if warn != nil { // a new snapshot that still carries a failure (node without gvmd)
			c.tracker.fail(kind, warn)
		}
		c.note(kind, warn)
	}
	if err := c.tracker.flush(); err != nil {
		c.log.Warn("estado: não foi possível gravar o que o hub já tem", "erro", err.Error())
	}
}

// order is the order of a cycle: every kind but node, then node — whose health reflects how the others went.
func (c *Collector) order() []contract.StateKind {
	out := make([]contract.StateKind, 0, len(c.kinds))
	for _, kind := range c.kinds {
		if kind != contract.KindNode {
			out = append(out, kind)
		}
	}
	return append(out, contract.KindNode)
}

// collectKind returns the data of one kind; warn is a failure that did not prevent a new snapshot.
func (c *Collector) collectKind(ctx context.Context, cyc *cycle, kind contract.StateKind) (
	data []byte, warn, err error) {
	if kind == contract.KindNode {
		return c.collectNode(ctx)
	}
	data, err = c.collectList(ctx, cyc, kind)
	return data, nil, err
}

func (c *Collector) collectList(ctx context.Context, cyc *cycle, kind contract.StateKind) ([]byte, error) {
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
func (c *Collector) Kinds() []contract.StateKind {
	return append([]contract.StateKind(nil), c.kinds...)
}

// Recovery is what Open found in state-sent.json.
func (c *Collector) Recovery() Recovery { return c.recovery }

// Pending lists, in the schema's order, the kinds whose current snapshot the hub has not accepted: changed since
// the last MarkSent, never sent, or forgotten by a Resync. A kind without any snapshot yet is not pending.
func (c *Collector) Pending() []contract.StateKind { return c.tracker.pending() }

// Current returns the kind's current snapshot (its own copy of the bytes); false when it has none yet.
func (c *Collector) Current(kind contract.StateKind) (Snapshot, bool) {
	return c.tracker.snapshot(kind)
}

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
