package events

import (
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"path/filepath"
	"regexp"
	"sync"

	"github.com/williamsouzadelima/suricatoos-infra/fleet/contract"
	"github.com/williamsouzadelima/suricatoos-infra/fleet/internal/fsutil"
)

// MaxOutbox is the outbox's cap (ADR-0011 "Limites"): when it is full, the oldest events are dropped and counted
// (Dropped, the heartbeat's outbox_dropped).
const MaxOutbox = 10_000

// Config is what an Outbox needs.
type Config struct {
	// StateDir is FLEET_STATE_DIR: the outbox and the baseline of the transitions live in StateDir/events.log.
	StateDir string
	// NodeKind is the node's kind: agents and remediation have transitions only on the central node.
	NodeKind contract.NodeKind
	// StaleAfterHours is FLEET_FEED_STALE_HOURS (ParseStaleHours): 0 = DefaultStaleHours.
	StaleAfterHours int
	// Logger receives the facts of the boot and the failures nobody else sees (an observation that could not be
	// recorded, the cap dropping events). nil discards them.
	Logger *slog.Logger
}

// Recovery is what Open found in events.log.
type Recovery struct {
	// Absent: there was no file, or one without a single complete record — the first start in this FLEET_STATE_DIR,
	// or a file removed. There is no baseline: the first observation of each kind only records one.
	Absent bool
	// Unreadable: the file could not be read. The outbox starts empty and without a baseline.
	Unreadable error
	// Corrupt counts the records refused (checksum, decode or rules) and FirstCorrupt says why the first one was.
	// The baseline read is dropped with them; the valid events are kept.
	Corrupt      int
	FirstCorrupt string
	// BaselineLost: no baseline survived the read (absent, unreadable or corrupt file).
	BaselineLost bool
	// DiscardedBytes: an incomplete last record — a write a crash cut, which never counted — was left out.
	DiscardedBytes int64
	// Events is how many events came back into the outbox.
	Events int
	// RewriteErr: the boot could not rewrite the file from memory. Until a rewrite succeeds nothing is recorded and
	// no event is handed out (every call tries it again).
	RewriteErr error
}

// queued is one event of the outbox: its seq, its event_id and its exact bytes.
type queued struct {
	seq int64
	id  string
	enc []byte
}

// Outbox is the node's durable event outbox and the baseline of the transitions (see the package documentation). It
// is safe for concurrent use. There is one Outbox per FLEET_STATE_DIR, opened while the connector holds the
// directory's exclusive lock (replay.Open takes it).
type Outbox struct {
	path, dir    string
	nodeKind     contract.NodeKind
	kinds        []contract.StateKind // the tracked kinds of this node
	staleAfter   int
	log          *slog.Logger
	ops          fileOps
	newID        func() string
	capacity     int   // MaxOutbox; a field only so that a test can lower it
	batchLimit   int   // contract.MaxEventBatchBytes; a field only so that a test can lower it
	compactSlack int64 // compactSlack; a field only so that a test can lower it

	observing sync.Mutex                    // one Observe at a time: the baseline is read under it
	memo      map[contract.StateKind]string // per kind, the observation last taken in (under observing)

	mu       sync.Mutex
	base     *baseline // changed only under observing AND mu
	queue    []queued
	head     int64 // every event with seq <= head has left the outbox (delivered or dropped)
	last     int64 // the last seq given
	dropped  int64 // events the cap dropped since Open
	dropping bool  // the cap is dropping (logged once per episode)
	recovery Recovery

	size, baseSize int64       // the size of the file as this outbox left it, and right after the last rewrite
	ident          fs.FileInfo // the file this outbox wrote
	needRewrite    error       // the file cannot be appended to: the next write rewrites it from memory first
	needDirSync    bool        // a rewrite is in place, its directory entry not confirmed
}

// Open reads FLEET_STATE_DIR/events.log (see Recovery) and rewrites it from memory: what was read is trusted only
// once that rewrite made it durable. What the file holds is never an error.
func Open(cfg Config) (*Outbox, error) { return open(cfg, defaultOps(), newEventID) }

func open(cfg Config, ops fileOps, newID func() string) (*Outbox, error) {
	kinds := kindsOf(cfg.NodeKind)
	stale := cfg.StaleAfterHours
	if stale == 0 {
		stale = DefaultStaleHours
	}
	switch {
	case cfg.StateDir == "":
		return nil, errors.New("events: FLEET_STATE_DIR vazio")
	case kinds == nil:
		return nil, fmt.Errorf("events: node_kind %.64q inválido", cfg.NodeKind)
	case stale < 1 || stale > MaxStaleHours:
		return nil, fmt.Errorf("%w: %d (horas inteiras de 1 a %d)", ErrInvalidStaleHours, cfg.StaleAfterHours,
			MaxStaleHours)
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	o := &Outbox{path: filepath.Join(cfg.StateDir, FileName), dir: cfg.StateDir, nodeKind: cfg.NodeKind, kinds: kinds,
		staleAfter: stale,
		log:        logger, ops: ops, newID: newID, capacity: MaxOutbox, batchLimit: contract.MaxEventBatchBytes,
		compactSlack: compactSlack, memo: map[contract.StateKind]string{}, base: newBaseline()}
	// leftovers of a rewrite a crash interrupted; best effort (the lock of the directory says no one else writes here)
	_, _ = fsutil.RemoveOrphanTemps(o.path)

	o.mu.Lock()
	defer o.mu.Unlock()
	sc := o.scanLocked()
	rec := &o.recovery
	rec.Absent, rec.Unreadable, rec.Corrupt, rec.FirstCorrupt = sc.absent, sc.unreadable, sc.corrupt, sc.firstBad
	rec.DiscardedBytes = sc.partial
	if sc.unreadable != nil {
		// what was read before the failure cannot be told complete
		o.base, o.queue, o.head, o.last = newBaseline(), nil, 0, 0
		logger.Error("eventos: arquivo ilegível; a outbox começa vazia e sem linha de base",
			"erro", sc.unreadable.Error())
	}
	if sc.lost {
		o.base = newBaseline()
		logger.Error("eventos: registros corrompidos; a linha de base foi descartada e os eventos válidos, mantidos",
			"registros", sc.corrupt, "motivo", sc.firstBad)
	}
	if sc.partial > 0 {
		logger.Warn("eventos: registro final incompleto descartado (queda no meio da gravação; ele nunca contou)",
			"bytes", sc.partial)
	}
	rec.BaselineLost = sc.absent || sc.unreadable != nil || sc.lost
	o.base.prune(kinds)
	rec.Events = len(o.queue)
	if len(o.queue) > o.capacity { // a file of a build with a larger cap: the oldest go, as the cap says
		over := len(o.queue) - o.capacity
		o.dropped += int64(over)
		o.leaveLocked(o.queue[over-1].seq)
	}
	// the boot always rewrites: it leaves out what was not taken (an incomplete or corrupt record) and makes what was
	// read durable before any of it is trusted
	if err := o.rewriteLocked(); err != nil && !errors.Is(err, fsutil.ErrNotDurable) {
		o.needRewrite, rec.RewriteErr = err, err
		logger.Error("eventos: o arquivo não pôde ser reescrito no boot; "+
			"nada se grava nem se entrega até uma reescrita dar certo",
			"erro", err.Error())
	}
	return o, nil
}

// Recovery returns what Open found.
func (o *Outbox) Recovery() Recovery {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.recovery
}

// Len is how many events wait in the outbox: the heartbeat's outbox_events.
func (o *Outbox) Len() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return len(o.queue)
}

// Dropped is how many events the cap dropped since Open: the heartbeat's outbox_dropped ("since start"). An event the
// cap drops while its batch is on the way counts too, even if the hub then accepts that batch.
func (o *Outbox) Dropped() int64 {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.dropped
}

// built is an event ready to enter the outbox: its id and its exact bytes.
type built struct {
	id  string
	enc []byte
}

// commitLocked records, in one tx of the log, a change of the baseline (d, possibly nil) and the events evs entering
// the outbox — with the oldest events the cap drops —, and only once the tx is on disk (its fsync returned) moves the
// memory. An error means nothing changed: neither the baseline nor the outbox.
func (o *Outbox) commitLocked(d *delta, evs []built) error {
	if err := o.readyLocked(); err != nil {
		return err
	}
	n := len(evs)
	drop := max(0, len(o.queue)+n-o.capacity)
	dropOld := min(drop, len(o.queue))
	dropNew := drop - dropOld
	head := o.head
	if dropOld > 0 {
		head = o.queue[dropOld-1].seq
	}
	if dropNew > 0 {
		head = o.last + int64(dropNew)
	}
	rec := record{K: kindTx, Done: head}
	if !d.empty() {
		rec.Delta = d
	}
	var in []queued
	for i := dropNew; i < n; i++ {
		seq := o.last + int64(i+1)
		rec.Events = append(rec.Events, stored{Seq: seq, Event: evs[i].enc})
		in = append(in, queued{seq: seq, id: evs[i].id, enc: evs[i].enc})
	}
	line, err := encodeLine(rec)
	if err != nil {
		return err
	}
	if err := o.appendLocked(line); err != nil {
		return err
	}
	// on disk: the memory moves
	if rec.Delta != nil {
		o.base.apply(rec.Delta)
	}
	o.queue = append(o.queue[dropOld:], in...)
	o.head, o.last = head, o.last+int64(n)
	if drop > 0 {
		o.dropped += int64(drop)
		if !o.dropping {
			o.dropping = true
			o.log.Warn("eventos: outbox cheia; os eventos mais antigos estão sendo descartados (outbox_dropped)",
				"teto", o.capacity, "descartados", drop)
		}
	}
	o.maybeCompactLocked()
	return nil
}

// add builds the events of ps and commits them: an event that cannot be built (a value the schema would refuse) is an
// error and nothing is recorded.
func (o *Outbox) add(ps ...pending) error {
	evs := make([]built, 0, len(ps))
	for _, p := range ps {
		id := o.newID()
		_, enc, err := build(id, p)
		if err != nil {
			return err
		}
		evs = append(evs, built{id: id, enc: enc})
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if err := o.commitLocked(nil, evs); err != nil {
		return fmt.Errorf("events: evento não enfileirado: %w", err)
	}
	return nil
}

// Batch is one POST /fleet/v1/events: its body and the event_ids it carries. Only Next makes one.
type Batch struct {
	// Body is the body of the POST (fleet-event.schema.json): schema_version, node_id and the events, each byte for
	// byte as it entered the outbox.
	Body []byte
	// IDs are the event_ids of the batch, in order.
	IDs  []string
	last int64 // the seq of its last event
}

var reNodeID = regexp.MustCompile(contract.PatternNodeID)

// batchHeader is the body without its events, in the schema's member order.
type batchHeader struct {
	SchemaVersion string `json:"schema_version"`
	NodeID        string `json:"node_id"`
}

// Next returns the next batch for node nodeID: the oldest events of the outbox, in the order they entered it, at most
// contract.MaxEventsPerBatch (100) and a body of at most contract.MaxEventBatchBytes (1 MiB); ok is false when the
// outbox is empty. The events stay in the outbox until Delivered: calling Next again — after a failure, say — gives
// the same events first, with the same event_ids, which the hub deduplicates (delivery is at least once). An error
// means the file is not yet known to hold the outbox durably (a rewrite the boot or a failed write owes): nothing is
// handed out before it is.
func (o *Outbox) Next(nodeID string) (b Batch, ok bool, err error) {
	if !reNodeID.MatchString(nodeID) {
		return Batch{}, false, errors.New("events: node_id inválido para o lote")
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if err := o.readyLocked(); err != nil {
		return Batch{}, false, err
	}
	if len(o.queue) == 0 {
		return Batch{}, false, nil
	}
	head, err := contract.MarshalCompact(batchHeader{SchemaVersion: contract.SchemaVersion, NodeID: nodeID})
	if err != nil {
		return Batch{}, false, err
	}
	body := append(head[:len(head)-1:len(head)-1], `,"events":[`...)
	for i, q := range o.queue {
		add := len(q.enc)
		if i > 0 {
			add++ // the comma
		}
		if i == contract.MaxEventsPerBatch || len(body)+add+len("]}") > o.batchLimit {
			break
		}
		if i > 0 {
			body = append(body, ',')
		}
		body = append(body, q.enc...)
		b.IDs = append(b.IDs, q.id)
		b.last = q.seq
	}
	if len(b.IDs) == 0 { // unreachable: one event is at most maxEventBytes, far below the batch cap
		return Batch{}, false, errors.New("events: o evento mais antigo não cabe num lote")
	}
	b.Body = append(body, "]}"...)
	return b, true, nil
}

// Delivered records the hub's 2xx for b: its events leave the outbox. The memory moves at once — the hub has them,
// whatever the disk says —; an error says only that the file could not record it yet: until a later write does (every
// write carries the head of the outbox), a restart would send these events again, with the same event_ids, which the
// hub deduplicates. Events that the cap already dropped are simply gone.
func (o *Outbox) Delivered(b Batch) error {
	if b.last <= 0 {
		return errors.New("events: lote vazio")
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if b.last > o.last {
		return errors.New("events: lote que esta outbox não fez")
	}
	if b.last <= o.head {
		return nil
	}
	o.leaveLocked(b.last)
	if len(o.queue) < o.capacity {
		o.dropping = false
	}
	line, err := encodeLine(record{K: kindTx, Done: o.head})
	if err == nil {
		err = o.appendLocked(line)
	}
	if err != nil {
		return fmt.Errorf("events: lote entregue, mas o arquivo ainda não o registra: %w", err)
	}
	o.maybeCompactLocked()
	return nil
}
