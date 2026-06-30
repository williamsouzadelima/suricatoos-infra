// Package agentd is the agent run loop: collect -> enqueue -> flush, with
// exponential backoff when the ingest plane is unreachable. The offline queue
// keeps unsent cycles across restarts (store-and-forward). It also runs a
// periodic, signed auto-update check against the control plane, with a
// stability-gated commit and crash-loop rollback.
package agentd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/williamsouzadelima/suricatoos-infra/agent/internal/collect"
	"github.com/williamsouzadelima/suricatoos-infra/agent/internal/command"
	"github.com/williamsouzadelima/suricatoos-infra/agent/internal/enroll"
	"github.com/williamsouzadelima/suricatoos-infra/agent/internal/inventory"
	"github.com/williamsouzadelima/suricatoos-infra/agent/internal/transport"
	"github.com/williamsouzadelima/suricatoos-infra/agent/internal/update"
)

const (
	backoffBase = 5 * time.Second
	backoffMax  = 10 * time.Minute
	// commitWindow is how long the swapped binary must run without crashing before
	// the staged update is committed (backup dropped). A crash inside this window
	// leaves the stage marker so BeginBoot's counter trips rollback.
	commitWindow = 2 * time.Minute
)

// ErrRolledBack signals that New detected a crash-looping staged update and rolled
// back to the previous binary; the service restart is imminent and the caller
// should exit cleanly rather than treat this as a fatal startup error.
var ErrRolledBack = errors.New("update: rolled back to previous version, restarting")

// Config parameterizes the agent daemon.
type Config struct {
	StateDir  string        // identidade gravada pelo enroll
	QueueDir  string        // fila offline
	IngestURL string        // endpoint do ingest
	MaxQueue  int           // teto de itens na fila
	Interval  time.Duration // intervalo entre coletas

	// Auto-update (optional). Enabled when UpdateInterval > 0 and the enrolled
	// identity carries a control-plane ServerURL.
	UpdateInterval time.Duration // intervalo entre checagens de update (0 = desligado)
	CurrentVersion string        // versão deste binário (version.Version)
	BinaryPath     string        // caminho do binário a substituir (os.Executable)
	Restart        func() error  // como reiniciar o serviço após a troca

	// CommandInterval is how often the agent polls the control-plane for a pending
	// command (e.g. "scan_now" → an immediate re-collect). Enabled when > 0 and the
	// enrolled identity carries a ServerURL. 0 = disabled.
	CommandInterval time.Duration
}

// Agent ties a collector, an offline queue and a sender into a loop, plus an
// optional auto-updater.
type Agent struct {
	collector inventory.Collector
	queue     *transport.Queue
	sender    transport.Sender
	interval  time.Duration
	rnd       func() float64

	// tickMu serializes tick() so the main Run loop and commandLoop (scan_now)
	// never flush the offline queue concurrently — Queue.Flush assumes a single
	// flusher (it releases its lock during Send, so two concurrent flushers would
	// re-POST the same backlog items). An on-demand scan_now waits for any
	// in-flight tick, then runs a fresh collect+flush.
	tickMu sync.Mutex

	updateInterval time.Duration
	currentVersion string
	stateDir       string
	doUpdate       func(context.Context) bool // nil quando desligado; retorna true se aplicou (parar o loop)

	// agentID é a identidade lógica enrolada (CN do certificado). Sobrescreve o
	// agent_id do inventário (que o coletor preenche com o hostname do SO) para
	// que --agent-id no enroll seja o nome reportado/correlacionado, independente
	// do hostname da máquina. Vazio = mantém o hostname.
	agentID string

	// Command channel (optional). When commandInterval > 0 the agent polls
	// serverURL+"/commands" over cmdClient (its mTLS client) and runs a verified
	// "scan_now" by forcing an immediate tick().
	commandInterval time.Duration
	cmdClient       *http.Client
	serverURL       string
}

// New builds an Agent from cfg: loads the enrolled identity, builds an mTLS
// sender pinned to the enrollment CA, opens the queue and selects the host
// collector. When auto-update is enabled it wires a signed update checker.
func New(cfg Config) (*Agent, error) {
	// Crash-loop guard: if a previously-staged update keeps failing to reach a
	// healthy run, BeginBoot rolls back to the backed-up binary and restarts.
	if cfg.UpdateInterval > 0 && cfg.BinaryPath != "" && cfg.Restart != nil {
		if rolledBack, _ := update.BeginBoot(cfg.StateDir, cfg.CurrentVersion, cfg.Restart); rolledBack {
			return nil, ErrRolledBack
		}
	}

	id, err := enroll.Load(cfg.StateDir)
	if err != nil {
		return nil, fmt.Errorf("identidade não encontrada (rode `enroll` primeiro): %w", err)
	}
	tlsCfg, err := id.TLSClientConfig()
	if err != nil {
		return nil, err
	}
	client := &http.Client{Timeout: 60 * time.Second, Transport: &http.Transport{TLSClientConfig: tlsCfg}}
	queue, err := transport.NewQueue(cfg.QueueDir, cfg.MaxQueue)
	if err != nil {
		return nil, err
	}
	col, err := collect.New()
	if err != nil {
		return nil, err
	}
	a := &Agent{
		collector:      col,
		queue:          queue,
		sender:         transport.NewHTTPSender(client, cfg.IngestURL),
		interval:       cfg.Interval,
		rnd:            rand.Float64,
		currentVersion: cfg.CurrentVersion,
		stateDir:       cfg.StateDir,
		agentID:        id.AgentID(),
	}
	// Command channel: poll over the same mTLS client used for ingest. Needs the
	// control-plane ServerURL (persisted at enroll); pre-update enrollments lack it.
	if cfg.CommandInterval > 0 && id.ServerURL != "" {
		a.commandInterval = cfg.CommandInterval
		a.cmdClient = client
		a.serverURL = id.ServerURL
	}
	if u := buildUpdater(cfg, id); u != nil {
		a.updateInterval = cfg.UpdateInterval
		a.doUpdate = u
	}
	return a, nil
}

// buildUpdater returns the periodic update closure, or nil when auto-update is
// disabled. The closure verifies the signed manifest, enforces the version policy
// (floor + quarantine), smoke-tests the binary, and applies it. It returns true
// once an apply has been ATTEMPTED so the loop stops (the process is restarting,
// or restart failed and re-applying would churn).
func buildUpdater(cfg Config, id *enroll.Identity) func(context.Context) bool {
	if cfg.UpdateInterval <= 0 || id.ServerURL == "" {
		return nil
	}
	caPub, err := id.CAPublicKey()
	if err != nil {
		log.Printf("auto-update desligado: %v", err)
		return nil
	}
	if cfg.BinaryPath == "" {
		log.Printf("auto-update desligado: caminho do binário desconhecido")
		return nil
	}
	server, version, state, binPath, restart := id.ServerURL, cfg.CurrentVersion, cfg.StateDir, cfg.BinaryPath, cfg.Restart
	hc := &http.Client{Timeout: 10 * time.Minute}
	return func(ctx context.Context) bool {
		checkCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		target, err := update.Check(checkCtx, hc, server, version, runtime.GOOS, runtime.GOARCH, caPub, time.Now())
		cancel()
		if err != nil {
			log.Printf("update check: %v", err)
			return false
		}
		if target == nil {
			return false // up to date
		}
		if ok, reason := update.Allowed(state, target.Version); !ok {
			log.Printf("update %s ignorado: %s", target.Version, reason)
			return false
		}
		log.Printf("update disponível: %s -> %s; baixando", version, target.Version)
		tmp, err := update.Download(ctx, hc, *target, filepath.Dir(binPath))
		if err != nil {
			log.Printf("update download: %v", err)
			return false
		}
		log.Printf("update verificado (sha256 ok); validando e aplicando %s", target.Version)
		if err := update.Apply(*target, tmp, binPath, state, version, restart, time.Now()); err != nil {
			log.Printf("update apply: %v", err)
		}
		// Whether restart succeeded (process about to die) or failed, do not loop
		// back and re-apply — stop here.
		return true
	}
}

// tick runs one cycle: collect, enqueue, and flush the backlog. A collection
// error is non-fatal (the backlog is still flushed).
func (a *Agent) tick(ctx context.Context) (int, error) {
	a.tickMu.Lock()
	defer a.tickMu.Unlock()
	if inv, err := a.collector.Collect(); err == nil {
		if a.agentID != "" {
			inv.Agent.AgentID = a.agentID // identidade lógica enrolada > hostname do SO
		}
		if b, err := json.Marshal(inv); err == nil {
			_ = a.queue.Enqueue(b)
		}
	}
	return a.queue.Flush(ctx, a.sender)
}

// Run loops tick until ctx is cancelled, backing off (exponential + jitter) when
// the ingest plane is unreachable and resetting on success. When auto-update is
// enabled it (a) commits a staged update after a stability window and (b) checks
// for new updates on a fixed cadence.
func (a *Agent) Run(ctx context.Context) error {
	if a.doUpdate != nil {
		go a.commitAfterStable(ctx)
		go a.updateLoop(ctx)
	}
	if a.commandInterval > 0 && a.cmdClient != nil {
		go a.commandLoop(ctx)
	}
	attempt := 0
	for {
		if _, err := a.tick(ctx); err != nil {
			attempt++
		} else {
			attempt = 0
		}
		wait := a.interval
		if attempt > 0 {
			wait = transport.Backoff(attempt, backoffBase, backoffMax, a.rnd)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
	}
}

// commitAfterStable commits a staged update once the process has run for
// commitWindow without crashing — proving real runtime liveness, not merely that
// the constructor returned. A crash before then leaves the stage armed for rollback.
func (a *Agent) commitAfterStable(ctx context.Context) {
	select {
	case <-ctx.Done():
		return
	case <-time.After(commitWindow):
	}
	if ok, _ := update.CommitIfHealthy(a.stateDir, a.currentVersion); ok {
		log.Printf("update: versão %s confirmada (estável por %s)", a.currentVersion, commitWindow)
	}
}

// commandLoop polls the control-plane for a pending command on a fixed cadence
// and runs a "scan_now" by forcing an immediate collect+report tick, then acks
// it. Poll/ack errors are logged and retried on the next tick (transient by
// nature). The agent always initiates, so no inbound listener is introduced.
func (a *Agent) commandLoop(ctx context.Context) {
	t := time.NewTicker(a.commandInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		pollCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		cmd, err := command.Poll(pollCtx, a.cmdClient, a.serverURL)
		cancel()
		if err != nil {
			log.Printf("command poll: %v", err)
			continue
		}
		if cmd == nil {
			continue
		}
		switch cmd.Type {
		case command.ScanNow:
			log.Printf("comando scan_now (%s): coletando e reportando agora", cmd.ID)
			if _, err := a.tick(ctx); err != nil {
				log.Printf("command scan_now tick: %v", err)
			}
		default:
			log.Printf("comando desconhecido ignorado: %q", cmd.Type)
		}
		ackCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		if err := command.Ack(ackCtx, a.cmdClient, a.serverURL, cmd.ID); err != nil {
			log.Printf("command ack %s: %v", cmd.ID, err)
		}
		cancel()
	}
}

// updateLoop checks for updates on a fixed cadence (with an initial short delay so
// a freshly-restarted agent doesn't immediately re-update). It stops after the
// first apply attempt — the process is restarting, or restart failed and looping
// would only churn.
func (a *Agent) updateLoop(ctx context.Context) {
	select {
	case <-ctx.Done():
		return
	case <-time.After(time.Minute):
	}
	if a.doUpdate(ctx) {
		return
	}
	t := time.NewTicker(a.updateInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if a.doUpdate(ctx) {
				return
			}
		}
	}
}
