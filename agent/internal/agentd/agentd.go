// Package agentd is the agent run loop: collect -> enqueue -> flush, with
// exponential backoff when the ingest plane is unreachable. The offline queue
// keeps unsent cycles across restarts (store-and-forward).
package agentd

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"time"

	"github.com/williamsouzadelima/suricatoos-infra/agent/internal/collect"
	"github.com/williamsouzadelima/suricatoos-infra/agent/internal/enroll"
	"github.com/williamsouzadelima/suricatoos-infra/agent/internal/inventory"
	"github.com/williamsouzadelima/suricatoos-infra/agent/internal/transport"
)

const (
	backoffBase = 5 * time.Second
	backoffMax  = 10 * time.Minute
)

// Config parameterizes the agent daemon.
type Config struct {
	StateDir  string        // identidade gravada pelo enroll
	QueueDir  string        // fila offline
	IngestURL string        // endpoint do ingest
	MaxQueue  int           // teto de itens na fila
	Interval  time.Duration // intervalo entre coletas
}

// Agent ties a collector, an offline queue and a sender into a loop.
type Agent struct {
	collector inventory.Collector
	queue     *transport.Queue
	sender    transport.Sender
	interval  time.Duration
	rnd       func() float64
}

// New builds an Agent from cfg: loads the enrolled identity, builds an mTLS
// sender pinned to the enrollment CA, opens the queue and selects the host
// collector.
func New(cfg Config) (*Agent, error) {
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
	return &Agent{
		collector: col,
		queue:     queue,
		sender:    transport.NewHTTPSender(client, cfg.IngestURL),
		interval:  cfg.Interval,
		rnd:       rand.Float64,
	}, nil
}

// tick runs one cycle: collect, enqueue, and flush the backlog. A collection
// error is non-fatal (the backlog is still flushed).
func (a *Agent) tick(ctx context.Context) (int, error) {
	if inv, err := a.collector.Collect(); err == nil {
		if b, err := json.Marshal(inv); err == nil {
			_ = a.queue.Enqueue(b)
		}
	}
	return a.queue.Flush(ctx, a.sender)
}

// Run loops tick until ctx is cancelled, backing off (exponential + jitter) when
// the ingest plane is unreachable and resetting on success.
func (a *Agent) Run(ctx context.Context) error {
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
