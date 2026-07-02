// Package supervisor is the sensor-agent's control loop (ADR-0007): poll the cloud
// for a scan job, run it locally (scope-gated) against the local gvmd, push the
// findings back, ack, and heartbeat — all outbound. It is interface-driven so the
// loop is testable without a network or a live gvmd.
package supervisor

import (
	"context"
	"encoding/json"
	"log"
	"time"

	"github.com/williamsouzadelima/suricatoos-infra/sensor/internal/cloud"
	"github.com/williamsouzadelima/suricatoos-infra/sensor/internal/scanrun"
)

// CloudClient is the subset of the cloud client the loop needs (injectable).
type CloudClient interface {
	PollJob(ctx context.Context) (*cloud.Job, bool, error)
	AckJob(ctx context.Context, jobID string) error
	PushReport(ctx context.Context, r cloud.Report) error
	Heartbeat(ctx context.Context, hb cloud.Heartbeat) error
}

// Scanner runs one scan job locally and returns the findings (injectable).
type Scanner interface {
	Run(ctx context.Context, job scanrun.Job) (findings []scanrun.Finding, dropped int, err error)
}

// Config tunes the loop cadence + sensor identity.
type Config struct {
	SensorID       string
	FeedVersion    func() string // current local feed version (for heartbeat/report)
	PollInterval   time.Duration // between polls when idle
	HeartbeatEvery time.Duration
	GvmdUp         func() bool // liveness probe of the local gvmd
}

// Supervisor ties the cloud client + scanner together.
type Supervisor struct {
	cfg     Config
	cloud   CloudClient
	scanner Scanner
	now     func() time.Time
}

// New builds a Supervisor.
func New(cfg Config, cl CloudClient, sc Scanner) *Supervisor {
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = 30 * time.Second
	}
	if cfg.HeartbeatEvery <= 0 {
		cfg.HeartbeatEvery = 60 * time.Second
	}
	if cfg.GvmdUp == nil {
		cfg.GvmdUp = func() bool { return true }
	}
	if cfg.FeedVersion == nil {
		cfg.FeedVersion = func() string { return "" }
	}
	return &Supervisor{cfg: cfg, cloud: cl, scanner: sc, now: time.Now}
}

// Run drives the loop until ctx is cancelled. Poll and heartbeat run on separate
// tickers; a poll that finds a job processes it inline (one scan at a time).
func (s *Supervisor) Run(ctx context.Context) {
	s.heartbeat(ctx) // announce presence immediately
	poll := time.NewTicker(s.cfg.PollInterval)
	beat := time.NewTicker(s.cfg.HeartbeatEvery)
	defer poll.Stop()
	defer beat.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-beat.C:
			s.heartbeat(ctx)
		case <-poll.C:
			s.pollOnce(ctx)
		}
	}
}

// pollOnce fetches at most one job and processes it. Exposed (unexported) for tests.
func (s *Supervisor) pollOnce(ctx context.Context) {
	job, ok, err := s.cloud.PollJob(ctx)
	if err != nil {
		log.Printf("supervisor: poll falhou: %v", err)
		return
	}
	if !ok {
		return
	}
	log.Printf("supervisor: job %s (corr=%s) — %d alvo(s)", job.JobID, job.CorrelationID, len(job.Targets))
	// Ack only AFTER the scan ran and the report was pushed. Acking on receipt made
	// a crash or a transient PushReport failure silently lose that tenant's findings
	// (the job was already terminal). Keeping the job DELIVERED-but-unacked lets the
	// cloud re-deliver it after its window; scanrun's find-or-create makes the re-run
	// idempotent, and this loop is single-goroutine so no concurrent poll runs during
	// the scan.
	if err := s.processJob(ctx, job); err != nil {
		log.Printf("supervisor: job %s não concluído — mantido p/ redelivery: %v", job.JobID, err)
		return
	}
	if err := s.cloud.AckJob(ctx, job.JobID); err != nil {
		log.Printf("supervisor: ack %s falhou: %v (será re-entregue; re-run é idempotente)", job.JobID, err)
	}
}

func (s *Supervisor) processJob(ctx context.Context, job *cloud.Job) error {
	findings, dropped, err := s.scanner.Run(ctx, scanrun.Job{
		CorrelationID: job.CorrelationID,
		Targets:       job.Targets,
		Ports:         job.Ports,
	})
	if err != nil {
		log.Printf("supervisor: scan corr=%s falhou: %v", job.CorrelationID, err)
		return err
	}
	if findings == nil {
		findings = []scanrun.Finding{}
	}
	raw, _ := json.Marshal(findings)
	rep := cloud.Report{
		SchemaVersion: "1.0.0",
		CorrelationID: job.CorrelationID,
		SensorID:      s.cfg.SensorID,
		FeedVersion:   s.cfg.FeedVersion(),
		CollectedAt:   s.now().UTC().Format(time.RFC3339),
		Findings:      raw,
	}
	if err := s.cloud.PushReport(ctx, rep); err != nil {
		log.Printf("supervisor: push report corr=%s falhou: %v", job.CorrelationID, err)
		return err
	}
	log.Printf("supervisor: corr=%s concluído (%d achado(s), %d fora-de-escopo)", job.CorrelationID, len(findings), dropped)
	return nil
}

func (s *Supervisor) heartbeat(ctx context.Context) {
	err := s.cloud.Heartbeat(ctx, cloud.Heartbeat{
		SensorID:    s.cfg.SensorID,
		FeedVersion: s.cfg.FeedVersion(),
		GvmdUp:      s.cfg.GvmdUp(),
	})
	if err != nil {
		log.Printf("supervisor: heartbeat falhou: %v", err)
	}
}
