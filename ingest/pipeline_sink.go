package ingest

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"github.com/williamsouzadelima/suricatoos-infra/correlation"
)

// PipelineSink runs each inventory through the Notus correlation engine and,
// when bridge settings are configured, imports findings to gvmd via the
// gmp-bridge Python script. It never fails the HTTP 202 response to the agent:
// correlation and import errors are logged but not propagated.
type PipelineSink struct {
	correlator   correlation.Correlator
	bridgeScript string // path to gmp-bridge/bridge.py — empty = skip import
	bridgePython string // python3 binary (default "python3")
	gmpSocket    string // gvmd Unix socket
	gmpUsername  string
	gmpPassword  string
	taskName     string

	// Idempotency/concurrency guard. cycle_hash makes a re-delivered inventory a
	// no-op (the agent retries on a lost ack, and re-imports would otherwise
	// duplicate findings); inflight collapses concurrent deliveries of the same
	// cycle. Both are keyed by agent_id and protected by mu.
	mu        sync.Mutex
	lastCycle map[string]string // agent_id -> last successfully-processed cycle_hash
	inflight  map[string]bool   // agent_id\x00cycle_hash currently being processed
}

// PipelineConfig configures a PipelineSink.
type PipelineConfig struct {
	NotusDir     string // path to directory of *.notus advisory files (required)
	BridgeScript string // path to bridge.py (optional; skips GMP import if empty)
	BridgePython string // python3 binary (default: "python3")
	GmpSocket    string // gvmd socket (default: /run/gvmd/gvmd.sock)
	GmpUsername  string // gvmd username (default: "admin")
	GmpPassword  string // gvmd password
	TaskName     string // container task name in GMP (default: "suricatoos-import")
}

// NewPipelineSink creates a PipelineSink by loading Notus advisories from cfg.NotusDir.
func NewPipelineSink(cfg PipelineConfig) (*PipelineSink, error) {
	corr, err := correlation.NewNotusCorrelator(cfg.NotusDir)
	if err != nil {
		return nil, fmt.Errorf("carregar advisories Notus de %s: %w", cfg.NotusDir, err)
	}
	// Surface advisories whose product_name we cannot map to a distro family:
	// they will never match any host, so an operator must extend
	// correlation.canonicalDistro rather than silently lose those findings.
	if unclassified := corr.UnclassifiedProducts(); len(unclassified) > 0 {
		log.Printf("pipeline: AVISO — %d produto(s) de advisory sem distro reconhecida (não casarão com nenhum host): %v",
			len(unclassified), unclassified)
	}

	python := cfg.BridgePython
	if python == "" {
		python = "python3"
	}
	socket := cfg.GmpSocket
	if socket == "" {
		socket = "/run/gvmd/gvmd.sock"
	}
	username := cfg.GmpUsername
	if username == "" {
		username = "admin"
	}
	taskName := cfg.TaskName
	if taskName == "" {
		taskName = "suricatoos-import"
	}

	return &PipelineSink{
		correlator:   corr,
		bridgeScript: cfg.BridgeScript,
		bridgePython: python,
		gmpSocket:    socket,
		gmpUsername:  username,
		gmpPassword:  cfg.GmpPassword,
		taskName:     taskName,
		lastCycle:    make(map[string]string),
		inflight:     make(map[string]bool),
	}, nil
}

// beginCycle returns true if (agentID, cycleHash) should be processed now. It
// returns false — and processes nothing — when the same cycle was already
// completed (a retried/unchanged report) or is currently in flight (a concurrent
// duplicate). A non-empty cycleHash is required to dedupe; empty always proceeds.
func (s *PipelineSink) beginCycle(agentID, cycleHash string) bool {
	if cycleHash == "" {
		return true
	}
	key := agentID + "\x00" + cycleHash
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lastCycle[agentID] == cycleHash || s.inflight[key] {
		return false
	}
	s.inflight[key] = true
	return true
}

// endCycle clears the in-flight mark and, on success, records the cycle as the
// agent's last-processed so future identical deliveries are skipped.
func (s *PipelineSink) endCycle(agentID, cycleHash string, ok bool) {
	if cycleHash == "" {
		return
	}
	key := agentID + "\x00" + cycleHash
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.inflight, key)
	if ok {
		s.lastCycle[agentID] = cycleHash
	}
}

// Put correlates the inventory and, if findings are produced, imports them to
// gvmd. Errors are logged but never returned — the agent always gets 202.
func (s *PipelineSink) Put(inv Inventory) error {
	ok := false
	// An on-demand scan (Force) always imports a fresh report — even if the
	// inventory is unchanged — so the operator's "scan now" produces a visible,
	// timestamped result. It does NOT touch the dedup state, so the periodic
	// 15-minute cycles keep deduping normally.
	if inv.Force {
		log.Printf("pipeline: agent=%s scan sob demanda (force) — importando", inv.Agent.AgentID)
	} else {
		// Skip re-delivered or concurrently-duplicated cycles: the agent retries when
		// an ack is lost, and re-running the bridge would duplicate the gvmd report.
		// Unchanged inventories (same cycle_hash) are also skipped, avoiding a bridge
		// subprocess + GMP round-trips on every 15-minute check-in.
		if !s.beginCycle(inv.Agent.AgentID, inv.CycleHash) {
			log.Printf("pipeline: agent=%s cycle inalterado/duplicado — skip", inv.Agent.AgentID)
			return nil
		}
		defer func() { s.endCycle(inv.Agent.AgentID, inv.CycleHash, ok) }()
	}

	corrInv := toCorrelationInventory(inv)

	report, err := s.correlator.Correlate(corrInv)
	if err != nil {
		log.Printf("pipeline: correlate agent=%s: %v", inv.Agent.AgentID, err)
		return nil // ok stays false → a retry of this cycle will reprocess
	}
	log.Printf("pipeline: agent=%s host=%s findings=%d", inv.Agent.AgentID, inv.Agent.Hostname, len(report.Findings))

	if s.bridgeScript == "" {
		ok = true
		return nil
	}

	// Import the precise Notus findings into the agent's per-agent container task
	// (find-or-create, idempotent). gvmd's CVE scanner can't drive a passive agent
	// on-demand, so Notus — distro-aware, accurate — is the per-agent signal; the
	// "scan now" refresh is handled by the agent command channel, not gvmd play.
	if err := s.importToBridge(report); err != nil {
		log.Printf("pipeline: gmp-bridge agent=%s: %v", inv.Agent.AgentID, err)
		return nil // ok stays false → a retry of this cycle reprocesses
	}
	ok = true
	return nil
}

// importToBridge writes the FindingReport to a temp file and calls bridge.py,
// which imports the Notus findings into the agent's per-agent container task.
func (s *PipelineSink) importToBridge(report *correlation.FindingReport) error {
	tmp, err := os.CreateTemp("", "suricatoos-report-*.json")
	if err != nil {
		return fmt.Errorf("criar arquivo temporário: %w", err)
	}
	defer os.Remove(tmp.Name())

	if err := json.NewEncoder(tmp).Encode(report); err != nil {
		tmp.Close()
		return fmt.Errorf("serializar relatório: %w", err)
	}
	tmp.Close()

	args := []string{
		s.bridgeScript,
		"--socket", s.gmpSocket,
		"--username", s.gmpUsername,
		"--task-name", fmt.Sprintf("%s-%s", s.taskName, report.AgentID),
		tmp.Name(),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, s.bridgePython, args...)
	cmd.Env = append(os.Environ(), "GVM_PASSWORD="+s.gmpPassword)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("bridge.py: %w\n%s", err, out)
	}
	log.Printf("pipeline: gmp-bridge ok — %s", filepath.Base(tmp.Name()))
	return nil
}

// toCorrelationInventory converts an ingest Inventory to the type the
// correlation engine expects. Packages are re-decoded from their raw JSON form.
func toCorrelationInventory(inv Inventory) correlation.Inventory {
	// Parse collected_at leniently: a malformed value must not reject the
	// inventory (the agent's report is still useful), and a zero result is floored
	// to a valid timestamp downstream in the bridge (valid_scan_time).
	collectedAt, _ := time.Parse(time.RFC3339, inv.CollectedAt)
	ci := correlation.Inventory{
		SchemaVersion: inv.SchemaVersion,
		CollectedAt:   collectedAt, // propagate so the gvmd report gets a real timestamp
		Agent: correlation.AgentInfo{
			AgentID:  inv.Agent.AgentID,
			Hostname: inv.Agent.Hostname,
		},
		OS: correlation.OSInfo{
			Family:  inv.OS.Family,
			Distro:  inv.OS.Distro,
			Release: inv.OS.Release,
		},
	}
	for _, raw := range inv.Packages {
		var p correlation.Package
		if err := json.Unmarshal(raw, &p); err == nil {
			ci.Packages = append(ci.Packages, p)
		}
	}
	return ci
}
