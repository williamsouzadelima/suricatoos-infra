package ingest

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
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
	}, nil
}

// Put correlates the inventory and, if findings are produced, imports them to
// gvmd. Errors are logged but never returned — the agent always gets 202.
func (s *PipelineSink) Put(inv Inventory) error {
	corrInv := toCorrelationInventory(inv)

	report, err := s.correlator.Correlate(corrInv)
	if err != nil {
		log.Printf("pipeline: correlate agent=%s: %v", inv.Agent.AgentID, err)
		return nil
	}
	log.Printf("pipeline: agent=%s host=%s findings=%d", inv.Agent.AgentID, inv.Agent.Hostname, len(report.Findings))

	if len(report.Findings) == 0 || s.bridgeScript == "" {
		return nil
	}

	if err := s.importToBridge(report); err != nil {
		log.Printf("pipeline: gmp-bridge agent=%s: %v", inv.Agent.AgentID, err)
	}
	return nil
}

// importToBridge writes the FindingReport to a temp file and calls bridge.py.
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
	ci := correlation.Inventory{
		SchemaVersion: inv.SchemaVersion,
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
