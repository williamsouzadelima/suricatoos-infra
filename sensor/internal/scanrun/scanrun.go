// Package scanrun runs a scoped OpenVAS scan on the sensor's LOCAL gvmd by driving
// gmp-bridge/scan_bridge.py (ADR-0007). It is invoked IN-PROCESS by the sensor
// supervisor (never over a network/loopback listener), applies the baked scope
// allowlist to every target before anything reaches gvmd, and returns the raw
// findings for the sensor to push to the cloud (where severity/CVE are re-attested).
package scanrun

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"time"

	"github.com/williamsouzadelima/suricatoos-infra/sensor/internal/scope"
)

// Finding is one normalized OpenVAS result from scan_bridge.py (same shape the
// cloud's sensor-report endpoint consumes; severity/CVE here are advisory — the
// cloud re-attests them from the central feed by OID).
type Finding struct {
	Host       string   `json:"host"`
	Port       string   `json:"port"`
	OID        string   `json:"oid"`
	Name       string   `json:"name"`
	CVSSBase   float64  `json:"cvss_base"`
	CVSSVector string   `json:"cvss_vector"`
	Threat     string   `json:"threat"`
	CVEs       []string `json:"cves"`
	References []string `json:"references"`
	Summary    string   `json:"summary"`
	Impact     string   `json:"impact"`
	Solution   string   `json:"solution"`
	QOD        int      `json:"qod"`
}

// Config configures the local scan runner.
type Config struct {
	BridgeScript string // path to scan_bridge.py
	BridgePython string // python3
	GmpSocket    string // LOCAL gvmd socket
	GmpUser      string // LOCAL gvmd user (per-sensor, generated at install — not shared)
	GmpPassword  string
	ScanConfig   string // GVM scan config UUID (default Full-and-fast)
	ScannerID    string // GVM scanner UUID (default OpenVAS Default)
	AliveTest    string
	TaskPrefix   string // default "suricatoos-sensor"
	PollInterval time.Duration
	MaxDuration  time.Duration
	Scope        *scope.Scope // baked authorization
}

// Job is one scan to run (from the cloud dispatch).
type Job struct {
	CorrelationID string
	Targets       []string
	Ports         string // GVM port_range (e.g. T:1-65535)
}

// bridgeResult is the union of scan_bridge.py's stdout fields.
type bridgeResult struct {
	TargetID string    `json:"target_id"`
	TaskID   string    `json:"task_id"`
	ReportID string    `json:"report_id"`
	Status   string    `json:"status"`
	Progress int       `json:"progress"`
	Findings []Finding `json:"findings"`
	Error    string    `json:"error"`
}

type bridgeExec func(ctx context.Context, subcommand string, reqJSON []byte) (*bridgeResult, error)

// Runner drives one scan to completion.
type Runner struct {
	cfg   Config
	run   bridgeExec
	now   func() time.Time
	sleep func(time.Duration)
}

// New builds a Runner. Defaults are applied for the GVM ids/prefix/timings.
func New(cfg Config) *Runner {
	if cfg.ScanConfig == "" {
		cfg.ScanConfig = "daba56c8-73ec-11df-a475-002264764cea" // Full and fast
	}
	if cfg.ScannerID == "" {
		cfg.ScannerID = "08b69003-5fc2-4037-a479-93b440211c73" // OpenVAS Default
	}
	if cfg.TaskPrefix == "" {
		cfg.TaskPrefix = "suricatoos-sensor"
	}
	if cfg.AliveTest == "" {
		cfg.AliveTest = "Consider Alive"
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = 30 * time.Second
	}
	if cfg.MaxDuration <= 0 {
		cfg.MaxDuration = 6 * time.Hour
	}
	r := &Runner{cfg: cfg, now: time.Now, sleep: time.Sleep}
	r.run = r.execBridge
	return r
}

// Run applies the baked scope, launches the scan, polls to completion, and returns
// the findings. droppedCount is how many targets were rejected by the scope (log
// it). Returns (nil, dropped, nil) when nothing is in scope.
func (r *Runner) Run(ctx context.Context, job Job) (findings []Finding, droppedCount int, err error) {
	kept, dropped := r.cfg.Scope.Filter(job.Targets)
	if len(dropped) > 0 {
		log.Printf("scanrun: corr=%s %d alvo(s) fora do escopo dropados: %v", job.CorrelationID, len(dropped), dropped)
	}
	if len(kept) == 0 {
		return nil, len(dropped), nil
	}
	ports := job.Ports
	if ports == "" {
		ports = "T:1-65535"
	}
	reqJSON, _ := json.Marshal(map[string]any{
		"scan_id": job.CorrelationID,
		"targets": kept,
		"ports":   ports,
	})

	if _, err := r.run(ctx, "launch", reqJSON); err != nil {
		return nil, len(dropped), fmt.Errorf("launch: %w", err)
	}
	deadline := r.now().Add(r.cfg.MaxDuration)
	for {
		res, err := r.run(ctx, "status", reqJSON)
		if err != nil {
			return nil, len(dropped), fmt.Errorf("status: %w", err)
		}
		switch res.Status {
		case "Done":
			fr, err := r.run(ctx, "fetch", reqJSON)
			if err != nil {
				return nil, len(dropped), fmt.Errorf("fetch: %w", err)
			}
			return fr.Findings, len(dropped), nil
		case "Stopped", "Interrupted", "Failed":
			return nil, len(dropped), fmt.Errorf("scan terminou como %s", res.Status)
		}
		if r.now().After(deadline) {
			r.run(ctx, "stop", reqJSON) // best effort
			return nil, len(dropped), fmt.Errorf("scan excedeu MaxDuration (%s)", r.cfg.MaxDuration)
		}
		if err := sleepCtx(ctx, r.sleep, r.cfg.PollInterval); err != nil {
			return nil, len(dropped), err
		}
	}
}

func sleepCtx(ctx context.Context, sleep func(time.Duration), d time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	sleep(d)
	return ctx.Err()
}

// execBridge is the production bridgeExec: temp-JSON + arg-vector exec of
// scan_bridge.py (never a shell), GVM_PASSWORD via env.
func (r *Runner) execBridge(ctx context.Context, subcommand string, reqJSON []byte) (*bridgeResult, error) {
	if r.cfg.BridgeScript == "" {
		return nil, fmt.Errorf("BridgeScript não configurado")
	}
	tmp, err := os.CreateTemp("", "suricatoos-sensor-job-*.json")
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(reqJSON); err != nil {
		tmp.Close()
		return nil, err
	}
	tmp.Close()

	python := r.cfg.BridgePython
	if python == "" {
		python = "python3"
	}
	args := []string{
		r.cfg.BridgeScript, subcommand, tmp.Name(),
		"--socket", r.cfg.GmpSocket,
		"--username", r.cfg.GmpUser,
		"--config-id", r.cfg.ScanConfig,
		"--scanner-id", r.cfg.ScannerID,
		"--alive-test", r.cfg.AliveTest,
		"--task-prefix", r.cfg.TaskPrefix,
	}
	cctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(cctx, python, args...)
	cmd.Env = append(os.Environ(), "GVM_PASSWORD="+r.cfg.GmpPassword)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("scan_bridge.py %s: %w\n%s", subcommand, err, stderr.String())
	}
	var res bridgeResult
	if err := json.Unmarshal(bytes.TrimSpace(stdout.Bytes()), &res); err != nil {
		return nil, fmt.Errorf("scan_bridge.py %s: saída inválida: %w", subcommand, err)
	}
	if res.Error != "" {
		return &res, fmt.Errorf("scan_bridge.py %s: %s", subcommand, res.Error)
	}
	return &res, nil
}
