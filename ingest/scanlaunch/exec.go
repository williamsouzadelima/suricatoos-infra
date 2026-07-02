package scanlaunch

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"time"
)

// Finding is one normalized OpenVAS result, as scan_bridge.py emits it and as
// the reNgine importer consumes it (schema/scan-request.schema.json's sibling
// response shape). Kept flat and stable so both sides stay in lockstep.
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

// bridgeResult is the union of fields scan_bridge.py prints (one JSON object on
// stdout) across its launch/status/fetch/stop subcommands.
type bridgeResult struct {
	TargetID string    `json:"target_id"`
	TaskID   string    `json:"task_id"`
	ReportID string    `json:"report_id"`
	Status   string    `json:"status"` // GVM: New/Requested/Queued/Running/Done/Stopped/Interrupted
	Progress int       `json:"progress"`
	Findings []Finding `json:"findings"`
	Stopped  bool      `json:"stopped"`
	Error    string    `json:"error"`
}

// bridgeRunner runs a scan_bridge.py subcommand. Injectable so the reconciler is
// testable without a Python process or a live gvmd.
type bridgeRunner func(ctx context.Context, subcommand string, req *Job) (*bridgeResult, error)

// execBridge is the production bridgeRunner: it writes the job (hosts/ports/
// scan_history_id/target) to a temp JSON file and execs scan_bridge.py with an
// arg vector (never a shell — attacker-influenced hosts/ports can't inject),
// passing SCAN_GVM_PASSWORD via the environment.
func execBridge(cfg Config) bridgeRunner {
	return func(ctx context.Context, subcommand string, req *Job) (*bridgeResult, error) {
		if cfg.BridgeScript == "" {
			return nil, fmt.Errorf("SCAN_BRIDGE_SCRIPT não configurado")
		}
		tmp, err := os.CreateTemp("", "suricatoos-scanreq-*.json")
		if err != nil {
			return nil, fmt.Errorf("temp file: %w", err)
		}
		defer os.Remove(tmp.Name())
		if err := json.NewEncoder(tmp).Encode(req); err != nil {
			tmp.Close()
			return nil, fmt.Errorf("encode request: %w", err)
		}
		tmp.Close()

		args := []string{
			cfg.BridgeScript, subcommand, tmp.Name(),
			"--socket", cfg.GmpSocket,
			"--username", cfg.GmpUsername,
			"--config-id", ConfigFullAndFast,
			"--scanner-id", ScannerOpenVASDefault,
			"--alive-test", cfg.AliveTest,
		}
		cctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
		defer cancel()

		var stdout, stderr bytes.Buffer
		cmd := exec.CommandContext(cctx, cfg.BridgePython, args...)
		cmd.Env = append(os.Environ(), "GVM_PASSWORD="+cfg.GmpPassword)
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			return nil, fmt.Errorf("scan_bridge.py %s: %w\n%s", subcommand, err, stderr.String())
		}
		var res bridgeResult
		if err := json.Unmarshal(bytes.TrimSpace(stdout.Bytes()), &res); err != nil {
			return nil, fmt.Errorf("scan_bridge.py %s: saída inválida: %w\nstdout=%s\nstderr=%s",
				subcommand, err, stdout.String(), stderr.String())
		}
		if res.Error != "" {
			return &res, fmt.Errorf("scan_bridge.py %s: %s", subcommand, res.Error)
		}
		return &res, nil
	}
}
