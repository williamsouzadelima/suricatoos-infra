// Command sensor-agent is the Suricatoos internal scanner sensor supervisor
// (ADR-0007). On first boot it enrolls to the cloud (exchanging a bootstrap token
// for an mTLS cert whose O=tenant is assigned by the token), then loops: poll the
// cloud for a scan job, run it locally scope-gated against the local gvmd, push the
// findings, and heartbeat. Every cloud call is OUTBOUND — the sensor never listens.
//
// Configuration (environment):
//
//	SENSOR_ID              stable sensor id = cert CN (default: sensor-<hostname>)
//	SENSOR_STATE_DIR       where enrolled cert/key/ca live (default: /var/lib/suricatoos-sensor)
//	ENROLL_TOKEN           bootstrap token (tenant + policy=scanner-sensor); only needed until enrolled
//	CLOUD_BASE_URL         e.g. https://scanner.suricatoos.com  (derives the /agent + /ingest URLs)
//	SCAN_SCOPE             the sensor's baked authorized CIDRs (must match the tenant's cloud scope)
//	SCAN_SELF_DENY_IPS     the sensor's own IPs + cloud endpoints — never scan targets
//	GMP_SOCKET             local gvmd socket (default: /run/gvmd/gvmd.sock)
//	SENSOR_GMP_USER        local gvmd user (per-sensor, generated at install)
//	SENSOR_GVM_PASSWORD    local gvmd password
//	SCAN_BRIDGE_SCRIPT     path to scan_bridge.py
//	POLL_INTERVAL          idle poll cadence (default 30s)
//	HEARTBEAT_INTERVAL     heartbeat cadence (default 60s)
package main

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/williamsouzadelima/suricatoos-infra/sensor/internal/cloud"
	"github.com/williamsouzadelima/suricatoos-infra/sensor/internal/enroll"
	"github.com/williamsouzadelima/suricatoos-infra/sensor/internal/feedsync"
	"github.com/williamsouzadelima/suricatoos-infra/sensor/internal/scanrun"
	"github.com/williamsouzadelima/suricatoos-infra/sensor/internal/scope"
	"github.com/williamsouzadelima/suricatoos-infra/sensor/internal/supervisor"
)

func main() {
	stateDir := envOr("SENSOR_STATE_DIR", "/var/lib/suricatoos-sensor")
	sensorID := envOr("SENSOR_ID", "sensor-"+hostname())
	base := strings.TrimRight(os.Getenv("CLOUD_BASE_URL"), "/")
	if base == "" {
		log.Fatal("CLOUD_BASE_URL obrigatório")
	}
	certFile := filepath.Join(stateDir, "sensor.crt")
	keyFile := filepath.Join(stateDir, "sensor.key")
	caFile := filepath.Join(stateDir, "ca.crt")

	// One-time enroll: if the cert isn't on disk, exchange the bootstrap token.
	if !fileExists(certFile) {
		if err := doEnroll(base, sensorID, certFile, keyFile, caFile, stateDir); err != nil {
			log.Fatalf("enroll: %v", err)
		}
	}

	// Baked scope: the sensor independently re-validates every target.
	sc, err := scope.New(os.Getenv("SCAN_SCOPE"), os.Getenv("SCAN_SELF_DENY_IPS"))
	if err != nil {
		log.Fatalf("scope: %v", err)
	}
	if sc.Empty() {
		log.Printf("AVISO: SCAN_SCOPE vazio — o sensor não escaneará nada até ser configurado")
	}

	runner := scanrun.New(scanrun.Config{
		BridgeScript: os.Getenv("SCAN_BRIDGE_SCRIPT"),
		BridgePython: envOr("BRIDGE_PYTHON", "python3"),
		GmpSocket:    envOr("GMP_SOCKET", "/run/gvmd/gvmd.sock"),
		GmpUser:      envOr("SENSOR_GMP_USER", "suricatoos-scan"),
		GmpPassword:  os.Getenv("SENSOR_GVM_PASSWORD"),
		Scope:        sc,
	})

	cl, err := cloud.New(cloud.Config{
		JobsURL:      base + "/agent/v1/scan-jobs",
		ReportURL:    base + "/ingest/v1/sensor-report",
		HeartbeatURL: base + "/agent/v1/heartbeat",
		CertFile:     certFile, KeyFile: keyFile, CAFile: caFile,
	})
	if err != nil {
		log.Fatalf("cloud client: %v", err)
	}

	sup := supervisor.New(supervisor.Config{
		SensorID:       sensorID,
		PollInterval:   envDur("POLL_INTERVAL", 30*time.Second),
		HeartbeatEvery: envDur("HEARTBEAT_INTERVAL", 60*time.Second),
		FeedVersion:    func() string { return readFeedVersion(stateDir) },
	}, cl, scannerAdapter{runner})

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Feed sync (ADR-0007): keep the LOCAL GVM feed current from the cloud mirror.
	// The snapshot is baked at install, so this pulls only deltas. Verified against
	// the CA pubkey the sensor pinned at enroll.
	startFeedSync(ctx, base, caFile, stateDir)

	log.Printf("sensor-agent %s iniciado (cloud=%s)", sensorID, base)
	sup.Run(ctx)
	log.Printf("sensor-agent encerrando")
}

// startFeedSync launches a background loop that keeps the local feed in sync. A
// failed sync is logged and retried next tick — the sensor keeps serving the feed
// it already has. Disabled if SENSOR_FEED_DIR is unset.
func startFeedSync(ctx context.Context, base, caFile, stateDir string) {
	feedDir := os.Getenv("SENSOR_FEED_DIR")
	if feedDir == "" {
		log.Printf("feedsync: desabilitado — defina SENSOR_FEED_DIR para habilitar")
		return
	}
	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		log.Printf("feedsync: não consegui ler o ca.crt (%v) — sync desabilitado", err)
		return
	}
	verifyKey, err := feedsync.VerifyKeyFromCACert(caPEM)
	if err != nil {
		log.Printf("feedsync: pubkey de verificação indisponível (%v) — sync desabilitado", err)
		return
	}
	syncer := feedsync.New(feedsync.Config{
		ManifestURL: base + "/agent/v1/feed/manifest",
		BlobURLBase: base + "/agent/v1/feed/blob",
		FeedDir:     feedDir,
		VerifyKey:   verifyKey,
	})
	interval := envDur("FEED_SYNC_INTERVAL", 30*time.Minute)
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		runFeedSync(ctx, syncer)
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				runFeedSync(ctx, syncer)
			}
		}
	}()
}

func runFeedSync(ctx context.Context, syncer *feedsync.Syncer) {
	res, err := syncer.Sync(ctx)
	if err != nil {
		log.Printf("feedsync: falhou: %v", err)
		return
	}
	log.Printf("feedsync: ok (feed=%s, baixados=%d, já-locais=%d, total=%d)",
		res.FeedVersion, res.Downloaded, res.AlreadyLocal, res.TotalFiles)
}

// scannerAdapter adapts *scanrun.Runner to the supervisor.Scanner interface.
type scannerAdapter struct{ r *scanrun.Runner }

func (a scannerAdapter) Run(ctx context.Context, job scanrun.Job) ([]scanrun.Finding, int, error) {
	return a.r.Run(ctx, job)
}

func doEnroll(base, sensorID, certFile, keyFile, caFile, stateDir string) error {
	token := os.Getenv("ENROLL_TOKEN")
	if token == "" {
		return errNoToken
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	res, err := enroll.Enroll(ctx, enroll.Config{
		EnrollURL: base + "/agent/v1/enroll",
		Token:     token,
		AgentID:   sensorID,
		OS:        "linux",
		Arch:      "amd64",
	})
	if err != nil {
		return err
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return err
	}
	if err := writeFile(certFile, res.CertPEM, 0o644); err != nil {
		return err
	}
	if err := writeFile(keyFile, res.KeyPEM, 0o600); err != nil {
		return err
	}
	if err := writeFile(caFile, res.CACertPEM, 0o644); err != nil {
		return err
	}
	log.Printf("enroll: %s enrolado (cert em %s)", sensorID, certFile)
	return nil
}

var errNoToken = errString("ENROLL_TOKEN obrigatório no primeiro boot (sensor não enrolado)")

type errString string

func (e errString) Error() string { return string(e) }

func readFeedVersion(stateDir string) string {
	b, err := os.ReadFile(filepath.Join(stateDir, "feed", "version.json"))
	if err != nil {
		return ""
	}
	var v struct {
		FeedVersion string `json:"feed_version"`
	}
	if json.Unmarshal(b, &v) != nil {
		return ""
	}
	return v.FeedVersion
}

func writeFile(path, content string, mode os.FileMode) error {
	if !strings.HasSuffix(content, "\n") {
		content += "\n"
	}
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		return err
	}
	return os.Chmod(path, mode)
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func hostname() string {
	h, err := os.Hostname()
	if err != nil || h == "" {
		return "unknown"
	}
	return h
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func envDur(k string, def time.Duration) time.Duration {
	if v := os.Getenv(k); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
	}
	return def
}
