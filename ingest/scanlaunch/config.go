package scanlaunch

import (
	"log"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds the scanlaunch service settings, all from SCAN_* env vars.
type Config struct {
	Enabled       bool          // SCAN_LAUNCH_ENABLED — master switch (POST 503 when false)
	BridgeScript  string        // SCAN_BRIDGE_SCRIPT — path to scan_bridge.py
	BridgePython  string        // BRIDGE_PYTHON (shared with the inventory path)
	GmpSocket     string        // GMP_SOCKET (shared)
	GmpUsername   string        // SCAN_GMP_USERNAME — the scoped launcher user (NOT admin)
	GmpPassword   string        // SCAN_GVM_PASSWORD — the scoped user's password
	StateFile     string        // SCAN_STATE_FILE — job registry path
	FindingsDir   string        // SCAN_FINDINGS_DIR — cached findings dir
	MaxConcurrent int           // SCAN_MAX_CONCURRENT — simultaneous gvmd tasks
	MaxHosts      int           // SCAN_MAX_HOSTS — per request
	MaxPorts      int           // SCAN_MAX_PORTS — per request (union)
	RescanWindow  time.Duration // SCAN_MIN_RESCAN_INTERVAL — per-target cooldown
	MaxDuration   time.Duration // SCAN_MAX_DURATION — auto-stop a stuck task
	Retention     time.Duration // SCAN_RESULT_RETENTION — evict terminal jobs after this
	AliveTest     string        // SCAN_ALIVE_TEST — GVM alive_test
	AllowedO      string        // SCAN_LAUNCH_ALLOWED_O — required cert O
	AllowedOU     string        // SCAN_LAUNCH_ALLOWED_OU — required cert OU
	Allowlist     string        // SCAN_HOST_ALLOWLIST — comma CIDRs (empty = deny-all)
	CRLURL        string        // SCAN_CRL_URL — control-plane CRL (DER)
	RequireCRL    bool          // SCAN_REQUIRE_CRL — fail-closed on missing/revoked
	TickInterval  time.Duration // reconciler tick (fixed, not env)
}

// ConfigFromEnv builds a Config from the environment with safe defaults. The
// allowlist ships EMPTY (deny-all) so no scan can launch until an operator adds
// explicit per-engagement CIDRs.
func ConfigFromEnv() Config {
	return Config{
		Enabled:       envBool("SCAN_LAUNCH_ENABLED", false),
		BridgeScript:  os.Getenv("SCAN_BRIDGE_SCRIPT"),
		BridgePython:  envStr("BRIDGE_PYTHON", "python3"),
		GmpSocket:     envStr("GMP_SOCKET", "/run/gvmd/gvmd.sock"),
		GmpUsername:   envStr("SCAN_GMP_USERNAME", "suricatoos-scan"),
		GmpPassword:   os.Getenv("SCAN_GVM_PASSWORD"),
		StateFile:     envStr("SCAN_STATE_FILE", "/data/scan-requests.json"),
		FindingsDir:   envStr("SCAN_FINDINGS_DIR", "/data/findings"),
		MaxConcurrent: envInt("SCAN_MAX_CONCURRENT", 2, 0, 64), // 0 = pausa lançamentos
		MaxHosts:      envInt("SCAN_MAX_HOSTS", 256, 1, 65535),
		MaxPorts:      envInt("SCAN_MAX_PORTS", 1000, 1, 65535),
		RescanWindow:  envDur("SCAN_MIN_RESCAN_INTERVAL", 6*time.Hour),
		MaxDuration:   envDur("SCAN_MAX_DURATION", 6*time.Hour),
		Retention:     envDur("SCAN_RESULT_RETENTION", 48*time.Hour),
		AliveTest:     envStr("SCAN_ALIVE_TEST", "Consider Alive"),
		AllowedO:      envStr("SCAN_LAUNCH_ALLOWED_O", "score-hub"),
		AllowedOU:     envStr("SCAN_LAUNCH_ALLOWED_OU", "scan-requester"),
		Allowlist:     os.Getenv("SCAN_HOST_ALLOWLIST"),
		CRLURL:        envStr("SCAN_CRL_URL", "http://control-plane:8080/v1/crl.der"),
		RequireCRL:    envBool("SCAN_REQUIRE_CRL", true),
		TickInterval:  30 * time.Second,
	}
}

func envStr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// envInt parses key into [min, max]. An unset key uses def silently; a set-but-
// invalid or out-of-range value is logged (not silent) and coerced to def/max.
func envInt(key string, def, min, max int) int {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil || n < min {
		log.Printf("scanlaunch: %s=%q inválido (min=%d) — usando default %d", key, v, min, def)
		return def
	}
	if n > max {
		log.Printf("scanlaunch: %s=%d acima do teto %d — limitando", key, n, max)
		return max
	}
	return n
}

func envBool(key string, def bool) bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv(key)))
	switch v {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	}
	return def
}

func envDur(key string, def time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(strings.TrimSpace(v))
	if err != nil || d <= 0 {
		log.Printf("scanlaunch: %s=%q inválido — usando default %s", key, v, def)
		return def
	}
	return d
}
