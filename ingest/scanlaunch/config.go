package scanlaunch

import (
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
		MaxConcurrent: envInt("SCAN_MAX_CONCURRENT", 2),
		MaxHosts:      envInt("SCAN_MAX_HOSTS", 256),
		MaxPorts:      envInt("SCAN_MAX_PORTS", 1000),
		RescanWindow:  envDur("SCAN_MIN_RESCAN_INTERVAL", 6*time.Hour),
		MaxDuration:   envDur("SCAN_MAX_DURATION", 6*time.Hour),
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

func envInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return def
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
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
	}
	return def
}
