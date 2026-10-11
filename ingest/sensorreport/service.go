package sensorreport

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"time"

	"github.com/williamsouzadelima/suricatoos-infra/ingest/scanlaunch"
)

const (
	// importTimeout bounds one report import (bridge.py --mode network) together with
	// the optional push to the Score, which shares its context.
	importTimeout = 5 * time.Minute

	// writeSlack is the margin past importTimeout in which the response must still be
	// written — also when the import hits its timeout and the handler answers 502.
	writeSlack = 30 * time.Second
)

// RevokedFunc reports whether a client-cert serial (hex) is revoked. nil = the CRL
// is not wired → the service denies everything (fail-closed).
type RevokedFunc func(serialHex string) bool

// Config holds the bridge invocation settings (the gvmd USER/password are per
// tenant, resolved per request — never a shared admin).
type Config struct {
	BridgeScript string // path to gmp-bridge/bridge.py
	BridgePython string // python3
	GmpSocket    string // gvmd socket
}

// importFunc imports a re-attested report into gvmd as the tenant's gvmd user and
// returns the FEED-re-attested findings (severity/CVE derived from the central feed
// by OID) — the set safe to forward to the Score, never the sensor's raw claim.
type importFunc func(ctx context.Context, tc TenantConfig, rep bridgeReport) ([]scanlaunch.Finding, error)

// Service serves POST /v1/sensor-report.
type Service struct {
	cfg       Config
	resolve   TenantResolver
	revoked   RevokedFunc
	imp       importFunc
	forwarder *Forwarder // optional push to the Score (ADR-0007 G); nil = disabled
}

// New builds a Service. resolve maps a tenant → its scoped gvmd user + scope
// (unknown tenant → deny). revoked SHOULD be wired (nil = fail-closed).
func New(cfg Config, resolve TenantResolver, revoked RevokedFunc) *Service {
	s := &Service{cfg: cfg, resolve: resolve, revoked: revoked}
	s.imp = s.execBridge
	return s
}

// WithForwarder wires an optional push of imported findings to the Score.
func (s *Service) WithForwarder(f *Forwarder) *Service { s.forwarder = f; return s }

// Register mounts the route.
func (s *Service) Register(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/sensor-report", s.handle)
}

func (s *Service) handle(w http.ResponseWriter, r *http.Request) {
	id, err := authorize(r.Header.Get("X-Client-Cert-Verify"), r.Header.Get("X-Client-Cert-DN"))
	if err != nil {
		log.Printf("sensorreport: authz negada: %v", err)
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	serial := normalizeSerial(r.Header.Get("X-Client-Cert-Serial"))
	if s.revoked == nil || s.revoked(serial) {
		log.Printf("sensorreport: CRL negada (cn=%s wired=%v)", id.CN, s.revoked != nil)
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	var rep SensorReport
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<20)).Decode(&rep); err != nil {
		http.Error(w, "json inválido", http.StatusBadRequest)
		return
	}
	if rep.SchemaVersion != SchemaVersion {
		http.Error(w, "schema_version não suportada", http.StatusBadRequest)
		return
	}
	// The cert O is authoritative. A body tenant that disagrees is a red flag.
	if rep.Tenant != "" && rep.Tenant != id.O {
		log.Printf("sensorreport: tenant do body %q ≠ cert O %q — rejeitado", rep.Tenant, id.O)
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	tc, ok := s.resolve(id.O)
	if !ok || tc.Scope == nil {
		log.Printf("sensorreport: tenant %q sem config/escopo — rejeitado", id.O)
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	// Drop any finding whose host is outside the tenant's scope (quarantine): a
	// compromised sensor cannot inject findings for a co-tenant or arbitrary host.
	kept := rep.Findings[:0]
	dropped := 0
	for _, f := range rep.Findings {
		if tc.Scope.ContainsIP(f.Host) {
			kept = append(kept, f)
		} else {
			dropped++
		}
	}
	if dropped > 0 {
		log.Printf("sensorreport: tenant=%s %d achado(s) fora de escopo quarentenados", id.O, dropped)
	}
	if len(kept) == 0 {
		writeJSON(w, http.StatusAccepted, map[string]any{"imported": 0, "quarantined": dropped})
		return
	}

	// The import below can run for minutes, far past the server-wide WriteTimeout
	// (30 s in cmd/ingest). Extend the write deadline for THIS response only — the
	// global timeout keeps protecting every other route. Without it the answer is cut
	// off after a successful import: the sensor sees an error, skips the ack and
	// re-delivers the job, and the report is imported a second time.
	extendWriteDeadline(w, importTimeout+writeSlack)
	ctx, cancel := context.WithTimeout(r.Context(), importTimeout)
	defer cancel()
	report := bridgeReport{Tenant: id.O, ScanTime: rep.CollectedAt, Findings: kept}
	reattested, err := s.imp(ctx, tc, report)
	if err != nil {
		log.Printf("sensorreport: import tenant=%s corr=%s falhou: %v", id.O, rep.CorrelationID, err)
		http.Error(w, "erro ao importar", http.StatusBadGateway)
		return
	}
	log.Printf("sensorreport: tenant=%s corr=%s importado (%d achado(s), %d quarentena)",
		id.O, rep.CorrelationID, len(kept), dropped)

	// Push to the Score (ADR-0007 G), best-effort — the central GSA already has the
	// data. The tenant is the authoritative cert O (never the sensor's claim), and
	// we forward the FEED-RE-ATTESTED findings (severity/CVE from the central feed by
	// OID), NOT the sensor's raw values — so a compromised sensor cannot forge
	// criticals/CVEs on the Score path either (ADR-0007 risk #1).
	if s.forwarder.Enabled() {
		if err := s.forwarder.Forward(ctx, id.O, rep.CorrelationID, reattested); err != nil {
			log.Printf("sensorreport: push p/ Score falhou (best-effort): %v", err)
		}
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"imported": len(kept), "quarantined": dropped})
}

// execBridge writes the re-attestable report to a temp file and runs
// bridge.py --mode network as the tenant's scoped gvmd user (never admin). The
// bridge re-attests severity/CVE from the central feed by OID and writes the
// re-attested findings to a second temp file, which we read back and return so the
// Score push forwards feed-attested values — never the sensor's raw claim.
func (s *Service) execBridge(ctx context.Context, tc TenantConfig, rep bridgeReport) ([]scanlaunch.Finding, error) {
	if s.cfg.BridgeScript == "" {
		return nil, fmt.Errorf("BRIDGE_SCRIPT não configurado")
	}
	tmp, err := os.CreateTemp("", "suricatoos-sensor-*.json")
	if err != nil {
		return nil, fmt.Errorf("temp file: %w", err)
	}
	defer os.Remove(tmp.Name())
	if err := json.NewEncoder(tmp).Encode(rep); err != nil {
		tmp.Close()
		return nil, fmt.Errorf("encode: %w", err)
	}
	tmp.Close()

	// bridge.py writes the feed-re-attested findings here (non-fabrication invariant).
	outTmp, err := os.CreateTemp("", "suricatoos-sensor-reatt-*.json")
	if err != nil {
		return nil, fmt.Errorf("temp file: %w", err)
	}
	outPath := outTmp.Name()
	outTmp.Close()
	defer os.Remove(outPath)

	python := s.cfg.BridgePython
	if python == "" {
		python = "python3"
	}
	args := []string{
		s.cfg.BridgeScript, tmp.Name(),
		"--mode", "network",
		"--socket", s.cfg.GmpSocket,
		"--username", tc.GmpUsername,
		"--reattested-out", outPath,
	}
	var stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, python, args...)
	cmd.Env = append(os.Environ(), "GVM_PASSWORD="+tc.GmpPassword)
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("bridge.py --mode network: %w\n%s", err, stderr.String())
	}
	data, err := os.ReadFile(outPath)
	if err != nil {
		return nil, fmt.Errorf("ler achados re-atestados: %w", err)
	}
	var reatt []scanlaunch.Finding
	if len(bytes.TrimSpace(data)) > 0 {
		if err := json.Unmarshal(data, &reatt); err != nil {
			return nil, fmt.Errorf("parse achados re-atestados: %w", err)
		}
	}
	return reatt, nil
}

// extendWriteDeadline moves this response's write deadline to now+d, overriding the
// server-wide WriteTimeout for this connection until the next request resets it. It
// is best-effort: a ResponseWriter that cannot do it (a wrapper without Unwrap, a
// recorder in tests) keeps the server default, which is logged so a response cut
// off at the global timeout is traceable.
func extendWriteDeadline(w http.ResponseWriter, d time.Duration) {
	if err := http.NewResponseController(w).SetWriteDeadline(time.Now().Add(d)); err != nil {
		log.Printf("sensorreport: não foi possível estender o prazo de escrita (%v) — a resposta fica sujeita ao WriteTimeout do servidor", err)
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
