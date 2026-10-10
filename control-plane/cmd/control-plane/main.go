// Command control-plane runs the Suricatoos Agent control-plane server.
//
// It exposes two sets of routes on a single HTTP(S) listener:
//
//   - POST /v1/enroll  — mTLS bootstrap enrollment (agent-facing)
//   - GET  /v1/crl.der — signed Certificate Revocation List (DER format)
//   - POST /api/v1/tokens, GET /api/v1/tokens, DELETE /api/v1/tokens/{id}
//     — admin token management (admin-facing, bearer-auth)
//
// Configuration via environment variables:
//
//	CONTROL_PLANE_ADDR    listen address  (default: :8080)
//	CONTROL_PLANE_URL     public HTTPS URL embedded in enrollment bundles (required)
//	ADMIN_SECRET          shared secret for Authorization: Bearer (required)
//	TLS_CERT              path to TLS certificate PEM  (optional; plaintext if absent)
//	TLS_KEY               path to TLS private key PEM  (optional)
//	CA_CERT_FILE          path to CA certificate PEM for persistent CA (recommended)
//	CA_KEY_FILE           path to CA Ed25519 private key PEM (recommended)
//	TOKEN_DB_PATH         path to BoltDB file for persistent token store (recommended)
//	CRL_URL               public URL of the CRL endpoint (e.g. https://cp.example.com/v1/crl.der)
//	                      when set, issued certs embed it as a CRL distribution point
//	CRL_FILE              path to JSON file for persisting revoked serials (recommended with CRL_URL)
//	INGEST_URL            public inventory endpoint handed to agents on enrollment
//	                      (e.g. https://scanner.suricatoos.com/ingest/v1/inventory)
//	UPDATE_MANIFEST_FILE  path to the JSON auto-update manifest (version + per
//	                      os/arch url+sha256). When set, /v1/update/check serves a
//	                      CA-signed answer; unset → endpoint returns 204 (disabled)
//	REMEDIATION_ENABLED   "true" mounts the remediation job routes (ADR-0010).
//	                      DARK by default — only safe behind the dedicated nginx
//	                      mTLS location that forwards X-Client-Cert-* and strips
//	                      client X-Operator (F2c). Leave unset until then.
//	REMEDIATION_SIGN_KEY_FILE  path to the Ed25519 key that signs approved jobs
//	                      (4th purpose-scoped key); its pubkey is handed to agents
//	                      at enroll. Absent → ephemeral (dev only).
//	REMEDIATION_JOBS_FILE path to the JSON file persisting the job queue (0600,
//	                      atomic). Absent → in-memory (lost on restart).
//	AI_CONFIG_ENABLED     "true" mounts the AI-provider admin routes (LLM router
//	                      keys). DARK by default; admin-bearer gated.
//	AI_CONFIG_KEK_FILE    path to the 32-byte key that encrypts provider API keys
//	                      at rest (0600). Absent → ephemeral (keys lost on restart).
//	AI_PROVIDERS_FILE     path to the JSON file persisting providers (0600, atomic;
//	                      keys stored ENCRYPTED). Absent → in-memory.
//	AI_PLANNER_ENABLED    "true" mounts POST /api/v1/remediation/plan (operator-
//	                      triggered AI draft). DARK by default; admin-bearer.
//	AI_PLANNER_CONSENT    "true" grants per-purpose consent. DEFAULT off → no model
//	                      call ever happens without it.
//	AI_PLANNER_BUDGET_USD monthly spend ceiling (estimate); <=0/unset → no ceiling.
//	AI_PLANNER_USD_PER_1K cost estimate per 1k tokens, for the budget gate.
//	AI_PLANNER_PROVIDER_ID provider id to use; unset → the first enabled provider.
//
// When CA_CERT_FILE/CA_KEY_FILE are set the CA survives restarts (agents keep
// their mTLS certificates). Without them a new ephemeral CA is generated on
// every startup, invalidating all enrolled agents.
// When TOKEN_DB_PATH is set token records (audit trail, revocations) survive
// restarts. Without it they are lost on exit.
//
// All configuration is logged on startup (secrets are not logged).
package main

import (
	"crypto/tls"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	cpaiproviders "github.com/williamsouzadelima/suricatoos-infra/control-plane/aiproviders"
	cpapi "github.com/williamsouzadelima/suricatoos-infra/control-plane/api"
	"github.com/williamsouzadelima/suricatoos-infra/control-plane/ca"
	cpcommands "github.com/williamsouzadelima/suricatoos-infra/control-plane/commands"
	"github.com/williamsouzadelima/suricatoos-infra/control-plane/enroll"
	cpenrollcmd "github.com/williamsouzadelima/suricatoos-infra/control-plane/enrollcmd"
	cpfeed "github.com/williamsouzadelima/suricatoos-infra/control-plane/feed"
	cpplanner "github.com/williamsouzadelima/suricatoos-infra/control-plane/planner"
	cpprovision "github.com/williamsouzadelima/suricatoos-infra/control-plane/provision"
	cpremediation "github.com/williamsouzadelima/suricatoos-infra/control-plane/remediation"
	cpsensorjobs "github.com/williamsouzadelima/suricatoos-infra/control-plane/sensorjobs"
	cpsignkeys "github.com/williamsouzadelima/suricatoos-infra/control-plane/signkeys"
	cptenants "github.com/williamsouzadelima/suricatoos-infra/control-plane/tenants"
	"github.com/williamsouzadelima/suricatoos-infra/control-plane/tokens"
	cpupdate "github.com/williamsouzadelima/suricatoos-infra/control-plane/update"
)

func main() {
	addr := envOr("CONTROL_PLANE_ADDR", ":8080")
	serverURL := mustEnv("CONTROL_PLANE_URL")
	adminSecret := mustEnv("ADMIN_SECRET")
	tlsCert := os.Getenv("TLS_CERT")
	tlsKey := os.Getenv("TLS_KEY")
	caCertFile := os.Getenv("CA_CERT_FILE")
	caKeyFile := os.Getenv("CA_KEY_FILE")
	tokenDBPath := os.Getenv("TOKEN_DB_PATH")
	crlURL := os.Getenv("CRL_URL")
	crlFile := os.Getenv("CRL_FILE")
	ingestURL := os.Getenv("INGEST_URL")
	updateManifestFile := os.Getenv("UPDATE_MANIFEST_FILE")

	// CA — persistent when CA_CERT_FILE + CA_KEY_FILE are set; ephemeral otherwise.
	var authority *ca.CA
	var err error
	if caCertFile != "" && caKeyFile != "" {
		authority, err = ca.NewPersistent(caCertFile, caKeyFile, time.Now())
		log.Printf("CA: persistent (%s)", caCertFile)
	} else {
		authority, err = ca.NewEphemeral(time.Now())
		log.Printf("CA: EPHEMERAL — set CA_CERT_FILE + CA_KEY_FILE for production")
	}
	if err != nil {
		log.Fatalf("CA init: %v", err)
	}
	log.Printf("CA fingerprint (pin): %s", authority.Fingerprint())

	// CRL — optional; when set, issued certs carry the distribution point URL and
	// revocations are persisted to disk so the CRL survives restarts.
	if crlURL != "" {
		authority.SetCRLURL(crlURL)
		log.Printf("CRL: distribution point %s", crlURL)
	} else {
		log.Printf("CRL: disabled — set CRL_URL to enable revocation support")
	}
	if crlFile != "" {
		if err := authority.LoadCRLFile(crlFile); err != nil {
			log.Fatalf("CRL file: %v", err)
		}
		log.Printf("CRL: persisting revocations to %s", crlFile)
	}

	// Token store — BoltDB when TOKEN_DB_PATH is set; in-memory otherwise.
	var store tokens.Store
	if tokenDBPath != "" {
		bs, err := tokens.NewBoltStore(tokenDBPath)
		if err != nil {
			log.Fatalf("token store: %v", err)
		}
		defer bs.Close()
		store = bs
		log.Printf("token store: BoltDB (%s)", tokenDBPath)
	} else {
		store = tokens.NewMemStore()
		log.Printf("token store: IN-MEMORY — set TOKEN_DB_PATH for production")
	}
	tm := tokens.NewManager(store)

	if ingestURL != "" {
		log.Printf("ingest URL (handed to agents on enroll): %s", ingestURL)
	} else {
		log.Printf("ingest URL: unset — set INGEST_URL so agents learn where to report")
	}

	// Purpose-scoped signing keys (ADR-0007 risk #3), separate from the CA's cert-
	// issuing key. Persisted so they survive restarts; their pubkeys are distributed
	// to sensors/agents at enroll. Absent path → ephemeral (dev).
	feedKey, err := cpsignkeys.LoadOrCreate(os.Getenv("FEED_SIGN_KEY_FILE"))
	if err != nil {
		log.Fatalf("feed sign key: %v", err)
	}
	updateKey, err := cpsignkeys.LoadOrCreate(os.Getenv("UPDATE_SIGN_KEY_FILE"))
	if err != nil {
		log.Fatalf("update sign key: %v", err)
	}
	// 4th purpose-scoped key: signs remediation jobs (ADR-0010). Its pubkey is
	// distributed to agents at enroll so they verify a signed job independently.
	remediationKey, err := cpsignkeys.LoadOrCreate(os.Getenv("REMEDIATION_SIGN_KEY_FILE"))
	if err != nil {
		log.Fatalf("remediation sign key: %v", err)
	}

	enrollOpts := []enroll.Option{
		enroll.WithIngestURL(ingestURL),
		enroll.WithVerificationKeys(feedKey.PublicPEM(), updateKey.PublicPEM()),
		enroll.WithRemediationKey(remediationKey.PublicPEM()),
		// CRL enforcement on /renew (ADR-0007 risk #6): a revoked cert cannot renew
		// itself into a fresh serial. authority.IsRevoked is authoritative + in-memory.
		enroll.WithRevocationCheck(authority.IsRevoked),
	}
	// Short renewed-cert TTL bounds revocation latency for a leaked cert (ADR-0007).
	if v := os.Getenv("RENEW_CERT_TTL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			enrollOpts = append(enrollOpts, enroll.WithRenewTTL(d))
		}
	}
	enrollSvc := enroll.NewService(tm, authority, enrollOpts...)
	adminAPI := cpapi.New(tm, authority, serverURL, ingestURL, adminSecret)

	// Auto-update channel — optional. When UPDATE_MANIFEST_FILE points at a valid
	// manifest, agents poll /v1/update/check and get a CA-signed answer; without
	// it the endpoint returns 204 (disabled).
	var updateCfg *cpupdate.ManifestConfig
	if updateManifestFile != "" {
		updateCfg, err = cpupdate.LoadConfig(updateManifestFile)
		if err != nil {
			log.Fatalf("update manifest: %v", err)
		}
		log.Printf("auto-update: manifest %s (version %s, %d artifacts)", updateManifestFile, updateCfg.Version, len(updateCfg.Artifacts))
	} else {
		log.Printf("auto-update: disabled — set UPDATE_MANIFEST_FILE to enable")
	}
	// Dual-sign updates: primary = CA key (legacy fleet compat), secondary =
	// dedicated update key (ADR-0007). Once the fleet has re-enrolled, drop the CA
	// primary so the CA key no longer signs updates.
	updateSvc := cpupdate.NewService(updateCfg, authority).WithUpdateKey(updateKey)

	// Frictionless install: mints a short-lived token and returns a ready install
	// command per OS. Guarded by nginx (GSA session), never bearer — see provision pkg.
	provisionSvc := cpprovision.New(tm, authority.Fingerprint(), serverURL)

	// Command channel: operators enqueue "scan_now" for an agent (admin Bearer);
	// the agent polls + acks over its mTLS channel and re-collects immediately.
	cmdSvc := cpcommands.NewService(cpcommands.NewQueue())

	// Sensor dispatch + tenant registry (ADR-0007). The tenant admin API is always
	// available (bearer-gated); the sensor-facing scan-job routes are mounted only
	// when SENSOR_JOBS_ENABLED (dark by default).
	tenantReg, err := cptenants.NewRegistry(os.Getenv("TENANTS_FILE"))
	if err != nil {
		log.Fatalf("tenants: %v", err)
	}
	tenantSvc := cptenants.NewService(tenantReg, adminSecret)
	sensorJobReg, err := cpsensorjobs.NewRegistry(cpsensorjobs.Config{
		Path: os.Getenv("SENSOR_JOBS_FILE"),
		ScopeOf: func(t string) *cpsensorjobs.Scope {
			s, _ := cpsensorjobs.NewScope(tenantReg.ScopeSpec(t))
			return s
		},
	})
	if err != nil {
		log.Fatalf("sensorjobs: %v", err)
	}
	// authority.IsRevoked is authoritative + in-memory → CRL enforced without staleness.
	sensorJobSvc := cpsensorjobs.NewService(sensorJobReg, tenantReg.Known, authority.IsRevoked)
	sensorJobsEnabled := os.Getenv("SENSOR_JOBS_ENABLED") == "true"

	// Remediation backbone (ADR-0010) — the signed/approved job queue. Mounted ONLY
	// when REMEDIATION_ENABLED (dark by default): until F2c lands the dedicated nginx
	// mTLS location (forwarding X-Client-Cert-* for these exact paths) and strips any
	// client-supplied X-Operator, these routes MUST NOT be reachable (see the
	// WIRING-CRITICAL note in remediation/service.go). The signer is the 4th
	// purpose-scoped key; a job is signed only on human approval.
	remReg, err := cpremediation.NewRegistry(cpremediation.Config{
		Path:   os.Getenv("REMEDIATION_JOBS_FILE"),
		Signer: remediationKey,
	})
	if err != nil {
		log.Fatalf("remediation: %v", err)
	}
	remSvc := cpremediation.NewService(remReg, tenantReg.Known, authority.IsRevoked, adminSecret)
	remediationEnabled := os.Getenv("REMEDIATION_ENABLED") == "true"

	// AI provider config (LLM router keys). Mounted ONLY when AI_CONFIG_ENABLED
	// (dark by default). API keys are WRITE-ONLY over the admin API and encrypted at
	// rest with a host KEK; a provider is enabled only if it meets the governance
	// bar (EU + ZDR). The plaintext key is read server-side only (by the planner).
	aiKEK, err := cpaiproviders.LoadOrCreateKEK(os.Getenv("AI_CONFIG_KEK_FILE"))
	if err != nil {
		log.Fatalf("ai-providers KEK: %v", err)
	}
	aiReg, err := cpaiproviders.NewRegistry(os.Getenv("AI_PROVIDERS_FILE"), aiKEK)
	if err != nil {
		log.Fatalf("ai-providers: %v", err)
	}
	aiSvc := cpaiproviders.NewService(aiReg, adminSecret)
	aiConfigEnabled := os.Getenv("AI_CONFIG_ENABLED") == "true"

	// Remediation planner (Fase 4) — operator-triggered AI draft. Consent is OFF by
	// default and the budget caps spend, so a drafting call only happens on an
	// explicit admin request with consent granted and an enabled provider. The real
	// OpenAI-compatible client reads the key from aiproviders server-side.
	plannerSvc := cpplanner.NewService(
		cpplanner.New(
			cpplanner.NewHTTPLLM(),
			cpplanner.NewRegistryResolver(aiReg, os.Getenv("AI_PLANNER_PROVIDER_ID")),
			cpplanner.Config{
				ConsentGranted:   os.Getenv("AI_PLANNER_CONSENT") == "true",
				MonthlyBudgetUSD: envFloat("AI_PLANNER_BUDGET_USD"),
				USDPer1kTokens:   envFloat("AI_PLANNER_USD_PER_1K"),
			},
		),
		adminSecret,
	)
	plannerEnabled := os.Getenv("AI_PLANNER_ENABLED") == "true"

	mux := http.NewServeMux()
	mux.Handle("/v1/", http.StripPrefix("/v1", enrollSvc.Handler()))
	mux.HandleFunc("GET /v1/crl.der", func(w http.ResponseWriter, r *http.Request) {
		der, err := authority.IssueCRL(time.Now().UTC())
		if err != nil {
			http.Error(w, "CRL generation failed", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/pkix-crl")
		w.Header().Set("Cache-Control", "max-age=3600")
		w.Write(der)
	})
	mux.HandleFunc("GET /v1/update/check", updateSvc.Handler())
	mux.HandleFunc("GET /provision/install", provisionSvc.Handler())
	// Agent command channel (mTLS-gated by nginx; identity from the client cert CN).
	mux.HandleFunc("GET /v1/commands", cmdSvc.PollHandler())
	mux.HandleFunc("POST /v1/commands/ack", cmdSvc.AckHandler())
	// Operator/CLI trigger (admin Bearer) to enqueue an on-demand scan.
	mux.HandleFunc("POST /api/v1/agents/{id}/commands", cmdSvc.EnqueueHandler(adminSecret))
	// Agents UI "Escanear agora" trigger — session-gated by nginx (GSAD_SID),
	// no bearer; shares the same command queue.
	mux.HandleFunc("POST /agents/scan", cmdSvc.SessionEnqueueHandler())
	mux.Handle("/api/", adminAPI.Handler())
	// Tenant registry admin (ADR-0007) — always available, bearer-gated. More
	// specific than "/api/" so these win over the adminAPI catch-all.
	mux.HandleFunc("PUT /api/v1/tenants/{t}", tenantSvc.PutHandler())
	mux.HandleFunc("GET /api/v1/tenants/{t}", tenantSvc.GetHandler())
	mux.HandleFunc("GET /api/v1/tenants", tenantSvc.ListHandler())
	// Per-tenant enrollment command (admin-bearer): mints a fresh token for the
	// validated tenant and returns a ready-to-paste `docker run` (or install.sh) with
	// the token embedded — the "dynamic per-tenant token" that activates an agent.
	enrollCmdSvc := cpenrollcmd.New(cpenrollcmd.Config{
		TM: tm, Known: tenantReg.Known, CAPin: authority.Fingerprint(),
		ServerURL: serverURL, Image: os.Getenv("AGENT_IMAGE"), AdminSecret: adminSecret,
		Tenants: func() []string {
			var out []string
			for _, t := range tenantReg.List() {
				if t.Enabled {
					out = append(out, t.Name)
				}
			}
			return out
		},
	})
	// Admin-bearer (automation/CLI).
	mux.HandleFunc("GET /api/v1/tenants/{t}/enroll-command", enrollCmdSvc.Handler())
	// Session-gated (GSA UI, behind nginx cookie gate) — the tenant selector + the
	// per-tenant enrollment command with a fresh token embedded.
	mux.HandleFunc("GET /provision/tenants", enrollCmdSvc.SessionTenantsHandler())
	mux.HandleFunc("GET /provision/enroll-command", enrollCmdSvc.SessionHandler())
	if sensorJobsEnabled {
		// Sensor-facing dispatch (nginx mTLS-gated + CRL fail-closed in the service).
		mux.HandleFunc("GET /v1/scan-jobs", sensorJobSvc.PollHandler())
		mux.HandleFunc("POST /v1/scan-jobs/{id}/ack", sensorJobSvc.AckHandler())
		mux.HandleFunc("POST /v1/heartbeat", sensorJobSvc.HeartbeatHandler())
		mux.HandleFunc("POST /api/v1/tenants/{t}/scan-jobs", sensorJobSvc.EnqueueHandler(adminSecret))
		// Feed mirror (ADR-0007): signed manifest + content-addressed blobs to the
		// sensor's local GVM. Signed with `authority` for now (a dedicated feed key
		// is the key-separation slice); the sensor verifies with the pinned CA pubkey.
		if feedRoot := os.Getenv("SENSOR_FEED_ROOT"); feedRoot != "" {
			feedSvc := cpfeed.New(cpfeed.Config{
				Root:        feedRoot,
				FeedVersion: func() string { return os.Getenv("SENSOR_FEED_VERSION") },
				Signer:      feedKey, // dedicated feed key, NOT the CA (risk #3)
				Authz:       sensorJobSvc.AuthorizeRequest,
			})
			feedSvc.Register(mux)
			log.Printf("sensor: mirror de feed HABILITADO (root=%s)", feedRoot)
		}
		log.Printf("sensor: dispatch de scan-jobs HABILITADO")
	} else {
		log.Printf("sensor: dispatch de scan-jobs desabilitado (SENSOR_JOBS_ENABLED != true)")
	}
	if remediationEnabled {
		// Agent routes (poll/ack/report) are nginx mTLS-gated + CRL fail-closed in the
		// service; operator routes (enqueue/approve/reject) are admin-bearer gated.
		// DANGER: safe only behind the F2c nginx wiring — see service.go auth() note.
		remSvc.Register(mux)
		log.Printf("remediation: fila de jobs HABILITADA (ADR-0010)")
	} else {
		log.Printf("remediation: fila de jobs desabilitada (REMEDIATION_ENABLED != true)")
	}
	if aiConfigEnabled {
		aiSvc.Register(mux)
		log.Printf("ai-providers: config de provedores HABILITADA (chaves cifradas, admin-bearer)")
	} else {
		log.Printf("ai-providers: config de provedores desabilitada (AI_CONFIG_ENABLED != true)")
	}
	if plannerEnabled {
		plannerSvc.Register(mux)
		log.Printf("remediation-planner: rascunho de IA HABILITADO (advisory; consentimento=%v)", os.Getenv("AI_PLANNER_CONSENT") == "true")
	} else {
		log.Printf("remediation-planner: desabilitado (AI_PLANNER_ENABLED != true)")
	}
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})

	srv := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	if tlsCert != "" && tlsKey != "" {
		cert, err := tls.LoadX509KeyPair(tlsCert, tlsKey)
		if err != nil {
			log.Fatalf("TLS keypair: %v", err)
		}
		srv.TLSConfig = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
		log.Printf("control-plane listening on %s (TLS)", addr)
		log.Fatal(srv.ListenAndServeTLS("", ""))
	} else {
		log.Printf("control-plane listening on %s (plaintext — use TLS in production)", addr)
		log.Fatal(srv.ListenAndServe())
	}
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func mustEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		log.Fatalf("required environment variable %s is not set", key)
	}
	return v
}

// envFloat parses a float env var, returning 0 when unset or unparseable.
func envFloat(key string) float64 {
	if v := os.Getenv(key); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			return f
		}
	}
	return 0
}
