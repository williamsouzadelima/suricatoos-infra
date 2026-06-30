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
	"time"

	cpapi "github.com/williamsouzadelima/suricatoos-infra/control-plane/api"
	"github.com/williamsouzadelima/suricatoos-infra/control-plane/ca"
	"github.com/williamsouzadelima/suricatoos-infra/control-plane/enroll"
	cpprovision "github.com/williamsouzadelima/suricatoos-infra/control-plane/provision"
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

	enrollSvc := enroll.NewService(tm, authority, enroll.WithIngestURL(ingestURL))
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
	updateSvc := cpupdate.NewService(updateCfg, authority)

	// Frictionless install: mints a short-lived token and returns a ready install
	// command per OS. Guarded by nginx (GSA session), never bearer — see provision pkg.
	provisionSvc := cpprovision.New(tm, authority.Fingerprint(), serverURL)

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
	mux.Handle("/api/", adminAPI.Handler())
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
