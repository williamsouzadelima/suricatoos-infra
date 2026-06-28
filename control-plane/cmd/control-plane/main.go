// Command control-plane runs the Suricatoos Agent control-plane server.
//
// It exposes two sets of routes on a single HTTP(S) listener:
//
//   - POST /v1/enroll  — mTLS bootstrap enrollment (agent-facing)
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
	"github.com/williamsouzadelima/suricatoos-infra/control-plane/tokens"
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

	enrollSvc := enroll.NewService(tm, authority)
	adminAPI := cpapi.New(tm, authority, serverURL, adminSecret)

	mux := http.NewServeMux()
	mux.Handle("/v1/", enrollSvc.Handler())
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
