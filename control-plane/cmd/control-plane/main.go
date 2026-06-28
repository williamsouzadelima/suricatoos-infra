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
//	TLS_CERT              path to TLS certificate PEM  (optional; plaintext HTTP if absent)
//	TLS_KEY               path to TLS private key PEM  (optional)
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

	// Ephemeral CA — replaced by persistent CA in Fase 4 (disk/KMS).
	authority, err := ca.NewEphemeral(time.Now())
	if err != nil {
		log.Fatalf("CA init: %v", err)
	}
	log.Printf("CA fingerprint (pin): %s", authority.Fingerprint())

	store := tokens.NewMemStore()
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
