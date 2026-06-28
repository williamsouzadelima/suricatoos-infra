// Command ingest receives agent inventory payloads over HTTP(S) with optional
// mTLS, runs the Notus correlation engine on each one, and imports findings to
// gvmd via the gmp-bridge Python script.
//
// Configuration via environment variables:
//
//	INGEST_ADDR      listen address           (default: :9090)
//	TLS_CERT         server TLS certificate PEM (optional; plaintext if absent)
//	TLS_KEY          server TLS private key PEM (optional)
//	CA_CERT_FILE     CA cert PEM for verifying agent mTLS (optional)
//	NOTUS_DIR        path to *.notus advisory files (required for correlation)
//	BRIDGE_SCRIPT    path to gmp-bridge/bridge.py  (optional; skips GMP import if absent)
//	BRIDGE_PYTHON    python3 binary               (default: python3)
//	GMP_SOCKET       gvmd Unix socket             (default: /run/gvmd/gvmd.sock)
//	GMP_USERNAME     gvmd username               (default: admin)
//	GVM_PASSWORD     gvmd password
//	GMP_TASK_NAME    container task prefix        (default: suricatoos-import)
package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/williamsouzadelima/suricatoos-infra/ingest"
)

func main() {
	addr := envOr("INGEST_ADDR", ":9090")
	tlsCertFile := os.Getenv("TLS_CERT")
	tlsKeyFile := os.Getenv("TLS_KEY")
	caCertFile := os.Getenv("CA_CERT_FILE")
	notusDir := os.Getenv("NOTUS_DIR")
	bridgeScript := os.Getenv("BRIDGE_SCRIPT")

	// Select sink.
	var sink ingest.Sink
	if notusDir != "" {
		ps, err := ingest.NewPipelineSink(ingest.PipelineConfig{
			NotusDir:     notusDir,
			BridgeScript: bridgeScript,
			BridgePython: envOr("BRIDGE_PYTHON", "python3"),
			GmpSocket:    envOr("GMP_SOCKET", "/run/gvmd/gvmd.sock"),
			GmpUsername:  envOr("GMP_USERNAME", "admin"),
			GmpPassword:  os.Getenv("GVM_PASSWORD"),
			TaskName:     envOr("GMP_TASK_NAME", "suricatoos-import"),
		})
		if err != nil {
			log.Fatalf("pipeline sink: %v", err)
		}
		sink = ps
		log.Printf("pipeline: correlation enabled (NOTUS_DIR=%s)", notusDir)
		if bridgeScript != "" {
			log.Printf("pipeline: GMP import enabled (BRIDGE_SCRIPT=%s)", bridgeScript)
		} else {
			log.Printf("pipeline: GMP import disabled — set BRIDGE_SCRIPT to enable")
		}
	} else {
		sink = &ingest.MemSink{}
		log.Printf("pipeline: correlation disabled — set NOTUS_DIR to enable")
	}

	srv := &http.Server{
		Addr:         addr,
		Handler:      ingest.NewServer(sink).Handler(),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	if tlsCertFile != "" && tlsKeyFile != "" {
		tlsCfg, err := buildTLSConfig(tlsCertFile, tlsKeyFile, caCertFile)
		if err != nil {
			log.Fatalf("TLS: %v", err)
		}
		srv.TLSConfig = tlsCfg
		log.Printf("ingest listening on %s (TLS%s)", addr, mtlsLabel(caCertFile))
		log.Fatal(srv.ListenAndServeTLS("", ""))
	} else {
		log.Printf("ingest listening on %s (plaintext — use TLS in production)", addr)
		log.Fatal(srv.ListenAndServe())
	}
}

// buildTLSConfig returns a TLS config with the server cert and, when caCertFile
// is set, requires client certificates issued by that CA (mTLS).
func buildTLSConfig(certFile, keyFile, caCertFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}
	if caCertFile != "" {
		caPEM, err := os.ReadFile(caCertFile)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, errorf("CA cert PEM inválido: %s", caCertFile)
		}
		cfg.ClientCAs = pool
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return cfg, nil
}

func mtlsLabel(caCertFile string) string {
	if caCertFile != "" {
		return " + mTLS"
	}
	return ""
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func errorf(format string, args ...any) error {
	return fmt.Errorf(format, args...)
}
