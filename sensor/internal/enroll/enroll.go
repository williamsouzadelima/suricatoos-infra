// Package enroll performs the sensor's one-time cloud enrollment (ADR-0007): it
// generates a keypair + CSR (CN = sensor id) and exchanges a bootstrap token for a
// signed mTLS client cert whose O=tenant / OU=scanner-sensor are assigned by the
// token's scope (the sensor does NOT choose its tenant). "Fetching the tenant" is
// exactly this — the cert IS the tenant credential.
package enroll

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Config drives one enrollment.
type Config struct {
	EnrollURL string       // .../agent/v1/enroll
	Token     string       // bootstrap token (tenant + policy=scanner-sensor)
	AgentID   string       // sensor id; becomes the cert CN (must match the CSR CN)
	OS        string       // e.g. linux
	Arch      string       // e.g. amd64
	Client    *http.Client // injectable for tests; nil → default with a timeout
}

// Result is the enrolled material.
type Result struct {
	CertPEM      string
	KeyPEM       string
	CACertPEM    string
	FeedPubKey   string // PKIX PEM; verifies signed feed manifests (ADR-0007)
	UpdatePubKey string
}

// request/response mirror control-plane/enroll.
type enrollRequest struct {
	Token   string `json:"token"`
	CSR     string `json:"csr"`
	AgentID string `json:"agent_id"`
	OS      string `json:"os"`
	Arch    string `json:"arch"`
}

type enrollResponse struct {
	Certificate  string `json:"certificate"`
	CACert       string `json:"ca_cert"`
	FeedPubKey   string `json:"feed_pubkey"`
	UpdatePubKey string `json:"update_pubkey"`
}

// Enroll generates a key + CSR and exchanges the token for a signed cert.
func Enroll(ctx context.Context, cfg Config) (*Result, error) {
	if cfg.Token == "" || cfg.AgentID == "" || cfg.EnrollURL == "" {
		return nil, fmt.Errorf("token, agent_id e enroll_url são obrigatórios")
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("keygen: %w", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: cfg.AgentID}}, key)
	if err != nil {
		return nil, fmt.Errorf("csr: %w", err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})

	body, _ := json.Marshal(enrollRequest{
		Token: cfg.Token, CSR: string(csrPEM), AgentID: cfg.AgentID,
		OS: cfg.OS, Arch: cfg.Arch,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.EnrollURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	hc := cfg.Client
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("enroll POST: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("enroll rejeitado (%d): %s", resp.StatusCode, bytes.TrimSpace(raw))
	}
	var er enrollResponse
	if err := json.Unmarshal(raw, &er); err != nil {
		return nil, fmt.Errorf("enroll: resposta inválida: %w", err)
	}
	if er.Certificate == "" || er.CACert == "" {
		return nil, fmt.Errorf("enroll: resposta incompleta")
	}
	return &Result{
		CertPEM: er.Certificate, KeyPEM: string(keyPEM), CACertPEM: er.CACert,
		FeedPubKey: er.FeedPubKey, UpdatePubKey: er.UpdatePubKey,
	}, nil
}
