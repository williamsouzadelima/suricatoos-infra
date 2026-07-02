// Package renew rotates the sensor's mTLS certificate before it expires (ADR-0007).
// It authenticates with the CURRENT cert (mTLS), sends a fresh CSR keeping the same
// CN, and atomically swaps in the new cert/key. The cloud derives the tenant/policy
// from the presented cert, so a rotation can never change who the sensor is.
package renew

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

// Config drives renewals.
type Config struct {
	RenewURL string // .../agent/v1/renew
	CertFile string
	KeyFile  string
	CAFile   string
	// FeedPubFile/UpdatePubFile receive the rotated verification pubkeys the cloud
	// returns on renew (ADR-0007 risk #3). Renew is the only graceful refresh channel
	// for a live sensor (re-enroll hits ErrAgentAlreadyExists), so a feed/update key
	// rotation must be persisted here or it never reaches the enrolled fleet. Empty =
	// don't persist.
	FeedPubFile   string
	UpdatePubFile string
	// RenewBefore triggers a renewal when the cert's remaining life is below this.
	RenewBefore time.Duration
}

// Renewer performs cert rotation.
type Renewer struct {
	cfg Config
	now func() time.Time
}

// New builds a Renewer.
func New(cfg Config) *Renewer {
	if cfg.RenewBefore <= 0 {
		cfg.RenewBefore = 7 * 24 * time.Hour
	}
	return &Renewer{cfg: cfg, now: time.Now}
}

// DueSoon reports whether the on-disk cert expires within RenewBefore.
func (r *Renewer) DueSoon() bool {
	cert, err := loadLeaf(r.cfg.CertFile)
	if err != nil {
		return false
	}
	return r.now().Add(r.cfg.RenewBefore).After(cert.NotAfter)
}

type renewReq struct {
	CSR     string `json:"csr"`
	AgentID string `json:"agent_id"`
}
type renewResp struct {
	Certificate  string `json:"certificate"`
	CACert       string `json:"ca_cert"`
	FeedPubKey   string `json:"feed_pubkey"`
	UpdatePubKey string `json:"update_pubkey"`
}

// RenewIfDue rotates the cert when it is close to expiry. It is a no-op (nil error)
// when the cert is still fresh. On success the new cert/key are written atomically.
func (r *Renewer) RenewIfDue(ctx context.Context) (bool, error) {
	if !r.DueSoon() {
		return false, nil
	}
	client, err := r.mtlsClient()
	if err != nil {
		return false, err
	}
	return r.renewWith(ctx, client)
}

// renewWith performs the rotation using the given HTTP client (injectable for tests).
func (r *Renewer) renewWith(ctx context.Context, client *http.Client) (bool, error) {
	leaf, err := loadLeaf(r.cfg.CertFile)
	if err != nil {
		return false, err
	}
	cn := leaf.Subject.CommonName

	// New keypair + CSR keeping the same CN (identity is preserved server-side).
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return false, err
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}}, key)
	if err != nil {
		return false, err
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	body, _ := json.Marshal(renewReq{CSR: string(csrPEM), AgentID: cn})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.cfg.RenewURL, bytes.NewReader(body))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 400 {
		return false, fmt.Errorf("renew rejeitado (%d): %s", resp.StatusCode, bytes.TrimSpace(raw))
	}
	var rr renewResp
	if err := json.Unmarshal(raw, &rr); err != nil || rr.Certificate == "" {
		return false, fmt.Errorf("renew: resposta inválida")
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	// Write key first (0600), then cert — a torn write leaves the OLD cert usable
	// until both succeed (atomic per-file via temp+rename).
	if err := writeAtomic(r.cfg.KeyFile, keyPEM, 0o600); err != nil {
		return false, err
	}
	if err := writeAtomic(r.cfg.CertFile, []byte(rr.Certificate), 0o644); err != nil {
		return false, err
	}
	if rr.CACert != "" && r.cfg.CAFile != "" {
		_ = writeAtomic(r.cfg.CAFile, []byte(rr.CACert), 0o644)
	}
	// Persist rotated verification pubkeys (ADR-0007 risk #3) so a feed/update-key
	// rotation reaches this live sensor through the renew channel (feedsync prefers
	// feed-verify.pub over the CA pubkey).
	if rr.FeedPubKey != "" && r.cfg.FeedPubFile != "" {
		_ = writeAtomic(r.cfg.FeedPubFile, []byte(rr.FeedPubKey), 0o644)
	}
	if rr.UpdatePubKey != "" && r.cfg.UpdatePubFile != "" {
		_ = writeAtomic(r.cfg.UpdatePubFile, []byte(rr.UpdatePubKey), 0o644)
	}
	return true, nil
}

func (r *Renewer) mtlsClient() (*http.Client, error) {
	cert, err := tls.LoadX509KeyPair(r.cfg.CertFile, r.cfg.KeyFile)
	if err != nil {
		return nil, err
	}
	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			// RootCAs nil → system trust verifies the cloud's public (Let's Encrypt)
			// server cert; the enrollment CA is what the SERVER uses to verify our
			// client cert (mTLS). Pinning it here made renew fail like every other
			// phone-home (same fix as sensor/internal/cloud + the endpoint agent).
			MinVersion: tls.VersionTLS12,
		}},
	}, nil
}

func loadLeaf(certFile string) (*x509.Certificate, error) {
	b, err := os.ReadFile(certFile)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, fmt.Errorf("cert PEM inválido")
	}
	return x509.ParseCertificate(block.Bytes)
}

func writeAtomic(path string, content []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, content, mode); err != nil {
		return err
	}
	if err := os.Chmod(tmp, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
