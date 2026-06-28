// Package ca is the control-plane certificate authority: it issues short-lived
// mTLS client certificates by signing verified CSRs. The CA certificate is the
// trust anchor pinned by agents.
package ca

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"time"
)

// CertProfile is the identity/scope baked into an issued client certificate.
type CertProfile struct {
	CommonName string // agent id
	Org        string // tenant
	OrgUnit    string // policy
}

// CA signs client CSRs. Use NewEphemeral for dev/tests; a persistent CA loaded
// from disk/KMS comes in Fase 4.
type CA struct {
	cert    *x509.Certificate
	key     ed25519.PrivateKey
	certPEM []byte
}

// NewEphemeral generates a fresh self-signed Ed25519 CA valid from now.
func NewEphemeral(now time.Time) (*CA, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := randSerial()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "Suricatoos Enrollment CA", Organization: []string{"Suricatoos"}},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &CA{
		cert:    cert,
		key:     priv,
		certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
	}, nil
}

// NewPersistent loads the CA from certFile and keyFile if both exist; otherwise
// it generates a new ephemeral CA, saves both files, and returns it. The key
// file is written with 0600 permissions. If exactly one file exists the call
// returns an error — the state is inconsistent and must be resolved manually.
//
// This is the production path. NewEphemeral is for tests and one-shot runs.
func NewPersistent(certFile, keyFile string, now time.Time) (*CA, error) {
	_, errCert := os.Stat(certFile)
	_, errKey := os.Stat(keyFile)
	switch {
	case errCert == nil && errKey == nil:
		return loadCA(certFile, keyFile)
	case errCert != nil && errKey != nil:
		// Neither exists — generate and persist.
		c, err := NewEphemeral(now)
		if err != nil {
			return nil, err
		}
		return c, saveCA(c, certFile, keyFile)
	default:
		return nil, fmt.Errorf("inconsistent CA state: certFile=%v keyFile=%v — remove both files and restart to regenerate", errCert, errKey)
	}
}

// loadCA reads a CA certificate and Ed25519 private key from PEM files.
func loadCA(certFile, keyFile string) (*CA, error) {
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return nil, fmt.Errorf("leitura CA cert: %w", err)
	}
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("leitura CA key: %w", err)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, errors.New("CA cert PEM inválido")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("CA cert: %w", err)
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, errors.New("CA key PEM inválido")
	}
	keyIface, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("CA key: %w", err)
	}
	key, ok := keyIface.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("CA key deve ser Ed25519")
	}
	return &CA{cert: cert, key: key, certPEM: certPEM}, nil
}

// saveCA persists the CA certificate (0644) and Ed25519 key (0600) as PEM files.
func saveCA(c *CA, certFile, keyFile string) error {
	if err := os.WriteFile(certFile, c.certPEM, 0o644); err != nil {
		return fmt.Errorf("gravar CA cert: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(c.key)
	if err != nil {
		return fmt.Errorf("serializar CA key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		return fmt.Errorf("gravar CA key: %w", err)
	}
	return nil
}

// Fingerprint returns the SHA-256 fingerprint of the CA certificate in
// "sha256:HEXHEX..." format — the value passed as --ca-pin to the agent.
func (c *CA) Fingerprint() string {
	h := sha256.Sum256(c.cert.Raw)
	return "sha256:" + hex.EncodeToString(h[:])
}

// CertPEM returns a copy of the CA certificate PEM — the trust anchor shipped to
// agents to pin.
func (c *CA) CertPEM() []byte {
	out := make([]byte, len(c.certPEM))
	copy(out, c.certPEM)
	return out
}

// SignClientCSR verifies a CSR (proof-of-possession + key-strength policy) and
// signs a client certificate bound to the profile, valid for ttl from now.
func (c *CA) SignClientCSR(csr *x509.CertificateRequest, p CertProfile, ttl time.Duration, now time.Time) ([]byte, error) {
	if csr == nil {
		return nil, errors.New("CSR nulo")
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("assinatura do CSR inválida (proof-of-possession): %w", err)
	}
	if err := allowedKey(csr.PublicKey); err != nil {
		return nil, err
	}
	if p.CommonName == "" {
		return nil, errors.New("CommonName (agent id) obrigatório")
	}
	if ttl <= 0 {
		return nil, errors.New("ttl do certificado deve ser positivo")
	}
	serial, err := randSerial()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               subject(p),
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(ttl),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, csr.PublicKey, c.key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

// allowedKey enforces a public-key strength/algorithm policy so the CA never
// signs a weak or unexpected key into a long-lived mTLS identity.
func allowedKey(pub any) error {
	switch k := pub.(type) {
	case ed25519.PublicKey:
		return nil
	case *ecdsa.PublicKey:
		switch k.Curve {
		case elliptic.P256(), elliptic.P384(), elliptic.P521():
			return nil
		}
		return errors.New("curva ECDSA não permitida (use P-256/P-384/P-521)")
	case *rsa.PublicKey:
		if k.N.BitLen() >= 2048 {
			return nil
		}
		return errors.New("chave RSA fraca (< 2048 bits)")
	default:
		return fmt.Errorf("tipo de chave não permitido: %T", pub)
	}
}

func subject(p CertProfile) pkix.Name {
	n := pkix.Name{CommonName: p.CommonName}
	if p.Org != "" {
		n.Organization = []string{p.Org}
	}
	if p.OrgUnit != "" {
		n.OrganizationalUnit = []string{p.OrgUnit}
	}
	return n
}

// randSerial returns a cryptographically random 128-bit certificate serial.
func randSerial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
}
