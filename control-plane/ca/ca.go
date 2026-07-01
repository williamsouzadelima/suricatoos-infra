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
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strings"
	"sync"
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

	mu      sync.RWMutex
	revoked []x509.RevocationListEntry // revoked cert entries
	crlURL  string                     // embedded in issued certs; empty = omit
	crlFile string                     // when set, revocations are persisted here
}

// crlEntry is the on-disk JSON representation of one revoked certificate.
type crlEntry struct {
	SerialHex string    `json:"serial"`
	RevokedAt time.Time `json:"revoked_at"`
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

// SetCRLURL sets the URL embedded as a CRL distribution point in issued client
// certificates. When non-empty, clients can fetch the CRL to check for
// revocations without waiting for the certificate TTL to expire.
func (c *CA) SetCRLURL(url string) {
	c.mu.Lock()
	c.crlURL = url
	c.mu.Unlock()
}

// LoadCRLFile reads revoked serial entries from path (JSON array of crlEntry)
// and remembers the path for future saves. Calling this is optional; without it
// revocations are in-memory only and lost on restart.
//
// A missing file is treated as an empty list (first-run case).
func (c *CA) LoadCRLFile(path string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.crlFile = path
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("ler crl file: %w", err)
	}
	var entries []crlEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return fmt.Errorf("decodificar crl file: %w", err)
	}
	for _, e := range entries {
		serial := new(big.Int)
		if _, ok := serial.SetString(e.SerialHex, 16); !ok {
			return fmt.Errorf("serial inválido na crl: %q", e.SerialHex)
		}
		c.revoked = append(c.revoked, x509.RevocationListEntry{SerialNumber: serial, RevocationTime: e.RevokedAt})
	}
	return nil
}

// RevokeCertSerial adds a certificate serial (hex string) to the revocation list.
// When LoadCRLFile was called, persists the updated list to disk.
func (c *CA) RevokeCertSerial(serialHex string, revokedAt time.Time) error {
	serial := new(big.Int)
	if _, ok := serial.SetString(serialHex, 16); !ok {
		return fmt.Errorf("serial inválido: %q", serialHex)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.revoked = append(c.revoked, x509.RevocationListEntry{SerialNumber: serial, RevocationTime: revokedAt})
	if c.crlFile != "" {
		if err := c.saveCRLLocked(); err != nil {
			return fmt.Errorf("persistir crl: %w", err)
		}
	}
	return nil
}

// IsRevoked reports whether serialHex (a client-cert serial in hex; colons,
// spaces and a 0x prefix are tolerated) is on the revocation list. The sensor
// mTLS routes call this to enforce revocation fail-closed at request time (the
// CA's revoked set is authoritative and in-memory, so there is no staleness).
func (c *CA) IsRevoked(serialHex string) bool {
	clean := strings.NewReplacer(":", "", " ", "", "0x", "", "0X", "").Replace(strings.TrimSpace(serialHex))
	want := new(big.Int)
	if _, ok := want.SetString(clean, 16); !ok || len(clean) == 0 {
		return false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	for _, e := range c.revoked {
		if e.SerialNumber != nil && e.SerialNumber.Cmp(want) == 0 {
			return true
		}
	}
	return false
}

// IssueCRL signs and returns a DER-encoded CRL valid for 24 hours from now.
func (c *CA) IssueCRL(now time.Time) ([]byte, error) {
	c.mu.RLock()
	entries := make([]x509.RevocationListEntry, len(c.revoked))
	copy(entries, c.revoked)
	c.mu.RUnlock()

	tmpl := &x509.RevocationList{
		Number:                    big.NewInt(now.UnixMilli()),
		ThisUpdate:                now,
		NextUpdate:                now.Add(24 * time.Hour),
		RevokedCertificateEntries: entries,
	}
	return x509.CreateRevocationList(rand.Reader, tmpl, c.cert, c.key)
}

// saveCRLLocked persists c.revoked to c.crlFile. Must be called with c.mu held.
func (c *CA) saveCRLLocked() error {
	entries := make([]crlEntry, len(c.revoked))
	for i, r := range c.revoked {
		entries[i] = crlEntry{SerialHex: r.SerialNumber.Text(16), RevokedAt: r.RevocationTime}
	}
	data, err := json.Marshal(entries)
	if err != nil {
		return err
	}
	return os.WriteFile(c.crlFile, data, 0o600)
}

// Fingerprint returns the SHA-256 fingerprint of the CA certificate in
// "sha256:HEXHEX..." format — the value passed as --ca-pin to the agent.
func (c *CA) Fingerprint() string {
	h := sha256.Sum256(c.cert.Raw)
	return "sha256:" + hex.EncodeToString(h[:])
}

// Sign returns an Ed25519 signature over msg using the CA private key. It lets the
// control-plane authenticate out-of-band artifacts (e.g. signed update manifests)
// that agents verify with the CA public key they pinned at enrollment — no extra
// key to distribute.
func (c *CA) Sign(msg []byte) []byte {
	return ed25519.Sign(c.key, msg)
}

// CertPEM returns a copy of the CA certificate PEM — the trust anchor shipped to
// agents to pin.
func (c *CA) CertPEM() []byte {
	out := make([]byte, len(c.certPEM))
	copy(out, c.certPEM)
	return out
}

// IssuedCert bundles the PEM-encoded certificate with its serial number (hex),
// allowing callers to record the serial for later revocation.
type IssuedCert struct {
	PEM       []byte // PEM-encoded certificate
	SerialHex string // hex representation of the certificate serial number
}

// SignClientCSR verifies a CSR (proof-of-possession + key-strength policy) and
// signs a client certificate bound to the profile, valid for ttl from now.
//
// When a CRL URL was set via SetCRLURL, the certificate includes a CRL
// distribution point so clients can check revocation status.
func (c *CA) SignClientCSR(csr *x509.CertificateRequest, p CertProfile, ttl time.Duration, now time.Time) ([]byte, error) {
	issued, err := c.SignClientCSRIssued(csr, p, ttl, now)
	if err != nil {
		return nil, err
	}
	return issued.PEM, nil
}

// SignClientCSRIssued is like SignClientCSR but returns the full IssuedCert so
// callers can record the serial for later revocation.
func (c *CA) SignClientCSRIssued(csr *x509.CertificateRequest, p CertProfile, ttl time.Duration, now time.Time) (IssuedCert, error) {
	if csr == nil {
		return IssuedCert{}, errors.New("CSR nulo")
	}
	if err := csr.CheckSignature(); err != nil {
		return IssuedCert{}, fmt.Errorf("assinatura do CSR inválida (proof-of-possession): %w", err)
	}
	if err := allowedKey(csr.PublicKey); err != nil {
		return IssuedCert{}, err
	}
	if p.CommonName == "" {
		return IssuedCert{}, errors.New("CommonName (agent id) obrigatório")
	}
	if ttl <= 0 {
		return IssuedCert{}, errors.New("ttl do certificado deve ser positivo")
	}
	serial, err := randSerial()
	if err != nil {
		return IssuedCert{}, err
	}
	c.mu.RLock()
	crlURL := c.crlURL
	c.mu.RUnlock()

	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               subject(p),
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(ttl),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	if crlURL != "" {
		tmpl.CRLDistributionPoints = []string{crlURL}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, csr.PublicKey, c.key)
	if err != nil {
		return IssuedCert{}, err
	}
	return IssuedCert{
		PEM:       pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		SerialHex: serial.Text(16),
	}, nil
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
