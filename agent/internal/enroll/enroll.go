package enroll

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// Identity is the agent's enrolled identity. PrivateKey never leaves the host.
type Identity struct {
	PrivateKey ed25519.PrivateKey
	CertPEM    []byte
	CACertPEM  []byte
	// IngestURL is where the agent reports inventory, learned from the
	// enrollment response so `run`/`install` need no separate --ingest flag.
	IngestURL string
	// ServerURL is the control-plane base URL (the --server passed at enroll,
	// ending in /v1). Persisted so the daemon can poll for signed update
	// manifests without a separate flag. Empty for pre-update enrollments.
	ServerURL string
}

// AgentID returns the agent's logical identity — the CommonName of its enrolled
// certificate (the value the control-plane signed, from --agent-id or the
// hostname at enroll time). Empty if the cert can't be parsed.
func (id *Identity) AgentID() string {
	block, _ := pem.Decode(id.CertPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return ""
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return ""
	}
	return cert.Subject.CommonName
}

// CAPublicKey returns the enrollment CA's Ed25519 public key, parsed from the
// pinned CA certificate. It is the trust anchor used to verify CA-signed
// artifacts (e.g. update manifests) the agent receives over untrusted channels.
func (id *Identity) CAPublicKey() (ed25519.PublicKey, error) {
	block, _ := pem.Decode(id.CACertPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("CA PEM inválido")
	}
	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	pub, ok := caCert.PublicKey.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("CA não usa chave Ed25519")
	}
	return pub, nil
}

// GenerateCSR creates a fresh Ed25519 keypair and a CSR for agentID. It returns
// the CSR PEM and the private key (kept by the caller; never transmitted).
func GenerateCSR(agentID string) (csrPEM []byte, key ed25519.PrivateKey, err error) {
	_, key, err = ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: agentID},
	}, key)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), key, nil
}

type request struct {
	Token   string `json:"token"`
	CSR     string `json:"csr"`
	AgentID string `json:"agent_id"`
	OS      string `json:"os"`
	Arch    string `json:"arch"`
}

type response struct {
	Certificate string `json:"certificate"`
	CACert      string `json:"ca_cert"`
	IngestURL   string `json:"ingest_url"`
}

// Enroll runs the full flow: generate key+CSR, POST to baseURL/enroll with the
// bootstrap token, verify the issued identity, and return it. The key stays local.
//
// Security: baseURL MUST be https (the token and the trust anchor travel here);
// cross-scheme redirects are refused. If caFingerprint (hex SHA-256 of the CA
// cert, optionally colon-separated) is non-empty, the returned CA is checked
// against it — corroborating the in-band trust anchor with an out-of-band pin.
func Enroll(ctx context.Context, hc *http.Client, baseURL, token, agentID, caFingerprint string) (*Identity, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("URL do control plane inválida: %w", err)
	}
	if u.Scheme != "https" {
		return nil, fmt.Errorf("control plane deve ser https:// (esquema %q recusado) — token e CA não podem trafegar em claro", u.Scheme)
	}
	if hc.CheckRedirect == nil {
		hc.CheckRedirect = func(r *http.Request, _ []*http.Request) error {
			if r.URL.Scheme != "https" {
				return errors.New("redirect para esquema não-https recusado (anti-downgrade)")
			}
			return nil
		}
	}

	csrPEM, key, err := GenerateCSR(agentID)
	if err != nil {
		return nil, err
	}
	body, err := json.Marshal(request{
		Token: token, CSR: string(csrPEM), AgentID: agentID, OS: runtime.GOOS, Arch: runtime.GOARCH,
	})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSuffix(baseURL, "/")+"/enroll", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("enrollment recusado (%d): %s", resp.StatusCode, bytes.TrimSpace(data))
	}
	var er response
	if err := json.Unmarshal(data, &er); err != nil {
		return nil, fmt.Errorf("resposta de enrollment inválida: %w", err)
	}
	id := &Identity{
		PrivateKey: key,
		CertPEM:    []byte(er.Certificate),
		CACertPEM:  []byte(er.CACert),
		IngestURL:  er.IngestURL,
		ServerURL:  strings.TrimSuffix(baseURL, "/"),
	}
	if err := id.verify(caFingerprint); err != nil {
		return nil, fmt.Errorf("identidade recebida inválida: %w", err)
	}
	return id, nil
}

// verify confirms the returned CA matches the optional pin, the leaf chains to
// that CA (ClientAuth), and the leaf's public key matches our private key.
func (id *Identity) verify(caFingerprint string) error {
	caBlock, _ := pem.Decode(id.CACertPEM)
	if caBlock == nil || caBlock.Type != "CERTIFICATE" {
		return errors.New("CA PEM inválido")
	}
	if caFingerprint != "" {
		sum := sha256.Sum256(caBlock.Bytes)
		want := normalizeFingerprint(caFingerprint)
		if !strings.EqualFold(hex.EncodeToString(sum[:]), want) {
			return errors.New("fingerprint da CA não confere com o pin esperado")
		}
	}
	leafBlock, _ := pem.Decode(id.CertPEM)
	if leafBlock == nil || leafBlock.Type != "CERTIFICATE" {
		return errors.New("certificado do agente inválido")
	}
	leaf, err := x509.ParseCertificate(leafBlock.Bytes)
	if err != nil {
		return err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(id.CACertPEM) {
		return errors.New("CA pinada inválida")
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		return fmt.Errorf("cert não encadeia na CA pinada: %w", err)
	}
	leafPub, ok := leaf.PublicKey.(ed25519.PublicKey)
	if !ok || !leafPub.Equal(id.PrivateKey.Public()) {
		return errors.New("cert não corresponde à chave privada do agente")
	}
	return nil
}

// normalizeFingerprint reduces a CA fingerprint pin to bare hex for comparison,
// accepting the forms the control-plane and openssl emit:
//
//	"sha256:efe7…"          enrollment bundle ca_pin (control-plane Fingerprint)
//	"efe7…"                 bare hex
//	"EF:E7:…" / "ef e7 …"   colon/space separated hex
//
// The leading "sha256:" algorithm label MUST be stripped first: without it the
// generic ":" removal left the literal "sha256" glued to the hex, so a bundle
// pin never matched the computed digest and --ca-pin always failed.
func normalizeFingerprint(fp string) string {
	fp = strings.TrimSpace(fp)
	if i := strings.IndexByte(fp, ':'); i >= 0 && strings.EqualFold(fp[:i], "sha256") {
		fp = fp[i+1:]
	}
	fp = strings.ReplaceAll(fp, ":", "")
	fp = strings.ReplaceAll(fp, " ", "")
	return fp
}

// TLSClientConfig builds an mTLS client config presenting the agent's client
// certificate. The SERVER is verified against the system trust store (the ingest
// is fronted by a public TLS cert, e.g. Let's Encrypt) — NOT against the
// enrollment CA. The enrollment CA is the trust anchor the SERVER uses to verify
// the agent's CLIENT cert (mTLS); using it as the client's RootCAs made the agent
// reject the public server cert ("unable to get local issuer certificate") and no
// inventory ever reached the ingest.
func (id *Identity) TLSClientConfig() (*tls.Config, error) {
	block, _ := pem.Decode(id.CertPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("certificado do agente inválido")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{block.Bytes},
			PrivateKey:  id.PrivateKey,
			Leaf:        leaf,
		}},
		// RootCAs nil → system trust store verifies the (public) server cert.
		MinVersion: tls.VersionTLS13,
	}, nil
}

// Save writes the identity to dir: agent.key (0600), agent.crt and ca.crt (0644).
// The key mode is enforced even if the file pre-existed with looser permissions.
func Save(dir string, id *Identity) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(id.PrivateKey)
	if err != nil {
		return err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	keyPath := filepath.Join(dir, "agent.key")
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return err
	}
	if err := os.Chmod(keyPath, 0o600); err != nil { // garante 0600 mesmo se o arquivo pré-existia
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "agent.crt"), id.CertPEM, 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "ca.crt"), id.CACertPEM, 0o644); err != nil {
		return err
	}
	// ingest.url is optional: only written when the control-plane supplied one.
	if id.IngestURL != "" {
		if err := os.WriteFile(filepath.Join(dir, "ingest.url"), []byte(id.IngestURL), 0o644); err != nil {
			return err
		}
	}
	// server.url is the control-plane base URL, used by the daemon to poll for
	// signed update manifests. Optional (absent for pre-update enrollments).
	if id.ServerURL != "" {
		if err := os.WriteFile(filepath.Join(dir, "server.url"), []byte(id.ServerURL), 0o644); err != nil {
			return err
		}
	}
	return nil
}

// Load reads an identity previously written by Save.
func Load(dir string) (*Identity, error) {
	keyPEM, err := os.ReadFile(filepath.Join(dir, "agent.key"))
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, errors.New("chave do agente inválida")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	edKey, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("chave do agente não é Ed25519")
	}
	certPEM, err := os.ReadFile(filepath.Join(dir, "agent.crt"))
	if err != nil {
		return nil, err
	}
	caPEM, err := os.ReadFile(filepath.Join(dir, "ca.crt"))
	if err != nil {
		return nil, err
	}
	id := &Identity{PrivateKey: edKey, CertPEM: certPEM, CACertPEM: caPEM}
	// ingest.url is optional (absent for pre-existing enrollments).
	if b, err := os.ReadFile(filepath.Join(dir, "ingest.url")); err == nil {
		id.IngestURL = strings.TrimSpace(string(b))
	}
	// server.url is optional (absent for pre-update enrollments).
	if b, err := os.ReadFile(filepath.Join(dir, "server.url")); err == nil {
		id.ServerURL = strings.TrimSpace(string(b))
	}
	return id, nil
}
