package enroll

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// testCA is a throwaway stdlib CA standing in for the control plane.
type testCA struct {
	cert *x509.Certificate
	key  ed25519.PrivateKey
	pem  []byte
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return &testCA{cert: cert, key: priv, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

func (c *testCA) signClient(t *testing.T, csr *x509.CertificateRequest) []byte {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      csr.Subject,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, csr.PublicKey, c.key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func (c *testCA) signServer(t *testing.T, ip string) tls.Certificate {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "test-server"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP(ip)},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, pub, c.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}
}

// signedEnrollServer is an https enroll endpoint that signs CSRs with the given
// CA and returns caPEM as ca_cert.
func signedEnrollServer(t *testing.T, signer *testCA, caPEM []byte) *httptest.Server {
	t.Helper()
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req request
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		block, _ := pem.Decode([]byte(req.CSR))
		csr, err := x509.ParseCertificateRequest(block.Bytes)
		if err != nil || csr.CheckSignature() != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(response{
			Certificate: string(signer.signClient(t, csr)),
			CACert:      string(caPEM),
			IngestURL:   testIngestURL,
		})
	}))
}

// testIngestURL is the ingest endpoint the mock enroll server hands back.
const testIngestURL = "https://scanner.suricatoos.com/ingest/v1/inventory"

func TestGenerateCSRValid(t *testing.T) {
	csrPEM, key, err := GenerateCSR("agent-x")
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(csrPEM)
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Fatalf("CSR PoP inválido: %v", err)
	}
	if csr.Subject.CommonName != "agent-x" {
		t.Fatalf("CN=%q", csr.Subject.CommonName)
	}
	if !key.Public().(ed25519.PublicKey).Equal(csr.PublicKey) {
		t.Fatal("chave pública do CSR != chave gerada")
	}
}

func TestEnrollRequiresHTTPS(t *testing.T) {
	_, err := Enroll(context.Background(), &http.Client{}, "http://127.0.0.1:1", "st_a.b", "agent", "")
	if err == nil || !strings.Contains(err.Error(), "https") {
		t.Fatalf("esperava recusa de http://, got %v", err)
	}
}

// TestEnrollAndMTLSEndToEnd prova o fluxo completo: o agente gera CSR, troca por
// um cert via HTTPS, verifica a cadeia, e usa o cert num handshake mTLS mútuo real.
func TestEnrollAndMTLSEndToEnd(t *testing.T) {
	authority := newTestCA(t)
	enrollSrv := signedEnrollServer(t, authority, authority.pem)
	defer enrollSrv.Close()

	id, err := Enroll(context.Background(), enrollSrv.Client(), enrollSrv.URL, "st_dummy.secret", "agent-e2e", "")
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	if id.PrivateKey == nil || len(id.CertPEM) == 0 || len(id.CACertPEM) == 0 {
		t.Fatal("identidade incompleta")
	}
	if id.IngestURL != testIngestURL {
		t.Errorf("ingest_url não propagado do enroll: got %q, want %q", id.IngestURL, testIngestURL)
	}

	cfg, err := id.TLSClientConfig()
	if err != nil {
		t.Fatal(err)
	}

	clientPool := x509.NewCertPool()
	if !clientPool.AppendCertsFromPEM(authority.pem) {
		t.Fatal("falha no pool de CA")
	}
	mtls := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(r.TLS.PeerCertificates) == 0 {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = io.WriteString(w, r.TLS.PeerCertificates[0].Subject.CommonName)
	}))
	mtls.TLS = &tls.Config{
		Certificates: []tls.Certificate{authority.signServer(t, "127.0.0.1")},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientPool,
		MinVersion:   tls.VersionTLS13,
	}
	mtls.StartTLS()
	defer mtls.Close()

	hc := &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}}
	resp, err := hc.Get(mtls.URL)
	if err != nil {
		t.Fatalf("handshake mTLS falhou (client cert recusado?): %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(body) != "agent-e2e" {
		t.Fatalf("status=%d body=%q (esperava CN agent-e2e)", resp.StatusCode, body)
	}
}

func TestEnrollRejectsCertNotChainingToReturnedCA(t *testing.T) {
	signer := newTestCA(t)
	other := newTestCA(t)
	// assina com `signer` mas devolve a CA `other` -> o leaf não encadeia
	srv := signedEnrollServer(t, signer, other.pem)
	defer srv.Close()
	if _, err := Enroll(context.Background(), srv.Client(), srv.URL, "st_a.b", "agent", ""); err == nil {
		t.Fatal("deveria rejeitar cert que não encadeia na CA retornada")
	}
}

func TestEnrollFingerprintPinMismatch(t *testing.T) {
	authority := newTestCA(t)
	srv := signedEnrollServer(t, authority, authority.pem)
	defer srv.Close()
	if _, err := Enroll(context.Background(), srv.Client(), srv.URL, "st_a.b", "agent", "deadbeef"); err == nil {
		t.Fatal("pin de fingerprint errado deve falhar")
	}
}

func TestSaveLoadRoundTripAndKeyPerm(t *testing.T) {
	authority := newTestCA(t)
	csrPEM, key, err := GenerateCSR("agent-sl")
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(csrPEM)
	csr, _ := x509.ParseCertificateRequest(block.Bytes)
	id := &Identity{PrivateKey: key, CertPEM: authority.signClient(t, csr), CACertPEM: authority.pem}

	dir := t.TempDir()
	// pré-cria a chave com modo frouxo para provar que Save força 0600
	if runtime.GOOS != "windows" {
		if err := os.WriteFile(filepath.Join(dir, "agent.key"), []byte("velho"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := Save(dir, id); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(filepath.Join(dir, "agent.key"))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("perm da chave = %v, want 0600", info.Mode().Perm())
		}
	}
	loaded, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !loaded.PrivateKey.Equal(id.PrivateKey) {
		t.Fatal("chave não confere após Load")
	}
	if _, err := loaded.TLSClientConfig(); err != nil {
		t.Fatalf("identidade carregada inutilizável: %v", err)
	}
}

func TestSaveLoadIngestURL(t *testing.T) {
	authority := newTestCA(t)
	csrPEM, key, err := GenerateCSR("agent-iu")
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(csrPEM)
	csr, _ := x509.ParseCertificateRequest(block.Bytes)
	base := &Identity{PrivateKey: key, CertPEM: authority.signClient(t, csr), CACertPEM: authority.pem}

	// With an ingest URL → persisted to ingest.url and reloaded.
	withURL := *base
	withURL.IngestURL = "https://scanner.suricatoos.com/ingest/v1/inventory"
	dir := t.TempDir()
	if err := Save(dir, &withURL); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.IngestURL != withURL.IngestURL {
		t.Errorf("ingest url = %q, want %q", loaded.IngestURL, withURL.IngestURL)
	}

	// Without an ingest URL → no file written; Load leaves it empty (backward
	// compatible with identities enrolled before this field existed).
	dir2 := t.TempDir()
	if err := Save(dir2, base); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir2, "ingest.url")); !os.IsNotExist(err) {
		t.Errorf("ingest.url não deve existir quando IngestURL vazio (err=%v)", err)
	}
	loaded2, err := Load(dir2)
	if err != nil {
		t.Fatal(err)
	}
	if loaded2.IngestURL != "" {
		t.Errorf("ingest url = %q, want vazio", loaded2.IngestURL)
	}
}
