package renew

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// makeCert writes a self-signed leaf cert (CN) valid for `dur` + a key, returning
// their paths. Stands in for the sensor's enrolled material.
func makeCert(t *testing.T, dir, cn string, dur time.Duration) (certFile, keyFile string) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(dur),
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	certFile = filepath.Join(dir, "sensor.crt")
	keyFile = filepath.Join(dir, "sensor.key")
	os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
	kb, _ := x509.MarshalECPrivateKey(key)
	os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600)
	return certFile, keyFile
}

func TestDueSoon(t *testing.T) {
	dir := t.TempDir()
	// cert expira em 3 dias, RenewBefore 7 dias → vencido em breve.
	certFile, keyFile := makeCert(t, dir, "sensor-acme-1", 3*24*time.Hour)
	r := New(Config{CertFile: certFile, KeyFile: keyFile, RenewBefore: 7 * 24 * time.Hour})
	if !r.DueSoon() {
		t.Fatal("cert expirando em 3d com RenewBefore 7d deveria estar due")
	}
	// cert com 90 dias → não vencido.
	certFile2, keyFile2 := makeCert(t, dir, "sensor-acme-1", 90*24*time.Hour)
	r2 := New(Config{CertFile: certFile2, KeyFile: keyFile2, RenewBefore: 7 * 24 * time.Hour})
	if r2.DueSoon() {
		t.Fatal("cert com 90d de vida não deveria estar due")
	}
}

func TestRenewIfDueRotates(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := makeCert(t, dir, "sensor-acme-1", time.Hour) // due (RenewBefore default 7d)
	caFile := filepath.Join(dir, "ca.crt")
	os.WriteFile(caFile, []byte("CA-PEM-STUB"), 0o644)

	var gotCSRCN string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var req renewReq
		json.Unmarshal(b, &req)
		// Verifica o CSR recebido: CN preservado + assinatura válida.
		block, _ := pem.Decode([]byte(req.CSR))
		csr, err := x509.ParseCertificateRequest(block.Bytes)
		if err != nil || csr.CheckSignature() != nil {
			http.Error(w, "csr ruim", 400)
			return
		}
		gotCSRCN = csr.Subject.CommonName
		json.NewEncoder(w).Encode(renewResp{Certificate: "NEW-CERT-PEM", CACert: "NEW-CA-PEM"})
	}))
	defer srv.Close()

	r := New(Config{RenewURL: srv.URL, CertFile: certFile, KeyFile: keyFile, CAFile: caFile})
	// Sobrescreve o mtls client p/ usar o do test server (o cert self-signed não
	// casa a CA do server; o teste foca na lógica de rotação, não no handshake).
	r2 := &Renewer{cfg: r.cfg, now: time.Now}
	rotated, err := r2.renewWith(context.Background(), srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	if !rotated {
		t.Fatal("deveria ter rotacionado")
	}
	if gotCSRCN != "sensor-acme-1" {
		t.Fatalf("CSR deveria preservar o CN, got %q", gotCSRCN)
	}
	// Novo cert/key gravados atomicamente.
	nc, _ := os.ReadFile(certFile)
	if string(nc) != "NEW-CERT-PEM\n" && string(nc) != "NEW-CERT-PEM" {
		t.Fatalf("cert não foi trocado: %q", nc)
	}
}

func TestRenewIfDueNoopWhenFresh(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := makeCert(t, dir, "sensor-acme-1", 90*24*time.Hour)
	r := New(Config{RenewURL: "http://nao-chamado", CertFile: certFile, KeyFile: keyFile})
	rotated, err := r.RenewIfDue(context.Background())
	if err != nil || rotated {
		t.Fatalf("cert fresco: não deveria rotacionar nem erro, got rotated=%v err=%v", rotated, err)
	}
}
