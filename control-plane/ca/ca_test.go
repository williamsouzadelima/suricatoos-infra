package ca

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"testing"
	"time"
)

func testCSR(t *testing.T, cn string) *x509.CertificateRequest {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}}, priv)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatal(err)
	}
	return csr
}

func TestSignClientCSRChainsToCAWithScope(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	c, err := NewEphemeral(now)
	if err != nil {
		t.Fatal(err)
	}
	certPEM, err := c.SignClientCSR(testCSR(t, "agent-123"),
		CertProfile{CommonName: "agent-123", Org: "acme", OrgUnit: "default"}, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(certPEM)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if cert.Subject.CommonName != "agent-123" {
		t.Fatalf("CN=%q", cert.Subject.CommonName)
	}
	if len(cert.Subject.Organization) != 1 || cert.Subject.Organization[0] != "acme" {
		t.Fatalf("org=%v", cert.Subject.Organization)
	}
	if cert.IsCA {
		t.Fatal("cert de cliente não pode ser CA")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(c.CertPEM()) {
		t.Fatal("CA PEM inválido")
	}
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:       roots,
		CurrentTime: now,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		t.Fatalf("cert não encadeia na CA: %v", err)
	}
}

func TestSignRejectsTamperedCSR(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	c, _ := NewEphemeral(now)
	csr := testCSR(t, "agent-x")
	csr.Signature[0] ^= 0xff // corrompe a prova de posse
	if _, err := c.SignClientCSR(csr, CertProfile{CommonName: "agent-x"}, time.Hour, now); err == nil {
		t.Fatal("CSR adulterado deve ser rejeitado (PoP)")
	}
}

func TestSignRejectsWeakRSAKey(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	c, _ := NewEphemeral(now)
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "weak"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	csr, _ := x509.ParseCertificateRequest(der)
	if _, err := c.SignClientCSR(csr, CertProfile{CommonName: "weak"}, time.Hour, now); err == nil {
		t.Fatal("chave RSA de 1024 bits deve ser rejeitada pela política de força")
	}
}

func TestSerialsAreUnique(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	c, _ := NewEphemeral(now)
	parse := func() string {
		certPEM, err := c.SignClientCSR(testCSR(t, "a"), CertProfile{CommonName: "a"}, time.Hour, now)
		if err != nil {
			t.Fatal(err)
		}
		block, _ := pem.Decode(certPEM)
		cert, _ := x509.ParseCertificate(block.Bytes)
		return cert.SerialNumber.String()
	}
	if parse() == parse() {
		t.Fatal("seriais devem ser únicos")
	}
}
