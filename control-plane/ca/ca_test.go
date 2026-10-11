package ca

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"os"
	"path/filepath"
	"runtime"
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

func TestNewPersistent_GeneratesAndLoads(t *testing.T) {
	dir := t.TempDir()
	certFile := dir + "/ca.crt"
	keyFile := dir + "/ca.key"
	now := time.Unix(1700000000, 0).UTC()

	// First call: generate and save.
	ca1, err := NewPersistent(certFile, keyFile, now)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	fp1 := ca1.Fingerprint()

	// Second call: load from disk — must yield the same fingerprint.
	ca2, err := NewPersistent(certFile, keyFile, now)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if ca2.Fingerprint() != fp1 {
		t.Error("fingerprint changed after reload — CA key mismatch")
	}

	// The loaded CA must still be able to issue valid client certs.
	certPEM, err := ca2.SignClientCSR(testCSR(t, "agent-reload"), CertProfile{CommonName: "agent-reload", Org: "acme"}, time.Hour, now)
	if err != nil {
		t.Fatalf("SignClientCSR after reload: %v", err)
	}
	block, _ := pem.Decode(certPEM)
	cert, _ := x509.ParseCertificate(block.Bytes)
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(ca2.CertPEM())
	if _, err := cert.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Fatalf("cert from reloaded CA: %v", err)
	}
}

func TestNewPersistent_InconsistentState(t *testing.T) {
	dir := t.TempDir()
	certFile := dir + "/ca.crt"
	keyFile := dir + "/ca.key"
	now := time.Now()

	// Create only the cert file, not the key — inconsistent.
	if err := os.WriteFile(certFile, []byte("dummy"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := NewPersistent(certFile, keyFile, now); err == nil {
		t.Error("expected error for inconsistent CA state (only cert present)")
	}
}

func TestCRLDistributionPoint(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	c, _ := NewEphemeral(now)
	c.SetCRLURL("https://cp.example.com/v1/crl.der")

	issued, err := c.SignClientCSRIssued(testCSR(t, "agent-crl"), CertProfile{CommonName: "agent-crl", Org: "acme"}, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(issued.PEM)
	cert, _ := x509.ParseCertificate(block.Bytes)
	if len(cert.CRLDistributionPoints) != 1 || cert.CRLDistributionPoints[0] != "https://cp.example.com/v1/crl.der" {
		t.Fatalf("CRLDistributionPoints = %v", cert.CRLDistributionPoints)
	}
	if issued.SerialHex == "" {
		t.Fatal("SerialHex must be non-empty")
	}
}

func TestIssueCRL_RevokeAndVerify(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	c, _ := NewEphemeral(now)

	issued, err := c.SignClientCSRIssued(testCSR(t, "agent-rev"), CertProfile{CommonName: "agent-rev", Org: "acme"}, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.RevokeCertSerial(issued.SerialHex, now); err != nil {
		t.Fatalf("RevokeCertSerial: %v", err)
	}

	crlDER, err := c.IssueCRL(now)
	if err != nil {
		t.Fatalf("IssueCRL: %v", err)
	}
	crl, err := x509.ParseRevocationList(crlDER)
	if err != nil {
		t.Fatalf("ParseRevocationList: %v", err)
	}
	if err := crl.CheckSignatureFrom(c.cert); err != nil {
		t.Fatalf("CRL signature invalid: %v", err)
	}
	if len(crl.RevokedCertificateEntries) != 1 {
		t.Fatalf("want 1 revoked entry, got %d", len(crl.RevokedCertificateEntries))
	}
	if crl.RevokedCertificateEntries[0].SerialNumber.Text(16) != issued.SerialHex {
		t.Errorf("serial mismatch in CRL")
	}
}

func TestCRLFile_PersistsAndLoads(t *testing.T) {
	dir := t.TempDir()
	crlPath := dir + "/revoked.json"
	now := time.Unix(1700000000, 0).UTC()

	c1, _ := NewEphemeral(now)
	if err := c1.LoadCRLFile(crlPath); err != nil {
		t.Fatal(err)
	}
	issued, _ := c1.SignClientCSRIssued(testCSR(t, "x"), CertProfile{CommonName: "x"}, time.Hour, now)
	if err := c1.RevokeCertSerial(issued.SerialHex, now); err != nil {
		t.Fatal(err)
	}

	// Reload CA state from same cert/key (simulating restart): revocations must survive.
	c2, _ := NewEphemeral(now)
	if err := c2.LoadCRLFile(crlPath); err != nil {
		t.Fatal(err)
	}
	crlDER, _ := c2.IssueCRL(now)
	crl, _ := x509.ParseRevocationList(crlDER)
	if len(crl.RevokedCertificateEntries) != 1 {
		t.Fatalf("revocations must survive CRL file reload, got %d entries", len(crl.RevokedCertificateEntries))
	}
}

// The CRL file is replaced (temp file in the same directory + rename), never rewritten
// in place: a crash or a full disk in the middle of a save must leave the previous
// list. LoadCRLFile refuses a truncated file, and main treats that as fatal at boot.
func TestCRLFileIsReplacedAtomically(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "crl.json")
	now := time.Unix(1700000000, 0).UTC()
	c, _ := NewEphemeral(now)
	if err := c.LoadCRLFile(path); err != nil {
		t.Fatal(err)
	}
	if err := c.RevokeCertSerial("0a1b", now); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatalf("CRL file not written: %v", err)
	}
	// On Windows os.Stat records only the path and SameFile resolves the file id
	// lazily; resolve it now, while the path still names the first file.
	_ = os.SameFile(before, before)

	if err := c.RevokeCertSerial("0c1d", now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if os.SameFile(before, after) {
		t.Fatal("the CRL file was rewritten in place; want a complete new file renamed over it")
	}

	// The final file is complete: a fresh CA (a restart) loads both revocations.
	c2, _ := NewEphemeral(now)
	if err := c2.LoadCRLFile(path); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if !c2.IsRevoked("0a1b") || !c2.IsRevoked("0c1d") {
		t.Fatal("a revocation was lost across the reload")
	}
	// Nothing is left next to it, and it is private.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "crl.json" {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("directory holds %v, want only crl.json (no temp file left behind)", names)
	}
	if runtime.GOOS != "windows" {
		if perm := after.Mode().Perm(); perm != 0o600 {
			t.Fatalf("CRL file mode = %o, want 600", perm)
		}
	}
}

// A save that fails is reported, and the file already on disk is left untouched.
// The new serial stays revoked in memory: the CA keeps blocking it (IsRevoked, the
// served CRL) until a restart; the caller decides how to report the lost persistence.
func TestCRLFileSaveFailureKeepsThePreviousFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "crl.json")
	now := time.Unix(1700000000, 0).UTC()
	c, _ := NewEphemeral(now)
	if err := c.LoadCRLFile(path); err != nil {
		t.Fatal(err)
	}
	if err := c.RevokeCertSerial("0a1b", now); err != nil {
		t.Fatal(err)
	}
	good, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// The temp name is taken by a non-empty directory: the save cannot even start.
	if err := os.MkdirAll(filepath.Join(path+".tmp", "busy"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := c.RevokeCertSerial("0c1d", now); err == nil {
		t.Fatal("RevokeCertSerial must report a save that failed")
	}
	if got, _ := os.ReadFile(path); !bytes.Equal(got, good) {
		t.Fatalf("a failed save changed the file on disk:\nbefore %s\nafter  %s", good, got)
	}
	if !c.IsRevoked("0c1d") {
		t.Fatal("the serial must stay revoked in memory after a failed save")
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

func TestIsRevoked(t *testing.T) {
	now := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	c, _ := NewEphemeral(now)
	if c.IsRevoked("0a1b2c") {
		t.Fatal("serial não revogado não deveria ser revogado")
	}
	if err := c.RevokeCertSerial("0a1b2c", now); err != nil {
		t.Fatal(err)
	}
	// Match tolerante a colons/uppercase/leading zeros (como o nginx encaminha).
	for _, s := range []string{"0a1b2c", "0A:1B:2C", "00A1B2C", "0x0a1b2c"} {
		if !c.IsRevoked(s) {
			t.Errorf("serial revogado %q deveria bater", s)
		}
	}
	if c.IsRevoked("deadbeef") || c.IsRevoked("") || c.IsRevoked("naoehex") {
		t.Fatal("serial diferente/vazio/inválido não deveria ser revogado")
	}
}
