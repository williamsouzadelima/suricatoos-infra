package contract

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// TestGoldenTestKey: the key derived from the documented seed text is EXACTLY the ADR's (SPKI and pin), and
// IsGoldenTestKey recognizes it — the connector refuses to pin it (F2.6).
func TestGoldenTestKey(t *testing.T) {
	pub := GoldenTestPublicKey()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	if got := base64.StdEncoding.EncodeToString(der); got != adrPublicKeySPKI {
		t.Fatalf("SPKI da chave de teste %s != ADR %s", got, adrPublicKeySPKI)
	}
	pin, err := KeyPin(pub)
	if err != nil || pin != adrPin {
		t.Fatalf("pin %s (%v) != ADR %s", pin, err, adrPin)
	}
	if !pub.Equal(goldenPub) || !IsGoldenTestKey(goldenPub) {
		t.Fatal("chave de teste")
	}
	if IsGoldenTestKey(otherPriv.Public().(ed25519.PublicKey)) || IsGoldenTestKey(nil) || IsGoldenTestKey(goldenPub[:31]) {
		t.Fatal("IsGoldenTestKey aceita outra chave")
	}
	pub[0] ^= 0xff // GoldenTestPublicKey returns a copy
	if !IsGoldenTestKey(goldenPub) {
		t.Fatal("GoldenTestPublicKey deve devolver cópia")
	}
}

// TestPins: KeyPin = sha256 of the SPKI DER, CAPin = sha256 of the certificate DER, both "sha256:<hex>" (the
// format of the control-plane CA Fingerprint and of the schema's pin).
func TestPins(t *testing.T) {
	der := []byte("qualquer DER")
	sum := sha256.Sum256(der)
	if got := CAPin(der); got != "sha256:"+hex.EncodeToString(sum[:]) || !compiled(PatternPin).MatchString(got) {
		t.Fatalf("CAPin: %s", got)
	}
	if _, err := KeyPin(goldenPub[:31]); err == nil {
		t.Fatal("KeyPin de chave inválida")
	}
}

// TestPublicKeyPEM: PKIX "PUBLIC KEY" PEM, the format of control-plane/signkeys PublicPEM, parsed strictly.
func TestPublicKeyPEM(t *testing.T) {
	b, err := MarshalPublicKeyPEM(goldenPub)
	if err != nil {
		t.Fatal(err)
	}
	want := "-----BEGIN PUBLIC KEY-----\n" + adrPublicKeySPKI + "\n-----END PUBLIC KEY-----\n"
	if string(b) != want {
		t.Fatalf("PEM:\n%s", b)
	}
	pub, err := ParsePublicKeyPEM(b)
	if err != nil || !pub.Equal(goldenPub) {
		t.Fatalf("ida e volta: %v", err)
	}
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ecDER, _ := x509.MarshalPKIXPublicKey(&ec.PublicKey)
	privDER, _ := x509.MarshalPKCS8PrivateKey(goldenPriv)
	bad := map[string][]byte{
		"vazio":                nil,
		"lixo depois":          append(append([]byte{}, b...), "x"...),
		"dois blocos":          append(append([]byte{}, b...), b...),
		"tipo errado":          pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER}),
		"não é Ed25519":        pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: ecDER}),
		"com cabeçalhos":       pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Headers: map[string]string{"X": "y"}, Bytes: []byte{1}}),
		"DER inválido":         pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte{1, 2, 3}}),
		"texto antes do bloco": append([]byte("oi\n"), b...),
	}
	for name, in := range bad {
		if _, err := ParsePublicKeyPEM(in); err == nil {
			t.Errorf("%s: deveria falhar", name)
		}
	}
}

// TestPrivateKeyPEMAndFile: PKCS#8 "PRIVATE KEY" PEM written 0600 and never over an existing file (the
// control-plane/signkeys format).
func TestPrivateKeyPEMAndFile(t *testing.T) {
	b, err := MarshalPrivateKeyPEM(goldenPriv)
	if err != nil {
		t.Fatal(err)
	}
	priv, err := ParsePrivateKeyPEM(b)
	if err != nil || !priv.Equal(goldenPriv) {
		t.Fatalf("ida e volta: %v", err)
	}
	pubPEM, _ := MarshalPublicKeyPEM(goldenPub)
	if _, err := ParsePrivateKeyPEM(pubPEM); err == nil {
		t.Fatal("PEM de chave pública como privada")
	}
	path := filepath.Join(t.TempDir(), "command-key.pem")
	if err := WritePrivateKeyFile(path, goldenPriv); err != nil {
		t.Fatal(err)
	}
	if err := WritePrivateKeyFile(path, otherPriv); err == nil {
		t.Fatal("não pode sobrescrever chave existente")
	}
	got, err := ReadPrivateKeyFile(path)
	if err != nil || !got.Equal(goldenPriv) {
		t.Fatalf("leitura: %v", err)
	}
	if runtime.GOOS != "windows" {
		st, err := os.Stat(path)
		if err != nil || st.Mode().Perm() != 0o600 {
			t.Fatalf("permissão %v (%v), esperado 0600", st.Mode().Perm(), err)
		}
	}
	if _, err := ReadPrivateKeyFile(filepath.Join(t.TempDir(), "não-existe.pem")); err == nil {
		t.Fatal("arquivo inexistente")
	}
}
