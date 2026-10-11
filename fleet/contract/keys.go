package contract

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
)

// GoldenTestKeySeedText derives the PUBLIC golden test key of ADR-0011: Ed25519 seed = SHA-256 of this ASCII
// text. It signs the golden vectors and the schema examples — never production. The connector refuses to pin
// it (IsGoldenTestKey) and the hub must never sign with it.
const GoldenTestKeySeedText = "suricatoos-fleet-command-v1/golden-test-key"

var goldenTestPublicKey = func() ed25519.PublicKey {
	seed := sha256.Sum256([]byte(GoldenTestKeySeedText))
	return ed25519.NewKeyFromSeed(seed[:]).Public().(ed25519.PublicKey)
}()

// GoldenTestPublicKey returns (a copy of) the golden test public key.
func GoldenTestPublicKey() ed25519.PublicKey {
	return bytes.Clone(goldenTestPublicKey)
}

// IsGoldenTestKey reports whether pub is the public golden test key, which a node must never pin.
func IsGoldenTestKey(pub ed25519.PublicKey) bool {
	return len(pub) == ed25519.PublicKeySize && bytes.Equal(pub, goldenTestPublicKey)
}

// CAPin is the pin of a DER structure: "sha256:" + lowercase hex SHA-256 (the format of the control-plane CA
// Fingerprint and of fleet-command.schema.json#/$defs/pin). FLEET_CA_PIN is CAPin of the fleet CA certificate.
func CAPin(der []byte) string {
	sum := sha256.Sum256(der)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// KeyPin is the pin of a command key: CAPin of its SubjectPublicKeyInfo DER (FLEET_COMMAND_KEY_PIN).
func KeyPin(pub ed25519.PublicKey) (string, error) {
	if len(pub) != ed25519.PublicKeySize {
		return "", ErrInvalidPublicKey
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	return CAPin(der), nil
}

// MarshalPublicKeyPEM renders a command key as PKIX "PUBLIC KEY" PEM (control-plane/signkeys PublicPEM; the
// command_pubkey of the enroll response).
func MarshalPublicKeyPEM(pub ed25519.PublicKey) ([]byte, error) {
	if len(pub) != ed25519.PublicKeySize {
		return nil, ErrInvalidPublicKey
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}

// decodeOnePEM requires exactly one PEM block of the given type, without headers and with nothing but
// whitespace around it.
func decodeOnePEM(b []byte, typ string) ([]byte, error) {
	trimmed := bytes.TrimLeft(b, " \t\r\n")
	block, rest := pem.Decode(trimmed)
	if block == nil || !bytes.HasPrefix(trimmed, []byte("-----BEGIN ")) {
		return nil, fmt.Errorf("contract: PEM %s ausente", typ)
	}
	if block.Type != typ || len(block.Headers) != 0 {
		return nil, fmt.Errorf("contract: bloco PEM %q, esperado %s", block.Type, typ)
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("contract: dado depois do bloco PEM")
	}
	return block.Bytes, nil
}

// ParsePublicKeyPEM parses exactly one PKIX "PUBLIC KEY" PEM block holding an Ed25519 key.
func ParsePublicKeyPEM(b []byte) (ed25519.PublicKey, error) {
	der, err := decodeOnePEM(b, "PUBLIC KEY")
	if err != nil {
		return nil, err
	}
	k, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("contract: chave pública: %w", err)
	}
	pub, ok := k.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("contract: a chave pública não é Ed25519")
	}
	return pub, nil
}

// MarshalPrivateKeyPEM renders a command key as PKCS#8 "PRIVATE KEY" PEM (the control-plane/signkeys format).
func MarshalPrivateKeyPEM(priv ed25519.PrivateKey) ([]byte, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, errors.New("contract: chave privada Ed25519 inválida")
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// ParsePrivateKeyPEM parses exactly one PKCS#8 "PRIVATE KEY" PEM block holding an Ed25519 key.
func ParsePrivateKeyPEM(b []byte) (ed25519.PrivateKey, error) {
	der, err := decodeOnePEM(b, "PRIVATE KEY")
	if err != nil {
		return nil, err
	}
	k, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("contract: chave privada: %w", err)
	}
	priv, ok := k.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("contract: a chave privada não é Ed25519")
	}
	return priv, nil
}

// WritePrivateKeyFile writes priv as PKCS#8 PEM to a NEW file with mode 0600; it never overwrites an existing
// key (O_EXCL), and removes a partial file on failure.
func WritePrivateKeyFile(path string, priv ed25519.PrivateKey) (err error) {
	b, err := MarshalPrivateKeyPEM(priv)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("contract: criar %s: %w", path, err)
	}
	defer func() {
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			os.Remove(path)
		}
	}()
	if _, err = f.Write(b); err != nil {
		return err
	}
	return f.Sync()
}

// ReadPrivateKeyFile reads a key written by WritePrivateKeyFile (or by control-plane/signkeys).
func ReadPrivateKeyFile(path string) (ed25519.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("contract: ler %s: %w", path, err)
	}
	return ParsePrivateKeyPEM(b)
}
