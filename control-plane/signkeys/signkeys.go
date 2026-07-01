// Package signkeys manages purpose-scoped Ed25519 signing keys separate from the
// CA's cert-issuing key (ADR-0007 risk #3). Today ca.Sign uses the SAME key that
// issues every tenant cert, so a compromise of that key lets an attacker
// impersonate any tenant AND push a poisoned feed manifest AND push an RCE update.
// Splitting the feed-signing and update-signing keys out limits the blast radius:
// the feed/update verification public keys are distributed to agents/sensors at
// enroll (pinned), so they can rotate independently of the CA.
package signkeys

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

// Key is a persisted Ed25519 signing key for one purpose (feed or update).
type Key struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
}

// LoadOrCreate loads an Ed25519 private key (PKCS8 PEM) from path, generating and
// persisting a fresh one (0600) if the file is absent. An empty path yields an
// in-memory ephemeral key (dev/tests) — a warning is the caller's responsibility.
func LoadOrCreate(path string) (*Key, error) {
	if path == "" {
		return generate()
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			k, err := generate()
			if err != nil {
				return nil, err
			}
			if err := k.save(path); err != nil {
				return nil, err
			}
			return k, nil
		}
		return nil, fmt.Errorf("ler chave %s: %w", path, err)
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, fmt.Errorf("chave %s: PEM inválido", path)
	}
	iface, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("chave %s: %w", path, err)
	}
	priv, ok := iface.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("chave %s: não é Ed25519", path)
	}
	return &Key{priv: priv, pub: priv.Public().(ed25519.PublicKey)}, nil
}

func generate() (*Key, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Key{priv: priv, pub: pub}, nil
}

func (k *Key) save(path string) error {
	der, err := x509.MarshalPKCS8PrivateKey(k.priv)
	if err != nil {
		return err
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	return os.WriteFile(path, pemBytes, 0o600)
}

// Sign signs msg (satisfies the feed/update Signer interfaces).
func (k *Key) Sign(msg []byte) []byte { return ed25519.Sign(k.priv, msg) }

// Public returns the verification public key.
func (k *Key) Public() ed25519.PublicKey { return k.pub }

// PublicPEM returns the public key as a PKIX PEM string, for distribution to
// agents/sensors at enroll (they pin it to verify signed manifests).
func (k *Key) PublicPEM() string {
	der, err := x509.MarshalPKIXPublicKey(k.pub)
	if err != nil {
		return ""
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}
