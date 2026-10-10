// Package aiproviders stores the operator-configured LLM providers/routers for the
// scanner's AI features (e.g. the remediation-planner). Each provider's API key is
// encrypted at rest with a host key-encryption-key (AES-256-GCM) and is NEVER
// returned by the API — only a masked last-4 and a has-key flag. A provider may be
// ENABLED only if it meets the AI-governance bar (EU region + zero data retention),
// so a key can be web-configured without weakening the privacy contract (ADR-0010 /
// reports governance). The plaintext key is read ONLY server-side, by the planner.
package aiproviders

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"time"
)

// kekSize is the AES-256 key-encryption-key length in bytes.
const kekSize = 32

// Supported provider shapes. Both speak the OpenAI-compatible API, so a single
// HTTP client serves OpenRouter and any compatible router/gateway.
const (
	KindOpenRouter       = "openrouter"
	KindOpenAICompatible = "openai_compatible"
)

func validKind(k string) bool { return k == KindOpenRouter || k == KindOpenAICompatible }

// Provider is one configured provider as persisted on disk. KeyCipher holds the
// AES-GCM (nonce||ciphertext) of the API key; it persists but is stripped from
// every API response (see Public). The plaintext key never lives in this struct.
type Provider struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Kind      string    `json:"kind"`
	BaseURL   string    `json:"base_url"`
	Model     string    `json:"model,omitempty"`
	EURegion  bool      `json:"eu_region"`
	ZDR       bool      `json:"zdr"`
	Enabled   bool      `json:"enabled"`
	KeyCipher []byte    `json:"key_cipher,omitempty"` // encrypted at rest; NEVER in an API response
	KeyLast4  string    `json:"key_last4,omitempty"`
	UpdatedBy string    `json:"updated_by,omitempty"`
	UpdatedAt time.Time `json:"updated_at,omitempty"`
}

// PublicProvider is the API-facing view: everything EXCEPT any key material.
type PublicProvider struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Kind      string    `json:"kind"`
	BaseURL   string    `json:"base_url"`
	Model     string    `json:"model,omitempty"`
	EURegion  bool      `json:"eu_region"`
	ZDR       bool      `json:"zdr"`
	Enabled   bool      `json:"enabled"`
	HasKey    bool      `json:"has_key"`
	KeyLast4  string    `json:"key_last4,omitempty"`
	UpdatedBy string    `json:"updated_by,omitempty"`
	UpdatedAt time.Time `json:"updated_at,omitempty"`
}

// Public returns the key-free view safe to serialize to any client.
func (p *Provider) Public() PublicProvider {
	return PublicProvider{
		ID: p.ID, Name: p.Name, Kind: p.Kind, BaseURL: p.BaseURL, Model: p.Model,
		EURegion: p.EURegion, ZDR: p.ZDR, Enabled: p.Enabled,
		HasKey: len(p.KeyCipher) > 0, KeyLast4: p.KeyLast4,
		UpdatedBy: p.UpdatedBy, UpdatedAt: p.UpdatedAt,
	}
}

// LoadOrCreateKEK reads a 32-byte key-encryption-key from path, generating and
// persisting one (0600) if absent. An empty path yields an ephemeral in-memory KEK
// (dev/tests): stored keys then do not survive a restart — the caller must warn.
func LoadOrCreateKEK(path string) ([]byte, error) {
	if path == "" {
		return randBytes(kekSize)
	}
	b, err := os.ReadFile(path)
	if err == nil {
		if len(b) != kekSize {
			return nil, fmt.Errorf("KEK %s: tamanho %d, esperado %d", path, len(b), kekSize)
		}
		return b, nil
	}
	if !os.IsNotExist(err) {
		return nil, fmt.Errorf("ler KEK %s: %w", path, err)
	}
	kek, err := randBytes(kekSize)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, kek, 0o600); err != nil {
		return nil, fmt.Errorf("gravar KEK %s: %w", path, err)
	}
	return kek, nil
}

func randBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, err
	}
	return b, nil
}

// encrypt seals plaintext with kek (AES-256-GCM), returning nonce||ciphertext.
func encrypt(kek, plaintext []byte) ([]byte, error) {
	gcm, err := newGCM(kek)
	if err != nil {
		return nil, err
	}
	nonce, err := randBytes(gcm.NonceSize())
	if err != nil {
		return nil, err
	}
	// Seal appends the ciphertext to its first arg, so the result is nonce||ct.
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// decrypt opens a nonce||ciphertext blob produced by encrypt.
func decrypt(kek, blob []byte) ([]byte, error) {
	gcm, err := newGCM(kek)
	if err != nil {
		return nil, err
	}
	ns := gcm.NonceSize()
	if len(blob) < ns {
		return nil, errors.New("ciphertext curto demais")
	}
	return gcm.Open(nil, blob[:ns], blob[ns:], nil)
}

func newGCM(kek []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// last4 returns the trailing 4 chars for masked display (whole string if shorter).
func last4(s string) string {
	if len(s) <= 4 {
		return s
	}
	return s[len(s)-4:]
}
