package aiproviders

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestEncryptDecryptRoundTrip(t *testing.T) {
	kek, _ := randBytes(kekSize)
	plain := []byte("sk-or-v1-supersecret-key-value")
	ct, err := encrypt(kek, plain)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if bytes.Contains(ct, plain) {
		t.Fatal("ciphertext contém o plaintext — não cifrou")
	}
	got, err := decrypt(kek, ct)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("round-trip = %q, want %q", got, plain)
	}
}

func TestDecryptRejectsTamper(t *testing.T) {
	kek, _ := randBytes(kekSize)
	ct, _ := encrypt(kek, []byte("segredo"))
	ct[len(ct)-1] ^= 0xff // flip a byte of the ciphertext tail
	if _, err := decrypt(kek, ct); err == nil {
		t.Fatal("GCM deveria rejeitar ciphertext adulterado")
	}
}

func TestDecryptWrongKEKFails(t *testing.T) {
	k1, _ := randBytes(kekSize)
	k2, _ := randBytes(kekSize)
	ct, _ := encrypt(k1, []byte("segredo"))
	if _, err := decrypt(k2, ct); err == nil {
		t.Fatal("decifrar com KEK errada deveria falhar")
	}
}

func TestLoadOrCreateKEK(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "kek.bin")
	k1, err := LoadOrCreateKEK(path)
	if err != nil || len(k1) != kekSize {
		t.Fatalf("create KEK: len=%d err=%v", len(k1), err)
	}
	k2, err := LoadOrCreateKEK(path)
	if err != nil || !bytes.Equal(k1, k2) {
		t.Fatalf("reload KEK deveria ser idêntica: err=%v", err)
	}
	// Wrong-size file is rejected rather than silently used.
	bad := filepath.Join(dir, "bad.bin")
	_ = os.WriteFile(bad, []byte("short"), 0o600)
	if _, err := LoadOrCreateKEK(bad); err == nil {
		t.Fatal("KEK de tamanho errado deveria ser rejeitada")
	}
}

func TestKindDefaults(t *testing.T) {
	if !validKind(KindUnoRouter) || !validKind(KindOpenRouter) || !validKind(KindOpenAICompatible) {
		t.Fatal("os três kinds deveriam ser válidos")
	}
	if validKind("bogus") {
		t.Fatal("kind desconhecido não deveria validar")
	}
	if defaultBaseURL(KindUnoRouter) != "https://api.unorouter.com/v1" {
		t.Fatalf("preset unorouter errado: %q", defaultBaseURL(KindUnoRouter))
	}
	if defaultBaseURL(KindOpenRouter) != "https://openrouter.ai/api/v1" {
		t.Fatalf("preset openrouter errado: %q", defaultBaseURL(KindOpenRouter))
	}
	if defaultBaseURL(KindOpenAICompatible) != "" {
		t.Fatal("openai_compatible não deveria ter preset")
	}
}

func TestPublicOmitsKeyMaterial(t *testing.T) {
	p := &Provider{ID: "p1", Name: "x", KeyCipher: []byte{1, 2, 3}, KeyLast4: "cafe"}
	pub := p.Public()
	if !pub.HasKey || pub.KeyLast4 != "cafe" {
		t.Fatalf("Public deveria sinalizar has_key + last4: %+v", pub)
	}
	// The public view has no field that could carry the ciphertext.
	b, _ := json.Marshal(pub)
	if bytes.Contains(b, []byte("key_cipher")) {
		t.Fatalf("PublicProvider serializou key_cipher: %s", b)
	}
}
