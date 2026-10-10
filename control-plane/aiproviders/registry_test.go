package aiproviders

import (
	"bytes"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
)

const testKey = "sk-or-v1-TESTKEY-abcd1234"

func newReg(t *testing.T) *Registry {
	t.Helper()
	kek, _ := randBytes(kekSize)
	r, err := NewRegistry("", kek)
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	return r
}

// a compliant (EU + ZDR) enabled OpenRouter provider carrying testKey.
func compliantInput() UpsertInput {
	return UpsertInput{
		Name: "OpenRouter UE", Kind: KindOpenRouter, EURegion: true, ZDR: true,
		Enabled: true, APIKey: testKey,
	}
}

func TestUpsertStoresKeyEncrypted(t *testing.T) {
	r := newReg(t)
	pub, err := r.Upsert(compliantInput(), "op1")
	if err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	if !pub.HasKey || pub.KeyLast4 != "1234" {
		t.Fatalf("esperava has_key + last4=1234: %+v", pub)
	}
	// Stored ciphertext must not be the plaintext.
	stored := r.providers[pub.ID]
	if bytes.Contains(stored.KeyCipher, []byte(testKey)) {
		t.Fatal("chave guardada em claro")
	}
	// Server-side decryption returns the original key.
	got, _, err := r.DecryptedKey(pub.ID)
	if err != nil || got != testKey {
		t.Fatalf("DecryptedKey = %q err=%v, want %q", got, err, testKey)
	}
}

func TestListNeverExposesKey(t *testing.T) {
	r := newReg(t)
	if _, err := r.Upsert(compliantInput(), "op1"); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	b, _ := json.Marshal(r.List())
	if bytes.Contains(b, []byte(testKey)) {
		t.Fatalf("List expôs a chave: %s", b)
	}
	if bytes.Contains(b, []byte("key_cipher")) {
		t.Fatalf("List expôs o ciphertext: %s", b)
	}
	if !bytes.Contains(b, []byte("1234")) {
		t.Fatal("List deveria mostrar o last4")
	}
}

func TestGovernanceGate(t *testing.T) {
	r := newReg(t)
	// Enabling a non-EU/non-ZDR provider is refused.
	in := compliantInput()
	in.EURegion = false
	if _, err := r.Upsert(in, "op1"); !errors.Is(err, ErrGovernance) {
		t.Fatalf("esperava ErrGovernance, veio %v", err)
	}
	// The same provider may be STORED while disabled.
	in.Enabled = false
	if _, err := r.Upsert(in, "op1"); err != nil {
		t.Fatalf("provedor fora da régua mas desabilitado deveria salvar: %v", err)
	}
}

func TestUpdateKeepsKeyWhenOmitted(t *testing.T) {
	r := newReg(t)
	pub, _ := r.Upsert(compliantInput(), "op1")
	// Metadata-only update (no api_key) must preserve the stored key.
	up := UpsertInput{ID: pub.ID, Name: "Renomeado", Kind: KindOpenRouter, EURegion: true, ZDR: true, Enabled: true}
	pub2, err := r.Upsert(up, "op2")
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if pub2.Name != "Renomeado" || !pub2.HasKey {
		t.Fatalf("update deveria renomear e manter a chave: %+v", pub2)
	}
	got, _, err := r.DecryptedKey(pub.ID)
	if err != nil || got != testKey {
		t.Fatalf("chave deveria persistir após update sem api_key: %q err=%v", got, err)
	}
}

func TestUpdateReplacesKey(t *testing.T) {
	r := newReg(t)
	pub, _ := r.Upsert(compliantInput(), "op1")
	up := compliantInput()
	up.ID = pub.ID
	up.APIKey = "sk-or-v1-NOVACHAVE-wxyz9999"
	pub2, err := r.Upsert(up, "op2")
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if pub2.KeyLast4 != "9999" {
		t.Fatalf("last4 deveria atualizar p/ 9999: %+v", pub2)
	}
	got, _, _ := r.DecryptedKey(pub.ID)
	if got != "sk-or-v1-NOVACHAVE-wxyz9999" {
		t.Fatalf("chave deveria ser a nova: %q", got)
	}
}

func TestDecryptedKeyRefusesDisabled(t *testing.T) {
	r := newReg(t)
	in := compliantInput()
	in.Enabled = false
	pub, _ := r.Upsert(in, "op1")
	if _, _, err := r.DecryptedKey(pub.ID); err == nil {
		t.Fatal("DecryptedKey de provedor desabilitado deveria falhar")
	}
}

func TestValidationRejectsBadKindAndURL(t *testing.T) {
	r := newReg(t)
	bad := UpsertInput{Name: "x", Kind: "bogus", EURegion: true, ZDR: true}
	if _, err := r.Upsert(bad, "op"); !errors.Is(err, ErrValidation) {
		t.Fatalf("kind inválido deveria dar ErrValidation: %v", err)
	}
	badURL := UpsertInput{Name: "x", Kind: KindOpenAICompatible, BaseURL: "http://insecure.example", EURegion: true, ZDR: true}
	if _, err := r.Upsert(badURL, "op"); !errors.Is(err, ErrValidation) {
		t.Fatalf("base_url não-https deveria dar ErrValidation: %v", err)
	}
}

func TestUnoRouterPresetBaseURL(t *testing.T) {
	r := newReg(t)
	pub, err := r.Upsert(UpsertInput{
		Name: "UnoRouter", Kind: KindUnoRouter, EURegion: true, ZDR: true, Enabled: true, APIKey: testKey,
	}, "op")
	if err != nil {
		t.Fatalf("Upsert unorouter: %v", err)
	}
	if pub.Kind != KindUnoRouter || pub.BaseURL != "https://api.unorouter.com/v1" {
		t.Fatalf("esperava preset unorouter: kind=%q base=%q", pub.Kind, pub.BaseURL)
	}
}

func TestPersistenceRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "providers.json")
	kek, _ := randBytes(kekSize)
	r1, _ := NewRegistry(path, kek)
	pub, err := r1.Upsert(compliantInput(), "op1")
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}
	// Reload with the SAME kek + path: the encrypted key survives and decrypts.
	r2, err := NewRegistry(path, kek)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	got, _, err := r2.DecryptedKey(pub.ID)
	if err != nil || got != testKey {
		t.Fatalf("chave deveria sobreviver ao reload: %q err=%v", got, err)
	}
}
