package signkeys

import (
	"crypto/ed25519"
	"encoding/pem"
	"path/filepath"
	"testing"
)

func TestLoadOrCreatePersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "feed.key")
	k1, err := LoadOrCreate(path)
	if err != nil {
		t.Fatal(err)
	}
	// Recarrega do disco → mesma chave.
	k2, err := LoadOrCreate(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(k1.Public()) != string(k2.Public()) {
		t.Fatal("chave recarregada deveria ser a mesma")
	}
	// Assina + verifica com a pubkey.
	msg := []byte("suricatoos-feed-manifest-v1\nfeed_version=v1\n")
	sig := k1.Sign(msg)
	if !ed25519.Verify(k2.Public(), msg, sig) {
		t.Fatal("assinatura deveria verificar com a pubkey persistida")
	}
}

func TestEphemeralWhenNoPath(t *testing.T) {
	k, err := LoadOrCreate("")
	if err != nil {
		t.Fatal(err)
	}
	if len(k.Public()) != ed25519.PublicKeySize {
		t.Fatal("chave efêmera deveria ter pubkey válida")
	}
}

func TestPublicPEMParses(t *testing.T) {
	k, _ := LoadOrCreate("")
	block, _ := pem.Decode([]byte(k.PublicPEM()))
	if block == nil || block.Type != "PUBLIC KEY" {
		t.Fatal("PublicPEM deveria ser um bloco PEM PUBLIC KEY válido")
	}
}

func TestDistinctKeys(t *testing.T) {
	dir := t.TempDir()
	feed, _ := LoadOrCreate(filepath.Join(dir, "feed.key"))
	update, _ := LoadOrCreate(filepath.Join(dir, "update.key"))
	if string(feed.Public()) == string(update.Public()) {
		t.Fatal("chaves de propósitos distintos deveriam ser diferentes")
	}
}
