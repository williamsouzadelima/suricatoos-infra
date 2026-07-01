package feedsync

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// cloudFeed is a minimal stand-in for control-plane/feed: it builds a manifest
// over a dir, signs it with the SAME canonical form, and serves manifest + blobs.
// This is the cross-module contract test — if the two canonical forms drift, the
// signature won't verify here.
type cloudFeed struct {
	root string
	priv ed25519.PrivateKey
	ver  string
}

func (c *cloudFeed) manifest(t *testing.T) Manifest {
	t.Helper()
	var m Manifest
	m.FeedVersion = c.ver
	filepath.Walk(c.root, func(p string, fi os.FileInfo, err error) error {
		if err != nil || fi.IsDir() {
			return err
		}
		b, _ := os.ReadFile(p)
		sum := sha256.Sum256(b)
		rel, _ := filepath.Rel(c.root, p)
		m.Files = append(m.Files, FileEntry{Path: filepath.ToSlash(rel), SHA256: hex.EncodeToString(sum[:]), Size: int64(len(b))})
		return nil
	})
	m.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(c.priv, m.canonical()))
	return m
}

func (c *cloudFeed) server(t *testing.T) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/manifest") {
			json.NewEncoder(w).Encode(c.manifest(t))
			return
		}
		// /blob/{sha256}
		hash := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
		found := false
		filepath.Walk(c.root, func(p string, fi os.FileInfo, err error) error {
			if err != nil || fi.IsDir() {
				return err
			}
			b, _ := os.ReadFile(p)
			sum := sha256.Sum256(b)
			if hex.EncodeToString(sum[:]) == hash {
				http.ServeContent(w, r, "", fi.ModTime(), strings.NewReader(string(b)))
				found = true
			}
			return nil
		})
		if !found {
			http.NotFound(w, r)
		}
	}))
}

func setupCloud(t *testing.T) (*cloudFeed, ed25519.PublicKey) {
	t.Helper()
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, "nvt"), 0o755)
	os.WriteFile(filepath.Join(root, "nvt", "a.nasl"), []byte("script A"), 0o644)
	os.WriteFile(filepath.Join(root, "b.xml"), []byte("<b>data</b>"), 0o644)
	pub, priv, _ := ed25519.GenerateKey(nil)
	return &cloudFeed{root: root, priv: priv, ver: "v42"}, pub
}

func newSyncer(t *testing.T, srv *httptest.Server, pub ed25519.PublicKey, feedDir string) *Syncer {
	return New(Config{
		ManifestURL: srv.URL + "/agent/v1/feed/manifest",
		BlobURLBase: srv.URL + "/agent/v1/feed/blob",
		FeedDir:     feedDir,
		VerifyKey:   pub,
		Client:      srv.Client(),
	})
}

func TestSyncDownloadsAndVerifies(t *testing.T) {
	cloud, pub := setupCloud(t)
	srv := cloud.server(t)
	defer srv.Close()
	feedDir := t.TempDir()

	res, err := newSyncer(t, srv, pub, feedDir).Sync(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.FeedVersion != "v42" || res.Downloaded != 2 || res.AlreadyLocal != 0 {
		t.Fatalf("resultado errado: %+v", res)
	}
	// Conteúdo correto em disco.
	got, _ := os.ReadFile(filepath.Join(feedDir, "nvt", "a.nasl"))
	if string(got) != "script A" {
		t.Fatalf("a.nasl errado: %q", got)
	}
	// version.json escrito.
	vb, _ := os.ReadFile(filepath.Join(feedDir, "version.json"))
	if !strings.Contains(string(vb), "v42") {
		t.Fatalf("version.json errado: %s", vb)
	}
}

func TestSyncIdempotent(t *testing.T) {
	cloud, pub := setupCloud(t)
	srv := cloud.server(t)
	defer srv.Close()
	feedDir := t.TempDir()
	s := newSyncer(t, srv, pub, feedDir)

	if _, err := s.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Segunda sync: nada baixado (já tudo local com o hash certo).
	res, err := s.Sync(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.Downloaded != 0 || res.AlreadyLocal != 2 {
		t.Fatalf("segunda sync deveria ser no-op: %+v", res)
	}
}

func TestSyncRejectsBadSignature(t *testing.T) {
	cloud, _ := setupCloud(t)
	srv := cloud.server(t)
	defer srv.Close()
	// Verifica com uma pubkey DIFERENTE → assinatura inválida.
	wrongPub, _, _ := ed25519.GenerateKey(nil)
	feedDir := t.TempDir()
	_, err := newSyncer(t, srv, wrongPub, feedDir).Sync(context.Background())
	if err == nil || !strings.Contains(err.Error(), "assinatura") {
		t.Fatalf("assinatura inválida deveria abortar, got %v", err)
	}
	// Nada foi escrito.
	if _, e := os.Stat(filepath.Join(feedDir, "b.xml")); e == nil {
		t.Fatal("nenhum blob deveria ser escrito com assinatura inválida")
	}
}

func TestSyncRejectsTamperedBlob(t *testing.T) {
	cloud, pub := setupCloud(t)
	// Servidor malicioso: manifest assinado válido, mas serve um blob adulterado.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/manifest") {
			json.NewEncoder(w).Encode(cloud.manifest(t))
			return
		}
		w.Write([]byte("PAYLOAD ADULTERADO")) // hash não vai bater
	}))
	defer srv.Close()
	feedDir := t.TempDir()
	_, err := newSyncer(t, srv, pub, feedDir).Sync(context.Background())
	if err == nil || !strings.Contains(err.Error(), "hash não confere") {
		t.Fatalf("blob adulterado deveria ser rejeitado por hash, got %v", err)
	}
}

func TestSyncRequiresVerifyKey(t *testing.T) {
	cloud, _ := setupCloud(t)
	srv := cloud.server(t)
	defer srv.Close()
	s := New(Config{ManifestURL: srv.URL + "/agent/v1/feed/manifest", FeedDir: t.TempDir(), Client: srv.Client()})
	if _, err := s.Sync(context.Background()); err == nil {
		t.Fatal("sem VerifyKey deveria recusar")
	}
}
