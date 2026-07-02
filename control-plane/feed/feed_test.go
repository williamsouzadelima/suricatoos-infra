package feed

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// edSigner is a test Ed25519 signer (stands in for *ca.CA).
type edSigner struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
}

func newSigner(t *testing.T) *edSigner {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &edSigner{priv: priv, pub: pub}
}
func (s *edSigner) Sign(msg []byte) []byte { return ed25519.Sign(s.priv, msg) }

func writeFeed(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, "nvt"), 0o755)
	os.WriteFile(filepath.Join(root, "nvt", "a.nasl"), []byte("script A"), 0o644)
	os.WriteFile(filepath.Join(root, "nvt", "b.nasl"), []byte("script B longer"), 0o644)
	os.WriteFile(filepath.Join(root, "scap.xml"), []byte("<scap/>"), 0o644)
	return root
}

func TestBuildManifestHashesEveryFile(t *testing.T) {
	root := writeFeed(t)
	m, err := BuildManifest(root, "v1")
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Files) != 3 {
		t.Fatalf("esperado 3 arquivos, got %d", len(m.Files))
	}
	// sorted por path; hash confere com o conteúdo.
	if m.Files[0].Path != "nvt/a.nasl" {
		t.Fatalf("primeiro path errado (deveria ser sorted): %s", m.Files[0].Path)
	}
	want := sha256.Sum256([]byte("script A"))
	if m.Files[0].SHA256 != hex.EncodeToString(want[:]) || m.Files[0].Size != 8 {
		t.Fatalf("hash/size de a.nasl errado: %+v", m.Files[0])
	}
}

func TestCanonicalDeterministicAndSignable(t *testing.T) {
	root := writeFeed(t)
	m, _ := BuildManifest(root, "v1")
	sg := newSigner(t)
	m.Signature = base64.StdEncoding.EncodeToString(sg.Sign(m.Canonical()))

	// Verifica como o sensor faria (pubkey da CA pinada).
	sig, _ := base64.StdEncoding.DecodeString(m.Signature)
	if !ed25519.Verify(sg.pub, m.Canonical(), sig) {
		t.Fatal("assinatura do manifest deveria verificar")
	}
	// Adulterar um hash quebra a verificação (Canonical muda).
	m.Files[0].SHA256 = "deadbeef"
	if ed25519.Verify(sg.pub, m.Canonical(), sig) {
		t.Fatal("manifest adulterado NÃO deveria verificar")
	}
}

func TestServeManifestSigned(t *testing.T) {
	root := writeFeed(t)
	sg := newSigner(t)
	svc := New(Config{Root: root, FeedVersion: func() string { return "v1" }, Signer: sg})
	mux := http.NewServeMux()
	svc.Register(mux)

	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest("GET", "/v1/feed/manifest", nil))
	if w.Code != 200 {
		t.Fatalf("manifest deveria 200, got %d", w.Code)
	}
	var m Manifest
	json.Unmarshal(w.Body.Bytes(), &m)
	if m.Signature == "" || len(m.Files) != 3 {
		t.Fatalf("manifest servido incompleto: %+v", m)
	}
	sig, _ := base64.StdEncoding.DecodeString(m.Signature)
	if !ed25519.Verify(sg.pub, m.Canonical(), sig) {
		t.Fatal("assinatura do manifest servido deveria verificar")
	}
}

func TestServeBlobContentAddressed(t *testing.T) {
	root := writeFeed(t)
	svc := New(Config{Root: root, FeedVersion: func() string { return "v1" }, Signer: newSigner(t)})
	mux := http.NewServeMux()
	svc.Register(mux)

	sum := sha256.Sum256([]byte("script A"))
	hexsum := hex.EncodeToString(sum[:])
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest("GET", "/v1/feed/blob/"+hexsum, nil))
	if w.Code != 200 {
		t.Fatalf("blob deveria 200, got %d", w.Code)
	}
	if w.Body.String() != "script A" {
		t.Fatalf("conteúdo do blob errado: %q", w.Body.String())
	}
	if w.Header().Get("ETag") != `"`+hexsum+`"` {
		t.Fatalf("ETag errado: %s", w.Header().Get("ETag"))
	}
}

func TestServeBlobRange(t *testing.T) {
	root := writeFeed(t)
	svc := New(Config{Root: root, FeedVersion: func() string { return "v1" }, Signer: newSigner(t)})
	mux := http.NewServeMux()
	svc.Register(mux)

	sum := sha256.Sum256([]byte("script B longer"))
	req := httptest.NewRequest("GET", "/v1/feed/blob/"+hex.EncodeToString(sum[:]), nil)
	req.Header.Set("Range", "bytes=9-") // resumível: "script B longer"[9:] == "longer"
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusPartialContent {
		t.Fatalf("Range deveria 206, got %d", w.Code)
	}
	if w.Body.String() != "longer" {
		t.Fatalf("range errado: %q", w.Body.String())
	}
}

func TestServeBlobRejectsBadHashAndUnknown(t *testing.T) {
	root := writeFeed(t)
	svc := New(Config{Root: root, FeedVersion: func() string { return "v1" }, Signer: newSigner(t)})
	mux := http.NewServeMux()
	svc.Register(mux)

	// hash malformado (anti-traversal) → 400.
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest("GET", "/v1/feed/blob/..%2f..%2fetc", nil))
	if w.Code != http.StatusBadRequest && w.Code != http.StatusNotFound {
		t.Fatalf("hash malformado deveria 400/404, got %d", w.Code)
	}
	// hash bem-formado mas ausente do manifest → 404.
	w2 := httptest.NewRecorder()
	absent := hex.EncodeToString(make([]byte, 32))
	mux.ServeHTTP(w2, httptest.NewRequest("GET", "/v1/feed/blob/"+absent, nil))
	if w2.Code != http.StatusNotFound {
		t.Fatalf("hash ausente deveria 404, got %d", w2.Code)
	}
}

func TestAuthzGate(t *testing.T) {
	root := writeFeed(t)
	denied := func(w http.ResponseWriter, r *http.Request) bool {
		http.Error(w, "forbidden", http.StatusForbidden)
		return false
	}
	svc := New(Config{Root: root, FeedVersion: func() string { return "v1" }, Signer: newSigner(t), Authz: denied})
	mux := http.NewServeMux()
	svc.Register(mux)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest("GET", "/v1/feed/manifest", nil))
	if w.Code != http.StatusForbidden {
		t.Fatalf("authz negada deveria 403, got %d", w.Code)
	}
}
