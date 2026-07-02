package update

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

const sha64 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

// goldenCanonical MUST be byte-identical to the agent package's golden — that is
// the contract that lets agents verify control-plane signatures.
const goldenCanonical = "suricatoos-agent-update-v1\n" +
	"issued_at=2026-06-30T03:00:00Z\n" +
	"os=linux\narch=amd64\nlatest=0.1.1\nupdate=true\n" +
	"url=https://example.test/bin\n" +
	"sha256=" + sha64 + "\n"

func TestCanonicalGolden(t *testing.T) {
	r := response{
		IssuedAt:        time.Date(2026, 6, 30, 3, 0, 0, 0, time.UTC),
		OS:              "linux",
		Arch:            "amd64",
		Latest:          "0.1.1",
		UpdateAvailable: true,
		URL:             "https://example.test/bin",
		SHA256:          sha64,
	}
	if got := string(canonical(r)); got != goldenCanonical {
		t.Fatalf("canonical drift vs agent contract:\n got=%q\nwant=%q", got, goldenCanonical)
	}
}

type edSigner struct{ priv ed25519.PrivateKey }

func (s edSigner) Sign(msg []byte) []byte { return ed25519.Sign(s.priv, msg) }

// TestHandlerProducesVerifiableSignature mirrors the agent's verification: parse
// the JSON, rebuild the canonical bytes, and verify the signature with the CA
// public key. This is the cross-module integration guarantee.
func TestHandlerProducesVerifiableSignature(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	cfg := &ManifestConfig{
		Version: "0.1.1",
		Artifacts: []Artifact{
			{OS: "linux", Arch: "amd64", URL: "https://example.test/bin", SHA256: sha64},
		},
	}
	svc := NewService(cfg, edSigner{priv})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/update/check?os=linux&arch=amd64&current=0.1.0", nil)
	svc.Handler()(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d", rec.Code)
	}
	var r response
	if err := json.Unmarshal(rec.Body.Bytes(), &r); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !r.UpdateAvailable || r.Latest != "0.1.1" || r.SHA256 != sha64 {
		t.Fatalf("unexpected manifest: %+v", r)
	}
	sig, err := base64.StdEncoding.DecodeString(r.Signature)
	if err != nil {
		t.Fatalf("sig b64: %v", err)
	}
	// Reconstruct canonical exactly as the agent would, from the JSON fields.
	if !ed25519.Verify(pub, canonical(r), sig) {
		t.Fatal("signature does not verify with CA public key (canonical mismatch?)")
	}
}

func TestHandlerDisabledReturns204(t *testing.T) {
	svc := NewService(nil, edSigner{})
	rec := httptest.NewRecorder()
	svc.Handler()(rec, httptest.NewRequest(http.MethodGet, "/update/check?os=linux&arch=amd64&current=0.1.0", nil))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204 when disabled, got %d", rec.Code)
	}
}

func TestHandlerUpToDateNotAvailable(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	cfg := &ManifestConfig{Version: "0.1.0", Artifacts: []Artifact{{OS: "linux", Arch: "amd64", URL: "https://x.test/b", SHA256: sha64}}}
	svc := NewService(cfg, edSigner{priv})
	rec := httptest.NewRecorder()
	svc.Handler()(rec, httptest.NewRequest(http.MethodGet, "/update/check?os=linux&arch=amd64&current=0.1.0", nil))
	var r response
	json.Unmarshal(rec.Body.Bytes(), &r)
	if r.UpdateAvailable {
		t.Fatal("should not offer update when current == latest")
	}
}

// TestDualSignBothVerify proves the fleet-migration dual-sign (ADR-0007): the
// primary signature verifies with the CA key (legacy fleet) AND the secondary with
// the dedicated update key (new agents), over the SAME canonical bytes.
func TestDualSignBothVerify(t *testing.T) {
	caPub, caPriv, _ := ed25519.GenerateKey(nil)
	upPub, upPriv, _ := ed25519.GenerateKey(nil)
	cfg := &ManifestConfig{Version: "0.2.0", Artifacts: []Artifact{
		{OS: "linux", Arch: "amd64", URL: "https://example.test/bin", SHA256: sha64},
	}}
	svc := NewService(cfg, edSigner{caPriv}).WithUpdateKey(edSigner{upPriv})
	rec := httptest.NewRecorder()
	svc.Handler()(rec, httptest.NewRequest(http.MethodGet, "/update/check?os=linux&arch=amd64&current=0.1.0", nil))

	var r response
	if err := json.Unmarshal(rec.Body.Bytes(), &r); err != nil {
		t.Fatal(err)
	}
	if r.Signature == "" || r.SignatureV2 == "" {
		t.Fatal("dual-sign deveria produzir as duas assinaturas")
	}
	msg := canonical(r)
	sig1, _ := base64.StdEncoding.DecodeString(r.Signature)
	sig2, _ := base64.StdEncoding.DecodeString(r.SignatureV2)
	if !ed25519.Verify(caPub, msg, sig1) {
		t.Fatal("primary deveria verificar com a chave da CA (frota legada)")
	}
	if !ed25519.Verify(upPub, msg, sig2) {
		t.Fatal("secondary deveria verificar com a chave de update dedicada")
	}
	// Cross-check: a primary NÃO verifica com a chave de update (chaves distintas).
	if ed25519.Verify(upPub, msg, sig1) {
		t.Fatal("as chaves deveriam ser realmente distintas")
	}
}
