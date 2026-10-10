package aiproviders

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"
)

// The session routes (/ai/providers) carry NO bearer — nginx's gsad gate is the
// boundary. These tests assert they work without a bearer, still hide the key,
// still enforce governance, and that the bearer routes are unaffected.

func TestSession_UpsertAndListWithoutBearer(t *testing.T) {
	srv, _ := testServer(t)
	resp, b := do(t, srv, "POST", "/ai/providers", "", upsertBody)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("session upsert sem bearer = %d: %s", resp.StatusCode, b)
	}
	if bytes.Contains(b, []byte("sk-or-v1-TESTKEY-abcd1234")) {
		t.Fatalf("session upsert vazou a chave: %s", b)
	}
	_, lb := do(t, srv, "GET", "/ai/providers", "", "")
	if bytes.Contains(lb, []byte("sk-or-v1-TESTKEY-abcd1234")) || bytes.Contains(lb, []byte("key_cipher")) {
		t.Fatalf("session list vazou material de chave: %s", lb)
	}
	if !bytes.Contains(lb, []byte(`"key_last4":"1234"`)) {
		t.Fatalf("session list deveria ter key_last4: %s", lb)
	}
}

func TestSession_GovernanceStillEnforced(t *testing.T) {
	srv, _ := testServer(t)
	body := `{"name":"NonEU","kind":"openai_compatible","base_url":"https://api.example/v1","eu_region":false,"zdr":false,"enabled":true,"api_key":"k"}`
	resp, _ := do(t, srv, "POST", "/ai/providers", "", body)
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("governança na rota de sessão = %d, want 422", resp.StatusCode)
	}
}

func TestSession_DeleteWithoutBearer(t *testing.T) {
	srv, _ := testServer(t)
	_, b := do(t, srv, "POST", "/ai/providers", "", upsertBody)
	var got struct {
		Provider PublicProvider `json:"provider"`
	}
	_ = json.Unmarshal(b, &got)
	if got.Provider.ID == "" {
		t.Fatalf("sem id: %s", b)
	}
	if resp, _ := do(t, srv, "DELETE", "/ai/providers/"+got.Provider.ID, "", ""); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("session delete = %d, want 204", resp.StatusCode)
	}
}

func TestSession_BearerRouteStillRequiresBearer(t *testing.T) {
	srv, _ := testServer(t)
	// The /api/v1 route must still reject a missing bearer (unchanged by the refactor).
	if resp, _ := do(t, srv, "GET", "/api/v1/ai/providers", "", ""); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("rota bearer sem token = %d, want 401", resp.StatusCode)
	}
}
