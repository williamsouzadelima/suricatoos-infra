package aiproviders

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func testServer(t *testing.T) (*httptest.Server, *Registry) {
	t.Helper()
	kek, _ := randBytes(kekSize)
	reg, _ := NewRegistry("", kek)
	mux := http.NewServeMux()
	NewService(reg, "s3cret").Register(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, reg
}

func do(t *testing.T, srv *httptest.Server, method, path, bearer, body string) (*http.Response, []byte) {
	t.Helper()
	req, _ := http.NewRequest(method, srv.URL+path, strings.NewReader(body))
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, b
}

const upsertBody = `{"name":"OpenRouter UE","kind":"openrouter","eu_region":true,"zdr":true,"enabled":true,"api_key":"sk-or-v1-TESTKEY-abcd1234"}`

func TestServiceRequiresBearer(t *testing.T) {
	srv, _ := testServer(t)
	if resp, _ := do(t, srv, "GET", "/api/v1/ai/providers", "", ""); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("sem bearer = %d, want 401", resp.StatusCode)
	}
	if resp, _ := do(t, srv, "POST", "/api/v1/ai/providers", "wrong", upsertBody); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("bearer errado = %d, want 401", resp.StatusCode)
	}
}

func TestServiceUpsertNeverReturnsKey(t *testing.T) {
	srv, _ := testServer(t)
	resp, b := do(t, srv, "POST", "/api/v1/ai/providers", "s3cret", upsertBody)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("upsert = %d: %s", resp.StatusCode, b)
	}
	if bytes.Contains(b, []byte("sk-or-v1-TESTKEY-abcd1234")) {
		t.Fatalf("resposta do upsert vazou a chave: %s", b)
	}
	if !bytes.Contains(b, []byte(`"key_last4":"1234"`)) {
		t.Fatalf("resposta deveria ter key_last4: %s", b)
	}
	// And the list endpoint likewise never carries the key.
	_, lb := do(t, srv, "GET", "/api/v1/ai/providers", "s3cret", "")
	if bytes.Contains(lb, []byte("sk-or-v1-TESTKEY-abcd1234")) || bytes.Contains(lb, []byte("key_cipher")) {
		t.Fatalf("list vazou material de chave: %s", lb)
	}
}

func TestServiceGovernanceRefused(t *testing.T) {
	srv, _ := testServer(t)
	body := `{"name":"NonEU","kind":"openai_compatible","base_url":"https://api.example/v1","eu_region":false,"zdr":false,"enabled":true,"api_key":"k"}`
	resp, _ := do(t, srv, "POST", "/api/v1/ai/providers", "s3cret", body)
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("provedor fora da régua habilitado = %d, want 422", resp.StatusCode)
	}
}

func TestServiceDelete(t *testing.T) {
	srv, _ := testServer(t)
	_, b := do(t, srv, "POST", "/api/v1/ai/providers", "s3cret", upsertBody)
	var got struct {
		Provider PublicProvider `json:"provider"`
	}
	_ = json.Unmarshal(b, &got)
	if got.Provider.ID == "" {
		t.Fatalf("sem id na resposta: %s", b)
	}
	if resp, _ := do(t, srv, "DELETE", "/api/v1/ai/providers/"+got.Provider.ID, "s3cret", ""); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete = %d, want 204", resp.StatusCode)
	}
	if resp, _ := do(t, srv, "DELETE", "/api/v1/ai/providers/"+got.Provider.ID, "s3cret", ""); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("delete repetido = %d, want 404", resp.StatusCode)
	}
}
