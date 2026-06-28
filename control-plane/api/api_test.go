package api

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/williamsouzadelima/suricatoos-infra/control-plane/ca"
	"github.com/williamsouzadelima/suricatoos-infra/control-plane/tokens"
)

const testSecret = "test-admin-secret"

func newTestHandler(t *testing.T) *Handler {
	t.Helper()
	authority, err := ca.NewEphemeral(time.Now())
	if err != nil {
		t.Fatalf("NewEphemeral: %v", err)
	}
	store := tokens.NewMemStore()
	tm := tokens.NewManager(store)
	return New(tm, authority, "https://test.example.com", testSecret)
}

func authHeader() string { return "Bearer " + testSecret }

func TestCreateToken_Success(t *testing.T) {
	h := newTestHandler(t)
	body := `{"type":"single_host","tenant":"acme","ttl_hours":1}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/tokens", strings.NewReader(body))
	req.Header.Set("Authorization", authHeader())
	rr := httptest.NewRecorder()
	h.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("want 201, got %d: %s", rr.Code, rr.Body.String())
	}
	ct := rr.Header().Get("Content-Type")
	if !strings.HasPrefix(ct, "application/yaml") {
		t.Errorf("Content-Type = %q, want application/yaml", ct)
	}
	if !strings.Contains(rr.Header().Get("Content-Disposition"), "attachment") {
		t.Error("response should be a download attachment")
	}
	yaml := rr.Body.String()
	if !strings.Contains(yaml, "st_") {
		t.Error("bundle must contain the token (st_ prefix)")
	}
	if !strings.Contains(yaml, "sha256:") {
		t.Error("bundle must contain the CA fingerprint (sha256:)")
	}
	if !strings.Contains(yaml, "https://test.example.com") {
		t.Error("bundle must contain the server URL")
	}
	if !strings.Contains(yaml, "acme") {
		t.Error("bundle must contain the tenant")
	}
}

func TestCreateToken_NoAuth(t *testing.T) {
	h := newTestHandler(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/tokens", strings.NewReader(`{"type":"single_host","tenant":"x"}`))
	rr := httptest.NewRecorder()
	h.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("want 401, got %d", rr.Code)
	}
}

func TestCreateToken_WrongAuth(t *testing.T) {
	h := newTestHandler(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/tokens", strings.NewReader(`{"type":"single_host","tenant":"x"}`))
	req.Header.Set("Authorization", "Bearer wrong-secret")
	rr := httptest.NewRecorder()
	h.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("want 401, got %d", rr.Code)
	}
}

func TestCreateToken_BadBody(t *testing.T) {
	h := newTestHandler(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/tokens", strings.NewReader(`not json`))
	req.Header.Set("Authorization", authHeader())
	rr := httptest.NewRecorder()
	h.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d", rr.Code)
	}
}

func TestCreateToken_MissingTenant(t *testing.T) {
	h := newTestHandler(t)
	// Mint requires a non-empty tenant (Scope.Tenant is mandatory).
	body := `{"type":"single_host","tenant":"","ttl_hours":1}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/tokens", strings.NewReader(body))
	req.Header.Set("Authorization", authHeader())
	rr := httptest.NewRecorder()
	h.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("want 400 for missing tenant, got %d", rr.Code)
	}
}

func TestListTokens_Empty(t *testing.T) {
	h := newTestHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/tokens", nil)
	req.Header.Set("Authorization", authHeader())
	rr := httptest.NewRecorder()
	h.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rr.Code)
	}
	var recs []tokenRecord
	if err := json.NewDecoder(rr.Body).Decode(&recs); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(recs) != 0 {
		t.Errorf("want 0 records, got %d", len(recs))
	}
}

func TestListTokens_AfterCreate(t *testing.T) {
	h := newTestHandler(t)

	// Create a token.
	body := `{"type":"single_host","tenant":"acme","ttl_hours":1}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/tokens", strings.NewReader(body))
	req.Header.Set("Authorization", authHeader())
	httptest.NewRecorder() // discard the bundle response
	rr := httptest.NewRecorder()
	h.Handler().ServeHTTP(rr, req)

	// List.
	req2 := httptest.NewRequest(http.MethodGet, "/api/v1/tokens", nil)
	req2.Header.Set("Authorization", authHeader())
	rr2 := httptest.NewRecorder()
	h.Handler().ServeHTTP(rr2, req2)

	var recs []tokenRecord
	json.NewDecoder(rr2.Body).Decode(&recs)
	if len(recs) != 1 {
		t.Fatalf("want 1 record after create, got %d", len(recs))
	}
	rec := recs[0]
	if rec.Type != "single_host" {
		t.Errorf("type = %q", rec.Type)
	}
	if rec.Tenant != "acme" {
		t.Errorf("tenant = %q", rec.Tenant)
	}
	if rec.MaxUses != 1 {
		t.Errorf("max_uses = %d", rec.MaxUses)
	}
	if rec.Remaining != 1 {
		t.Errorf("remaining = %d", rec.Remaining)
	}
	if rec.Revoked {
		t.Error("new token must not be revoked")
	}
	// List response must NOT contain any token secret.
	body2, _ := io.ReadAll(bytes.NewReader(rr2.Body.Bytes()))
	if strings.Contains(string(body2), "st_") {
		t.Error("list response must not contain token secret")
	}
}

func TestRevokeToken_Success(t *testing.T) {
	h := newTestHandler(t)

	// Create a token.
	cr := httptest.NewRequest(http.MethodPost, "/api/v1/tokens",
		strings.NewReader(`{"type":"single_host","tenant":"x","ttl_hours":1}`))
	cr.Header.Set("Authorization", authHeader())
	crr := httptest.NewRecorder()
	h.Handler().ServeHTTP(crr, cr)

	// Extract token id from list.
	lr := httptest.NewRequest(http.MethodGet, "/api/v1/tokens", nil)
	lr.Header.Set("Authorization", authHeader())
	lrr := httptest.NewRecorder()
	h.Handler().ServeHTTP(lrr, lr)
	var recs []tokenRecord
	json.NewDecoder(lrr.Body).Decode(&recs)
	if len(recs) == 0 {
		t.Fatal("no tokens to revoke")
	}
	id := recs[0].ID

	// Revoke it.
	dr := httptest.NewRequest(http.MethodDelete, "/api/v1/tokens/"+id, nil)
	dr.Header.Set("Authorization", authHeader())
	dr.SetPathValue("id", id)
	drr := httptest.NewRecorder()
	h.Handler().ServeHTTP(drr, dr)
	if drr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", drr.Code, drr.Body.String())
	}

	// List: token must be revoked.
	lr2 := httptest.NewRequest(http.MethodGet, "/api/v1/tokens", nil)
	lr2.Header.Set("Authorization", authHeader())
	lrr2 := httptest.NewRecorder()
	h.Handler().ServeHTTP(lrr2, lr2)
	var recs2 []tokenRecord
	json.NewDecoder(lrr2.Body).Decode(&recs2)
	if len(recs2) == 0 || !recs2[0].Revoked {
		t.Error("token must appear as revoked after DELETE")
	}
}

func TestRevokeToken_NotFound(t *testing.T) {
	h := newTestHandler(t)
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/tokens/nonexistent", nil)
	req.Header.Set("Authorization", authHeader())
	req.SetPathValue("id", "nonexistent")
	rr := httptest.NewRecorder()
	h.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Errorf("want 404, got %d", rr.Code)
	}
}

func TestBuildBundle(t *testing.T) {
	authority, _ := ca.NewEphemeral(time.Now())
	store := tokens.NewMemStore()
	m := tokens.NewManager(store)
	minted, err := m.Mint(tokens.MintRequest{
		Type:    tokens.SingleHost,
		Scope:   tokens.Scope{Tenant: "demo"},
		TTL:     24 * time.Hour,
		MaxUses: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	bundle := buildBundle(minted, authority.Fingerprint(), "https://cp.example.com")
	for _, want := range []string{
		"st_", "sha256:", "https://cp.example.com", "demo",
		"suricatoos-agent enroll", "--server", "--token", "--ca-pin",
	} {
		if !strings.Contains(bundle, want) {
			t.Errorf("bundle missing %q", want)
		}
	}
}
