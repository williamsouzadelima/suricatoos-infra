package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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
	return New(tm, authority, "https://test.example.com", "https://test.example.com/ingest/v1/inventory", testSecret)
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

// Every near miss of "Bearer <secret>" is refused, on every admin route.
func TestAdminAuthRefusesWrongAndEmptyBearers(t *testing.T) {
	h := newTestHandler(t)
	for name, auth := range map[string]string{
		"no header":             "",
		"wrong secret":          "Bearer wrong",
		"scheme only":           "Bearer",
		"empty token":           "Bearer ",
		"other scheme":          "Basic " + testSecret,
		"secret without scheme": testSecret,
		"lowercase scheme":      "bearer " + testSecret,
		"trailing junk":         "Bearer " + testSecret + " ",
		"prefix of the secret":  "Bearer " + testSecret[:len(testSecret)-1],
	} {
		for _, rt := range []struct{ method, path, body string }{
			{http.MethodGet, "/api/v1/tokens", ""},
			{http.MethodPost, "/api/v1/tokens", `{"type":"single_host","tenant":"x"}`},
			{http.MethodDelete, "/api/v1/tokens/any", ""},
		} {
			req := httptest.NewRequest(rt.method, rt.path, strings.NewReader(rt.body))
			if auth != "" {
				req.Header.Set("Authorization", auth)
			}
			rr := httptest.NewRecorder()
			h.Handler().ServeHTTP(rr, req)
			if rr.Code != http.StatusUnauthorized {
				t.Errorf("%s: %s %s = %d, want 401", name, rt.method, rt.path, rr.Code)
			}
		}
	}
	if recs, _ := h.tm.List(); len(recs) != 0 {
		t.Fatalf("a refused request minted tokens: %+v", recs)
	}
}

// An empty ADMIN_SECRET must fail closed: "Bearer " with an empty token used to
// match it and open the whole admin API.
func TestAdminAuthFailsClosedWithAnEmptySecret(t *testing.T) {
	authority, err := ca.NewEphemeral(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	tm := tokens.NewManager(tokens.NewMemStore())
	h := New(tm, authority, "https://test.example.com", "https://test.example.com/ingest/v1/inventory", "")
	for _, auth := range []string{"", "Bearer ", "Bearer"} {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/tokens", strings.NewReader(`{"type":"single_host","tenant":"x"}`))
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		rr := httptest.NewRecorder()
		h.Handler().ServeHTTP(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Errorf("empty secret, Authorization %q: mint = %d, want 401", auth, rr.Code)
		}
	}
	if recs, _ := tm.List(); len(recs) != 0 {
		t.Fatalf("an empty secret let a token be minted: %+v", recs)
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

// revokeSetup builds a handler whose CA persists revocations in dir/crl.json and a
// token with one enrollment per serial; it returns the handler, the CA and the token id.
func revokeSetup(t *testing.T, dir string, serials ...string) (*Handler, *ca.CA, string) {
	t.Helper()
	authority, err := ca.NewEphemeral(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := authority.LoadCRLFile(filepath.Join(dir, "crl.json")); err != nil {
		t.Fatal(err)
	}
	tm := tokens.NewManager(tokens.NewMemStore())
	minted, err := tm.Mint(tokens.MintRequest{Type: tokens.Deployment, Scope: tokens.Scope{Tenant: "acme"}, TTL: time.Hour, MaxUses: 10})
	if err != nil {
		t.Fatal(err)
	}
	for i, s := range serials {
		if _, err := tm.Consume(minted.Token, tokens.Enrollment{AgentID: fmt.Sprintf("agent-%d", i), CertSerial: s}); err != nil {
			t.Fatal(err)
		}
	}
	return New(tm, authority, "https://test.example.com", "https://test.example.com/ingest/v1/inventory", testSecret), authority, minted.ID
}

func deleteToken(h *Handler, id string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/tokens/"+id, nil)
	req.Header.Set("Authorization", authHeader())
	rr := httptest.NewRecorder()
	h.Handler().ServeHTTP(rr, req)
	return rr
}

type revokeBody struct {
	Status        string   `json:"status"`
	ID            string   `json:"id"`
	TokenRevoked  bool     `json:"token_revoked"`
	CertsRevoked  int      `json:"certs_revoked"`
	FailedSerials []string `json:"failed_serials"`
	Error         string   `json:"error"`
}

// A revocation whose certificate list cannot be written to disk used to answer 200
// and lose it at the next restart without anyone knowing. Now: 500, a JSON body that
// says the token itself IS revoked (a retry answers 409) and which serials failed,
// and one log line per failed serial.
func TestRevokeToken_PersistFailureIs500(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	h, authority, id := revokeSetup(t, dir, "0a1b2c", "0d0e0f")
	var logs []string
	h.logf = func(format string, args ...any) { logs = append(logs, fmt.Sprintf(format, args...)) }
	if err := os.RemoveAll(dir); err != nil { // the disk under CRL_FILE goes away
		t.Fatal(err)
	}

	rr := deleteToken(h, id)
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("revoke with an unwritable CRL = %d, want 500: %s", rr.Code, rr.Body)
	}
	if ct := rr.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("Content-Type = %q, want application/json", ct)
	}
	var body revokeBody
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("500 body is not JSON: %v\n%s", err, rr.Body)
	}
	if body.Status != "partial" || body.ID != id || !body.TokenRevoked || body.CertsRevoked != 0 {
		t.Fatalf("body = %+v, want status=partial, the id, token_revoked=true, certs_revoked=0", body)
	}
	if strings.Join(body.FailedSerials, ",") != "0a1b2c,0d0e0f" {
		t.Fatalf("failed_serials = %v, want [0a1b2c 0d0e0f]", body.FailedSerials)
	}
	if !strings.Contains(body.Error, "409") || strings.Contains(rr.Body.String(), dir) {
		t.Fatalf("error must tell a retry answers 409 and must not leak the server path: %q", body.Error)
	}
	for _, s := range []string{"0a1b2c", "0d0e0f"} {
		found := false
		for _, l := range logs {
			found = found || (strings.Contains(l, s) && strings.Contains(l, id))
		}
		if !found {
			t.Errorf("no log line names serial %s and token %s: %q", s, id, logs)
		}
		// Not persisted, but the in-process CA keeps blocking it until a restart.
		if !authority.IsRevoked(s) {
			t.Errorf("serial %s must stay revoked in memory", s)
		}
	}

	// The token itself is revoked; retrying the DELETE is a 409, as the body says.
	if rr := deleteToken(h, id); rr.Code != http.StatusConflict {
		t.Fatalf("retry = %d, want 409", rr.Code)
	}
}

// Partial: one serial revokes and persists, the other cannot be revoked at all.
func TestRevokeToken_PartialFailureNamesOnlyTheFailedSerial(t *testing.T) {
	h, authority, id := revokeSetup(t, t.TempDir(), "0a1b2c", "zz-not-hex")
	h.logf = func(string, ...any) {}

	rr := deleteToken(h, id)
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("revoke with an invalid serial = %d, want 500: %s", rr.Code, rr.Body)
	}
	var body revokeBody
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("500 body is not JSON: %v\n%s", err, rr.Body)
	}
	if !body.TokenRevoked || body.CertsRevoked != 1 || strings.Join(body.FailedSerials, ",") != "zz-not-hex" {
		t.Fatalf("body = %+v, want token_revoked=true, certs_revoked=1, failed_serials=[zz-not-hex]", body)
	}
	if !authority.IsRevoked("0a1b2c") {
		t.Fatal("the good serial must have been revoked despite the other failure")
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
	bundle := buildBundle(minted, authority.Fingerprint(), "https://cp.example.com", "https://cp.example.com/ingest/v1/inventory")
	for _, want := range []string{
		"st_", "sha256:", "https://cp.example.com", "demo",
		"suricatoos-agent enroll", "--server", "--token", "--ca-pin",
		"ingest_url:", "https://cp.example.com/ingest/v1/inventory",
	} {
		if !strings.Contains(bundle, want) {
			t.Errorf("bundle missing %q", want)
		}
	}
}
