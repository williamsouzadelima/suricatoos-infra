package api

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"errors"
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

// revokeSetup builds a handler whose CA persists revocations in dir/crl.json (dir ""
// = no CRL_FILE: memory only) and a token with one enrollment per serial; it returns
// the handler, the CA and the token id.
func revokeSetup(t *testing.T, dir string, serials ...string) (*Handler, *ca.CA, string) {
	t.Helper()
	authority, err := ca.NewEphemeral(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if dir != "" {
		if err := authority.LoadCRLFile(filepath.Join(dir, "crl.json")); err != nil {
			t.Fatal(err)
		}
	}
	tm := tokens.NewManager(tokens.NewMemStore())
	minted, err := tm.Mint(tokens.MintRequest{Type: tokens.Deployment, Scope: tokens.Scope{Tenant: "acme"}, TTL: time.Hour, MaxUses: len(serials) + 10})
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
	FailedCount   int      `json:"failed_count"`
	Persisted     *bool    `json:"persisted"`
	Error         string   `json:"error"`
}

// A token without certificates whose DELETE could not save the revocation list (it
// may still hold an earlier revocation that was never saved): 200 with "persisted":
// false as before, but no longer silently — the save error is logged.
func TestRevokeToken_SaveFailureWithoutCertificatesIsLogged(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	h, _, id := revokeSetup(t, dir) // a token nobody enrolled with
	var logs []string
	h.logf = func(format string, args ...any) { logs = append(logs, fmt.Sprintf(format, args...)) }
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	rr := deleteToken(h, id)
	if rr.Code != http.StatusOK {
		t.Fatalf("DELETE = %d, want 200: %s", rr.Code, rr.Body)
	}
	if b := decodeRevoke(t, rr); b.Persisted == nil || *b.Persisted {
		t.Fatalf("body = %s, want \"persisted\": false", rr.Body)
	}
	if len(logs) != 1 || !strings.Contains(logs[0], id) || !strings.Contains(logs[0], "não foi gravada") {
		t.Fatalf("want one log line naming the token and the failed save, got %q", logs)
	}
}

// failingStore is a token store whose writes of an existing token fail.
type failingStore struct{ *tokens.MemStore }

func (failingStore) Update(tokens.Record) error {
	return errors.New("bolt: /data/tokens.db: no space left on device")
}

// The token store could not record the revocation: the 500 is JSON like every other
// revocation answer — "persisted": false, "token_revoked": false — the cause goes to
// the log, and no server path goes to the client.
func TestRevokeToken_TokenStoreFailureIsJSON(t *testing.T) {
	authority, err := ca.NewEphemeral(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	tm := tokens.NewManager(failingStore{tokens.NewMemStore()})
	minted, err := tm.Mint(tokens.MintRequest{Type: tokens.SingleHost, Scope: tokens.Scope{Tenant: "acme"}, TTL: time.Hour, MaxUses: 1})
	if err != nil {
		t.Fatal(err)
	}
	h := New(tm, authority, "https://test.example.com", "https://test.example.com/ingest/v1/inventory", testSecret)
	var logs []string
	h.logf = func(format string, args ...any) { logs = append(logs, fmt.Sprintf(format, args...)) }

	rr := deleteToken(h, minted.ID)
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("DELETE with a failing token store = %d, want 500: %s", rr.Code, rr.Body)
	}
	b := decodeRevoke(t, rr)
	if b.Status != "failed" || b.ID != minted.ID || b.TokenRevoked || b.Persisted == nil || *b.Persisted {
		t.Fatalf("body = %s, want status=failed, the id, token_revoked=false, persisted=false", rr.Body)
	}
	if strings.Contains(rr.Body.String(), "/data/tokens.db") {
		t.Fatalf("the 500 body leaks the server path: %s", rr.Body)
	}
	if len(logs) != 1 || !strings.Contains(logs[0], minted.ID) || !strings.Contains(logs[0], "no space left") {
		t.Fatalf("want one log line with the token and the cause, got %q", logs)
	}
}

// A failed save for a big token logs ONE summary line (the count and the first 20
// serials) and caps the body: failed_serials holds the first 100, failed_count all —
// not one line and one array element per certificate (100k of them: 100k log lines
// and a ~3 MB answer).
func TestRevokeToken_FailureReportIsBounded(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	serials := make([]string, 250)
	for i := range serials {
		serials[i] = fmt.Sprintf("ab%04x", i)
	}
	h, _, id := revokeSetup(t, dir, serials...)
	var logs []string
	h.logf = func(format string, args ...any) { logs = append(logs, fmt.Sprintf(format, args...)) }
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}

	rr := deleteToken(h, id)
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("DELETE = %d, want 500", rr.Code)
	}
	b := decodeRevoke(t, rr)
	if b.FailedCount != 250 || len(b.FailedSerials) != 100 || b.FailedSerials[0] != serials[0] || b.FailedSerials[99] != serials[99] {
		t.Fatalf("failed_count=%d, %d failed_serials (first %q), want 250 and the first 100 in order", b.FailedCount, len(b.FailedSerials), b.FailedSerials[:1])
	}
	if len(logs) != 1 {
		t.Fatalf("want ONE summary log line, got %d", len(logs))
	}
	l := logs[0]
	if !strings.Contains(l, id) || !strings.Contains(l, "250") || !strings.Contains(l, serials[19]) || strings.Contains(l, serials[20]) {
		t.Fatalf("summary line must name the token, the count and the first 20 serials only: %q", l)
	}
}

// decodeRevoke reads a DELETE answer as JSON, failing the test otherwise.
func decodeRevoke(t *testing.T, rr *httptest.ResponseRecorder) revokeBody {
	t.Helper()
	if ct := rr.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("Content-Type = %q, want application/json (%d %s)", ct, rr.Code, rr.Body)
	}
	var body revokeBody
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("DELETE body is not JSON: %v\n%s", err, rr.Body)
	}
	return body
}

// The DELETE answer — 200, the 409 of a repeated one, and the 500 — says whether the
// revocation list is on disk: false without CRL_FILE (memory only, as the boot warning
// says), true when the list was saved.
func TestRevokeToken_SaysWhetherTheRevocationIsPersisted(t *testing.T) {
	for _, withFile := range []bool{false, true} {
		dir := ""
		if withFile {
			dir = t.TempDir()
		}
		h, _, id := revokeSetup(t, dir, "0a1b2c")
		h.logf = func(string, ...any) {}
		for _, want := range []int{http.StatusOK, http.StatusConflict} {
			rr := deleteToken(h, id)
			if rr.Code != want {
				t.Fatalf("CRL_FILE=%v: DELETE = %d, want %d: %s", withFile, rr.Code, want, rr.Body)
			}
			body := decodeRevoke(t, rr)
			if body.ID != id || body.Persisted == nil || *body.Persisted != withFile {
				t.Fatalf("CRL_FILE=%v, %d: body = %s, want the id and \"persisted\": %v", withFile, want, rr.Body, withFile)
			}
		}
	}
}

// servedSerials returns how many entries the CRL the CA serves holds.
func servedSerials(t *testing.T, authority *ca.CA) int {
	t.Helper()
	der, err := authority.IssueCRL(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	crl, err := x509.ParseRevocationList(der)
	if err != nil {
		t.Fatal(err)
	}
	return len(crl.RevokedCertificateEntries)
}

// A revocation whose certificate list cannot be written to disk used to answer 200
// and lose it at the next restart without anyone knowing. Now: 500, a JSON body that
// says the token itself IS revoked, which serials failed and to repeat the DELETE,
// one log line per failed serial — and the repeated DELETE redoes and saves the
// revocation: 500 again while the disk is still gone (no duplicate entries), 409
// once every serial is revoked AND on disk.
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
	if body.Persisted == nil || *body.Persisted {
		t.Fatalf("a revocation whose save failed must say \"persisted\": false: %s", rr.Body)
	}
	if strings.Join(body.FailedSerials, ",") != "0a1b2c,0d0e0f" {
		t.Fatalf("failed_serials = %v, want [0a1b2c 0d0e0f]", body.FailedSerials)
	}
	if !strings.Contains(body.Error, "repita o DELETE: ele refaz e grava a revogação") || strings.Contains(rr.Body.String(), dir) {
		t.Fatalf("error must tell to repeat the DELETE and must not leak the server path: %q", body.Error)
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

	// Retry with the disk still gone: the same 500, and nothing piles up in the CRL.
	rr = deleteToken(h, id)
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("retry with the disk still gone = %d, want 500: %s", rr.Code, rr.Body)
	}
	body = revokeBody{}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil || strings.Join(body.FailedSerials, ",") != "0a1b2c,0d0e0f" || !body.TokenRevoked {
		t.Fatalf("retry body = %+v (err %v), want the same failed_serials and token_revoked=true", body, err)
	}
	if n := servedSerials(t, authority); n != 2 {
		t.Fatalf("served CRL has %d entries after the retry, want 2 (no duplicates)", n)
	}

	// The disk is back: the retry redoes and saves the revocation, then says 409.
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	rr = deleteToken(h, id)
	if rr.Code != http.StatusConflict {
		t.Fatalf("retry with the disk back = %d, want 409 (already revoked, now on disk): %s", rr.Code, rr.Body)
	}
	if b := decodeRevoke(t, rr); b.Persisted == nil || !*b.Persisted {
		t.Fatalf("the 409 after a successful save must say \"persisted\": true: %s", rr.Body)
	}
	fresh, err := ca.NewEphemeral(time.Now()) // a restart: only what is on disk survives
	if err != nil {
		t.Fatal(err)
	}
	if err := fresh.LoadCRLFile(filepath.Join(dir, "crl.json")); err != nil {
		t.Fatal(err)
	}
	if !fresh.IsRevoked("0a1b2c") || !fresh.IsRevoked("0d0e0f") {
		t.Fatal("after the 409 both serials must be on disk")
	}
	if n := servedSerials(t, fresh); n != 2 {
		t.Fatalf("crl.json holds %d entries, want 2", n)
	}
}

// A token revoked by a request that never got to its certificates (a crash between
// the token store and the CRL, or a restart that lost an unsaved list): repeating the
// DELETE revokes and saves them, then answers 409.
func TestRevokeToken_RetryRevokesTheCertsOfAnAlreadyRevokedToken(t *testing.T) {
	dir := t.TempDir()
	h, authority, id := revokeSetup(t, dir, "0a1b2c", "0d0e0f")
	h.logf = func(string, ...any) {}
	if _, err := h.tm.RevokeRecord(id, "crashed-request"); err != nil { // token revoked, certs not
		t.Fatal(err)
	}
	if authority.IsRevoked("0a1b2c") || authority.IsRevoked("0d0e0f") {
		t.Fatal("setup: the certificates must not be revoked yet")
	}

	if rr := deleteToken(h, id); rr.Code != http.StatusConflict {
		t.Fatalf("DELETE of the already revoked token = %d, want 409 after redoing the certs: %s", rr.Code, rr.Body)
	}
	if !authority.IsRevoked("0a1b2c") || !authority.IsRevoked("0d0e0f") {
		t.Fatal("the retry must revoke the certificates the first request never reached")
	}
	fresh, _ := ca.NewEphemeral(time.Now())
	if err := fresh.LoadCRLFile(filepath.Join(dir, "crl.json")); err != nil {
		t.Fatal(err)
	}
	if !fresh.IsRevoked("0a1b2c") || !fresh.IsRevoked("0d0e0f") {
		t.Fatal("the retried revocation must be on disk")
	}
	// And again: still 409, still exactly two entries.
	if rr := deleteToken(h, id); rr.Code != http.StatusConflict {
		t.Fatalf("second retry = %d, want 409", rr.Code)
	}
	if n := servedSerials(t, authority); n != 2 {
		t.Fatalf("served CRL has %d entries, want 2", n)
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
	if body.Persisted == nil || !*body.Persisted {
		t.Fatalf("the list (with the good serial) was saved, so \"persisted\" must be true: %s", rr.Body)
	}
	if !authority.IsRevoked("0a1b2c") {
		t.Fatal("the good serial must have been revoked despite the other failure")
	}
}

// A token revoked while its certificates never reached the saved list — a crash
// between the token store and the CRL, or a restart before the operator repeated a
// DELETE whose save failed — gets them back at boot, on disk, with nobody acting.
// Certificates of tokens that are not revoked are left alone; a second run adds nothing.
func TestReconcileRevocationsRestoresTheCertsOfRevokedTokens(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "crl.json")
	h, _, revokedID := revokeSetup(t, dir, "0a1b2c", "0d0e0f")
	live, err := h.tm.Mint(tokens.MintRequest{Type: tokens.SingleHost, Scope: tokens.Scope{Tenant: "acme"}, TTL: time.Hour, MaxUses: 1})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.tm.Consume(live.Token, tokens.Enrollment{AgentID: "agent-live", CertSerial: "0f0f0f"}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.tm.RevokeRecord(revokedID, "crashed-request"); err != nil { // the certs never got revoked
		t.Fatal(err)
	}

	// The restart: a CA that loads the CRL file (nothing in it) over the same token store.
	boot, err := ca.NewEphemeral(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := boot.LoadCRLFile(path); err != nil {
		t.Fatal(err)
	}
	added, invalid, err := ReconcileRevocations(h.tm, boot, time.Now())
	if err != nil || added != 2 || len(invalid) != 0 {
		t.Fatalf("reconcile: added=%d invalid=%v err=%v, want 2, none, nil", added, invalid, err)
	}
	fresh, _ := ca.NewEphemeral(time.Now()) // what survives the next restart is what is on disk
	if err := fresh.LoadCRLFile(path); err != nil {
		t.Fatal(err)
	}
	if !fresh.IsRevoked("0a1b2c") || !fresh.IsRevoked("0d0e0f") {
		t.Fatal("after the boot reconciliation the revoked token's certificates must be on disk")
	}
	if fresh.IsRevoked("0f0f0f") || boot.IsRevoked("0f0f0f") {
		t.Fatal("a certificate of a token that is not revoked must not be revoked")
	}

	// Idempotent: the next boot finds everything in place.
	if added, _, err := ReconcileRevocations(h.tm, boot, time.Now()); err != nil || added != 0 {
		t.Fatalf("second reconcile: added=%d err=%v, want 0, nil", added, err)
	}
	if n := servedSerials(t, boot); n != 2 {
		t.Fatalf("served CRL has %d entries, want 2", n)
	}
}

// A save that fails during the boot reconciliation is returned (main logs it loudly
// and keeps running); the serials are revoked in memory anyway.
func TestReconcileRevocationsReportsASaveFailure(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	h, _, id := revokeSetup(t, dir, "0a1b2c")
	if _, err := h.tm.RevokeRecord(id, "crashed-request"); err != nil {
		t.Fatal(err)
	}
	boot, _ := ca.NewEphemeral(time.Now())
	if err := boot.LoadCRLFile(filepath.Join(dir, "crl.json")); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	added, _, err := ReconcileRevocations(h.tm, boot, time.Now())
	if err == nil || added != 1 {
		t.Fatalf("reconcile with the disk gone: added=%d err=%v, want 1 and an error", added, err)
	}
	if !boot.IsRevoked("0a1b2c") {
		t.Fatal("the serial must be revoked in memory even though the save failed")
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
