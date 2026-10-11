package aiproviders

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/williamsouzadelima/suricatoos-infra/control-plane/sessiongate"
)

// The session routes (/ai/providers) carry NO bearer — nginx's gsad gate is the
// boundary, and the control-plane additionally requires the X-Suricatoos-Gate marker
// that nginx sets only on session-gated locations (defense in depth). These tests
// assert they work WITH the marker and without a bearer, still hide the key, still
// enforce governance, refuse every route (read or write) WITHOUT the marker, and that
// the other routes (bearer, static page) are unaffected.

// doGate sends a request without a bearer. gate is the X-Suricatoos-Gate value
// ("" omits the header).
func doGate(t *testing.T, srv *httptest.Server, method, path, gate, body string) (*http.Response, []byte) {
	t.Helper()
	req, err := http.NewRequest(method, srv.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	if gate != "" {
		req.Header.Set(sessiongate.Header, gate)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, b
}

// doSession sends a request the way nginx delivers it from a session-gated location:
// no bearer, with the gate marker.
func doSession(t *testing.T, srv *httptest.Server, method, path, body string) (*http.Response, []byte) {
	t.Helper()
	return doGate(t, srv, method, path, sessiongate.Value, body)
}

func TestSession_UpsertAndListWithoutBearer(t *testing.T) {
	srv, _ := testServer(t)
	resp, b := doSession(t, srv, "POST", "/ai/providers", upsertBody)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("session upsert sem bearer = %d: %s", resp.StatusCode, b)
	}
	if bytes.Contains(b, []byte("sk-or-v1-TESTKEY-abcd1234")) {
		t.Fatalf("session upsert vazou a chave: %s", b)
	}
	_, lb := doSession(t, srv, "GET", "/ai/providers", "")
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
	resp, _ := doSession(t, srv, "POST", "/ai/providers", body)
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("governança na rota de sessão = %d, want 422", resp.StatusCode)
	}
}

func TestSession_DeleteWithoutBearer(t *testing.T) {
	srv, _ := testServer(t)
	_, b := doSession(t, srv, "POST", "/ai/providers", upsertBody)
	var got struct {
		Provider PublicProvider `json:"provider"`
	}
	_ = json.Unmarshal(b, &got)
	if got.Provider.ID == "" {
		t.Fatalf("sem id: %s", b)
	}
	if resp, _ := doSession(t, srv, "DELETE", "/ai/providers/"+got.Provider.ID, ""); resp.StatusCode != http.StatusNoContent {
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

// Without the marker nginx sets only on session-gated locations, all three session
// routes refuse with 403 and NOTHING is read or changed (defense in depth: a location
// that lacks the gate must not reach the AI config).
func TestSession_RequiresGateMarker(t *testing.T) {
	srv, reg := testServer(t)

	// A provider created through the bearer route: proves the refused requests neither
	// list, nor remove, nor add anything.
	resp, b := do(t, srv, "POST", "/api/v1/ai/providers", "s3cret", upsertBody)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("setup: upsert com bearer = %d: %s", resp.StatusCode, b)
	}
	var got struct {
		Provider PublicProvider `json:"provider"`
	}
	_ = json.Unmarshal(b, &got)
	id := got.Provider.ID
	if id == "" {
		t.Fatalf("setup: sem id: %s", b)
	}

	// Leading/trailing spaces are not tried here: the HTTP client and server trim them,
	// so on the wire they would BE the exact value. Those cases live in the
	// sessiongate tests, which call the handler directly.
	for _, c := range []struct{ name, gate string }{
		{"ausente", ""},
		{"valor 1", "1"},
		{"caixa diferente", "GSAD-SESSION"},
		{"valor com sufixo", "gsad-session-x"},
	} {
		t.Run(c.name, func(t *testing.T) {
			for _, rt := range []struct{ method, path, body string }{
				{"GET", "/ai/providers", ""},
				{"POST", "/ai/providers", upsertBody},
				{"DELETE", "/ai/providers/" + id, ""},
			} {
				resp, b := doGate(t, srv, rt.method, rt.path, c.gate, rt.body)
				if resp.StatusCode != http.StatusForbidden {
					t.Errorf("%s %s com marca %q = %d, want 403: %s", rt.method, rt.path, c.gate, resp.StatusCode, b)
				}
				if !bytes.Contains(b, []byte("rota de sessão sem portão")) {
					t.Errorf("%s %s com marca %q: corpo inesperado: %s", rt.method, rt.path, c.gate, b)
				}
				if bytes.Contains(b, []byte("OpenRouter UE")) {
					t.Errorf("%s %s com marca %q vazou dado de provedor: %s", rt.method, rt.path, c.gate, b)
				}
			}
		})
	}

	// The registry is exactly as it was: only the setup provider.
	if list := reg.List(); len(list) != 1 || list[0].ID != id {
		t.Fatalf("pedidos sem marca alteraram o registro: %+v", list)
	}

	// Positive control: the marker is the only difference. With it the same GET lists
	// the provider and the DELETE removes it (and only then).
	resp, b = doSession(t, srv, "GET", "/ai/providers", "")
	if resp.StatusCode != http.StatusOK || !bytes.Contains(b, []byte("OpenRouter UE")) {
		t.Fatalf("GET com marca = %d, want 200 listando o provedor: %s", resp.StatusCode, b)
	}
	if resp, _ := doSession(t, srv, "DELETE", "/ai/providers/"+id, ""); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("DELETE com marca = %d, want 204", resp.StatusCode)
	}
}

// The marker applies to the session routes only: the bearer routes and the static
// admin page stay reachable without it (each has a different gate).
func TestSession_OtherRoutesDoNotNeedMarker(t *testing.T) {
	srv, _ := testServer(t)
	if resp, b := do(t, srv, "GET", "/api/v1/ai/providers", "s3cret", ""); resp.StatusCode != http.StatusOK {
		t.Fatalf("rota com bearer, sem marca = %d, want 200: %s", resp.StatusCode, b)
	}
	resp, _ := do(t, srv, "GET", "/admin/ai-providers", "", "")
	if resp.StatusCode != http.StatusOK || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/html") {
		t.Fatalf("página estática, sem marca = %d (%s), want 200 text/html", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
}
