package scanlaunch

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func testService(t *testing.T, enabled bool) *Service {
	t.Helper()
	cfg := Config{
		Enabled:       enabled,
		StateFile:     "", // in-memory
		FindingsDir:   t.TempDir(),
		MaxConcurrent: 2,
		MaxHosts:      256,
		MaxPorts:      1000,
		RescanWindow:  6 * time.Hour,
		AllowedO:      "score-hub",
		AllowedOU:     "scan-requester",
		Allowlist:     "203.0.113.0/24",
		CRLURL:        "", // revocation not enforced in handler tests
		TickInterval:  time.Hour,
	}
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func authReq(method, path string, body any) *http.Request {
	var buf bytes.Buffer
	if body != nil {
		json.NewEncoder(&buf).Encode(body)
	}
	r := httptest.NewRequest(method, path, &buf)
	r.Header.Set("X-Client-Cert-Verify", "SUCCESS")
	r.Header.Set("X-Client-Cert-DN", "CN=score-hub-2026,O=score-hub,OU=scan-requester")
	return r
}

func serve(s *Service, r *http.Request) *httptest.ResponseRecorder {
	mux := http.NewServeMux()
	s.Register(mux)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	return w
}

func TestPostDisabled503(t *testing.T) {
	s := testService(t, false)
	w := serve(s, authReq("POST", "/v1/scan-request", testReq(1, "a.com")))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("desabilitado deveria 503, got %d", w.Code)
	}
}

func TestPostNoCert403(t *testing.T) {
	s := testService(t, true)
	r := httptest.NewRequest("POST", "/v1/scan-request", bytes.NewReader([]byte("{}")))
	// no auth headers
	w := serve(s, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("sem cert deveria 403, got %d", w.Code)
	}
}

func TestPostHostname422(t *testing.T) {
	s := testService(t, true)
	req := &ScanRequest{SchemaVersion: SchemaVersion, RengineScanHistoryID: 1,
		Hosts: []Host{{IP: "evil.com", Ports: []int{80}}}}
	w := serve(s, authReq("POST", "/v1/scan-request", req))
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("hostname deveria 422, got %d (%s)", w.Code, w.Body.String())
	}
}

func TestPostOffAllowlist422(t *testing.T) {
	s := testService(t, true)
	req := &ScanRequest{SchemaVersion: SchemaVersion, RengineScanHistoryID: 1,
		Hosts: []Host{{IP: "8.8.8.8", Ports: []int{80}}}}
	w := serve(s, authReq("POST", "/v1/scan-request", req))
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("IP fora da allowlist deveria 422, got %d", w.Code)
	}
}

func TestPostBadSchemaVersion400(t *testing.T) {
	s := testService(t, true)
	req := &ScanRequest{SchemaVersion: "9.9.9", RengineScanHistoryID: 1,
		Hosts: []Host{{IP: "203.0.113.10", Ports: []int{80}}}}
	w := serve(s, authReq("POST", "/v1/scan-request", req))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("schema errada deveria 400, got %d", w.Code)
	}
}

func TestPostCreatesAndIsIdempotent(t *testing.T) {
	s := testService(t, true)
	req := testReq(1234, "acme.com")

	w1 := serve(s, authReq("POST", "/v1/scan-request", req))
	if w1.Code != http.StatusCreated {
		t.Fatalf("criação deveria 201, got %d (%s)", w1.Code, w1.Body.String())
	}
	var r1 createResponse
	json.Unmarshal(w1.Body.Bytes(), &r1)
	if r1.RequestID == "" || r1.State != StatePending || r1.Idempotent {
		t.Fatalf("resposta de criação inesperada: %+v", r1)
	}

	// Same scan_history_id → 200 idempotent, same request_id.
	w2 := serve(s, authReq("POST", "/v1/scan-request", req))
	if w2.Code != http.StatusOK {
		t.Fatalf("replay deveria 200, got %d", w2.Code)
	}
	var r2 createResponse
	json.Unmarshal(w2.Body.Bytes(), &r2)
	if !r2.Idempotent || r2.RequestID != r1.RequestID {
		t.Fatalf("replay não idempotente: %+v", r2)
	}
}

func TestGetOwnerScope(t *testing.T) {
	s := testService(t, true)
	// Create a job owned by our tenant.
	w := serve(s, authReq("POST", "/v1/scan-request", testReq(1, "a.com")))
	var cr createResponse
	json.Unmarshal(w.Body.Bytes(), &cr)

	// Owned GET → 200.
	wg := serve(s, authReq("GET", "/v1/scan-request/"+cr.RequestID, nil))
	if wg.Code != http.StatusOK {
		t.Fatalf("GET próprio deveria 200, got %d", wg.Code)
	}

	// Unknown id → 404.
	wn := serve(s, authReq("GET", "/v1/scan-request/deadbeef", nil))
	if wn.Code != http.StatusNotFound {
		t.Fatalf("GET inexistente deveria 404, got %d", wn.Code)
	}

	// Foreign-owned job → 404 (no enumeration/IDOR).
	foreign, _, _ := s.reg.FindOrCreate(testReq(2, "b.com"), certIdentity{O: "other-tenant"}, 0)
	wf := serve(s, authReq("GET", "/v1/scan-request/"+foreign.RequestID, nil))
	if wf.Code != http.StatusNotFound {
		t.Fatalf("GET de job de outro tenant deveria 404, got %d", wf.Code)
	}
}

func TestDeleteRequestsStop(t *testing.T) {
	s := testService(t, true)
	w := serve(s, authReq("POST", "/v1/scan-request", testReq(1, "a.com")))
	var cr createResponse
	json.Unmarshal(w.Body.Bytes(), &cr)
	// Move to RUNNING so DELETE is a real stop-request (not a no-op terminal).
	s.reg.Update(cr.RequestID, func(j *Job) { j.State = StateRunning })

	wd := serve(s, authReq("DELETE", "/v1/scan-request/"+cr.RequestID, nil))
	if wd.Code != http.StatusAccepted {
		t.Fatalf("DELETE deveria 202, got %d", wd.Code)
	}
	got, _ := s.reg.Get(cr.RequestID)
	if !got.StopRequested {
		t.Fatal("DELETE deveria marcar StopRequested para o reconciler")
	}
}
