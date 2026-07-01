package sensorjobs

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func notRevoked(string) bool { return false }

func testService(t *testing.T) (*Service, *Registry) {
	t.Helper()
	r, _ := NewRegistry(Config{
		ScopeOf:  scopes(map[string]string{"acme": "10.20.0.0/16", "globex": "192.168.0.0/16"}),
		Cooldown: time.Hour,
	})
	s := NewService(r, func(o string) bool { return o == "acme" || o == "globex" }, notRevoked)
	return s, r
}

func sensorReq(method, path string, body any) *http.Request {
	var buf bytes.Buffer
	if body != nil {
		json.NewEncoder(&buf).Encode(body)
	}
	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("X-Client-Cert-Verify", "SUCCESS")
	req.Header.Set("X-Client-Cert-DN", "CN=sensor-acme-1,OU=scanner-sensor,O=acme")
	req.Header.Set("X-Client-Cert-Serial", "0A1B")
	return req
}

func TestPollNoCert403(t *testing.T) {
	s, _ := testService(t)
	req := httptest.NewRequest("GET", "/v1/scan-jobs", nil) // sem headers
	w := httptest.NewRecorder()
	s.PollHandler()(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("sem cert deveria 403, got %d", w.Code)
	}
}

func TestHeartbeat(t *testing.T) {
	s, _ := testService(t)
	w := httptest.NewRecorder()
	body := map[string]any{"sensor_id": "sensor-acme-1", "feed_version": "v42", "gvmd_up": true}
	s.HeartbeatHandler()(w, sensorReq("POST", "/v1/heartbeat", body))
	if w.Code != http.StatusNoContent {
		t.Fatalf("heartbeat válido deveria 204, got %d", w.Code)
	}
	// Sem cert → 403.
	w2 := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/v1/heartbeat", nil)
	s.HeartbeatHandler()(w2, req)
	if w2.Code != http.StatusForbidden {
		t.Fatalf("heartbeat sem cert deveria 403, got %d", w2.Code)
	}
}

func TestPollRevoked403(t *testing.T) {
	r, _ := NewRegistry(Config{ScopeOf: scopes(map[string]string{"acme": "10.20.0.0/16"})})
	s := NewService(r, nil, func(string) bool { return true }) // serial revogado
	w := httptest.NewRecorder()
	s.PollHandler()(w, sensorReq("GET", "/v1/scan-jobs", nil))
	if w.Code != http.StatusForbidden {
		t.Fatalf("serial revogado deveria 403, got %d", w.Code)
	}
}

func TestPollCRLNotWiredFailClosed(t *testing.T) {
	r, _ := NewRegistry(Config{ScopeOf: scopes(map[string]string{"acme": "10.20.0.0/16"})})
	s := NewService(r, nil, nil) // CRL não conectada → fail-closed
	w := httptest.NewRecorder()
	s.PollHandler()(w, sensorReq("GET", "/v1/scan-jobs", nil))
	if w.Code != http.StatusForbidden {
		t.Fatalf("CRL não conectada deveria negar (fail-closed), got %d", w.Code)
	}
}

func TestPollEmpty204ThenJob(t *testing.T) {
	s, r := testService(t)
	w := httptest.NewRecorder()
	s.PollHandler()(w, sensorReq("GET", "/v1/scan-jobs", nil))
	if w.Code != http.StatusNoContent {
		t.Fatalf("sem jobs deveria 204, got %d", w.Code)
	}
	r.Enqueue(EnqueueRequest{Tenant: "acme", Targets: []string{"10.20.1.1"}})
	w2 := httptest.NewRecorder()
	s.PollHandler()(w2, sensorReq("GET", "/v1/scan-jobs", nil))
	if w2.Code != http.StatusOK {
		t.Fatalf("com job deveria 200, got %d", w2.Code)
	}
	var job ScanJob
	json.Unmarshal(w2.Body.Bytes(), &job)
	if job.Tenant != "acme" || len(job.Targets) != 1 {
		t.Fatalf("job errado: %+v", job)
	}
}

func TestAckForeign404(t *testing.T) {
	s, r := testService(t)
	acme, _, _ := r.Enqueue(EnqueueRequest{Tenant: "acme", Targets: []string{"10.20.1.1"}})
	// Um sensor da globex tenta dar ack no job da acme.
	req := sensorReq("POST", "/v1/scan-jobs/"+acme.JobID+"/ack", nil)
	req.Header.Set("X-Client-Cert-DN", "CN=sensor-globex-1,OU=scanner-sensor,O=globex")
	req.SetPathValue("id", acme.JobID)
	w := httptest.NewRecorder()
	s.AckHandler()(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("ack cross-tenant deveria 404, got %d", w.Code)
	}
}

func TestEnqueueHandler(t *testing.T) {
	s, _ := testService(t)
	// Sem bearer → 401.
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/v1/tenants/acme/scan-jobs", bytes.NewReader([]byte("{}")))
	req.SetPathValue("t", "acme")
	s.EnqueueHandler("s3cret")(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("sem bearer deveria 401, got %d", w.Code)
	}
	// Com bearer + alvos em escopo → 201.
	w2 := httptest.NewRecorder()
	req2 := httptest.NewRequest("POST", "/api/v1/tenants/acme/scan-jobs",
		bytes.NewReader(mustJSON(enqueueBody{Targets: []string{"10.20.1.1", "8.8.8.8"}})))
	req2.Header.Set("Authorization", "Bearer s3cret")
	req2.SetPathValue("t", "acme")
	s.EnqueueHandler("s3cret")(w2, req2)
	if w2.Code != http.StatusCreated {
		t.Fatalf("enqueue válido deveria 201, got %d (%s)", w2.Code, w2.Body.String())
	}
	// Tudo fora de escopo → 422.
	w3 := httptest.NewRecorder()
	req3 := httptest.NewRequest("POST", "/api/v1/tenants/acme/scan-jobs",
		bytes.NewReader(mustJSON(enqueueBody{Targets: []string{"1.2.3.4"}})))
	req3.Header.Set("Authorization", "Bearer s3cret")
	req3.SetPathValue("t", "acme")
	s.EnqueueHandler("s3cret")(w3, req3)
	if w3.Code != http.StatusUnprocessableEntity {
		t.Fatalf("tudo fora de escopo deveria 422, got %d", w3.Code)
	}
}

func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}
