package sensorjobs

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
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

// POST /v1/scan-jobs/{id}/ack: o sensor só conclui o que recebeu. Um job ainda
// PENDING responde 404 (como um id desconhecido) e não muda; depois do poll o ack dá
// 204 e conclui (DONE); repetir é idempotente (204).
func TestAckHandlerOnlyForDeliveredJobs(t *testing.T) {
	s, r := testService(t)
	j, _, _ := r.Enqueue(EnqueueRequest{Tenant: "acme", Targets: []string{"10.20.1.1"}})
	ack := func() int {
		req := sensorReq("POST", "/v1/scan-jobs/"+j.JobID+"/ack", nil)
		req.SetPathValue("id", j.JobID)
		w := httptest.NewRecorder()
		s.AckHandler()(w, req)
		return w.Code
	}
	stateNow := func() JobState {
		got, _ := r.Get(j.JobID, "acme")
		return got.State
	}

	if code := ack(); code != http.StatusNotFound {
		t.Fatalf("ack de job PENDING = %d, want 404", code)
	}
	if got := stateNow(); got != StatePending {
		t.Fatalf("o ack recusado mudou o job para %s", got)
	}

	w := httptest.NewRecorder()
	s.PollHandler()(w, sensorReq("GET", "/v1/scan-jobs", nil)) // → DELIVERED
	if w.Code != http.StatusOK {
		t.Fatalf("poll = %d, want 200", w.Code)
	}
	if code := ack(); code != http.StatusNoContent {
		t.Fatalf("ack de job DELIVERED = %d, want 204", code)
	}
	if got := stateNow(); got != StateDone {
		t.Fatalf("estado após o ack = %s, want DONE", got)
	}
	if code := ack(); code != http.StatusNoContent {
		t.Fatalf("ack repetido = %d, want 204 (idempotente)", code)
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

// listReq builds GET /api/v1/tenants/{t}/scan-jobs{query} as the mux would deliver
// it. bearer == "" sends no Authorization header at all.
func listReq(tenant, query, bearer string) *http.Request {
	req := httptest.NewRequest("GET", "/api/v1/tenants/"+tenant+"/scan-jobs"+query, nil)
	req.SetPathValue("t", tenant)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	return req
}

// listedJob / listBody mirror the listing response (only what the tests read).
type listedJob struct {
	JobID   string   `json:"job_id"`
	Tenant  string   `json:"tenant"`
	State   JobState `json:"state"`
	Targets []string `json:"targets"`
}

type listBody struct {
	Jobs  []listedJob `json:"jobs"`
	Total int         `json:"total"`
	Limit int         `json:"limit"`
}

func doList(t *testing.T, s *Service, tenant, query string) (int, string, listBody) {
	t.Helper()
	w := httptest.NewRecorder()
	s.ListHandler("s3cret")(w, listReq(tenant, query, "s3cret"))
	var lb listBody
	_ = json.Unmarshal(w.Body.Bytes(), &lb)
	return w.Code, w.Body.String(), lb
}

func (l listBody) ids() []string {
	out := make([]string, 0, len(l.Jobs))
	for _, j := range l.Jobs {
		out = append(out, j.JobID)
	}
	return out
}

func sameIDs(t *testing.T, what string, got listBody, want ...string) {
	t.Helper()
	g := got.ids()
	if len(g) != len(want) {
		t.Errorf("%s: ids = %v, want %v", what, g, want)
		return
	}
	for i := range want {
		if g[i] != want[i] {
			t.Errorf("%s: ids = %v, want %v", what, g, want)
			return
		}
	}
}

// Os dois handlers de operador (enqueue e listagem) compartilham o mesmo portão
// bearer: sem header, bearer errado e — o clássico — secret VAZIO com o header
// "Bearer " (que uma comparação ingênua aceitaria) dão 401.
func TestOperatorRoutesRequireBearer(t *testing.T) {
	s, _ := testService(t)
	body := mustJSON(enqueueBody{Targets: []string{"10.20.1.1"}})
	handlers := map[string]func(secret, authz string) int{
		"list": func(secret, authz string) int {
			req := listReq("acme", "", "")
			if authz != "" {
				req.Header.Set("Authorization", authz)
			}
			w := httptest.NewRecorder()
			s.ListHandler(secret)(w, req)
			return w.Code
		},
		"enqueue": func(secret, authz string) int {
			req := httptest.NewRequest("POST", "/api/v1/tenants/acme/scan-jobs", bytes.NewReader(body))
			req.SetPathValue("t", "acme")
			if authz != "" {
				req.Header.Set("Authorization", authz)
			}
			w := httptest.NewRecorder()
			s.EnqueueHandler(secret)(w, req)
			return w.Code
		},
	}
	for name, call := range handlers {
		for _, tc := range []struct{ what, secret, authz string }{
			{"sem header", "s3cret", ""},
			{"bearer errado", "s3cret", "Bearer errado"},
			{"bearer mais longo", "s3cret", "Bearer s3cret-e-mais"},
			{"bearer mais curto", "s3cret", "Bearer s3cre"},
			{"secret cru, sem o prefixo Bearer", "s3cret", "s3cret"},
			{"esquema em minúsculas", "s3cret", "bearer s3cret"},
			{"secret vazio + header 'Bearer '", "", "Bearer "},
			{"secret vazio + sem header", "", ""},
		} {
			if code := call(tc.secret, tc.authz); code != http.StatusUnauthorized {
				t.Errorf("%s / %s = %d, want 401", name, tc.what, code)
			}
		}
		if code := call("s3cret", "Bearer s3cret"); code == http.StatusUnauthorized {
			t.Errorf("%s com o bearer certo não deveria ser 401", name)
		}
	}
}

func TestListHandlerTenantIsolation(t *testing.T) {
	s, r := testService(t)
	a1, _, _ := r.Enqueue(EnqueueRequest{Tenant: "acme", Targets: []string{"10.20.1.1"}})
	g1, _, _ := r.Enqueue(EnqueueRequest{Tenant: "globex", Targets: []string{"192.168.1.1"}})

	code, raw, lb := doList(t, s, "acme", "")
	if code != http.StatusOK {
		t.Fatalf("list = %d, want 200 (%s)", code, raw)
	}
	sameIDs(t, "acme", lb, a1.JobID)
	if lb.Jobs[0].Tenant != "acme" || len(lb.Jobs[0].Targets) != 1 {
		t.Errorf("job errado: %+v", lb.Jobs[0])
	}
	if strings.Contains(raw, g1.JobID) || strings.Contains(raw, "192.168.1.1") {
		t.Errorf("a listagem da acme vazou dado da globex: %s", raw)
	}
	_, _, lb = doList(t, s, "globex", "")
	sameIDs(t, "globex", lb, g1.JobID)

	// Tenant sem jobs (ou inexistente): 200 com lista vazia — "[]", nunca null.
	code, raw, lb = doList(t, s, "nobody", "")
	if code != http.StatusOK || len(lb.Jobs) != 0 || lb.Total != 0 || !strings.Contains(raw, `"jobs":[]`) {
		t.Errorf("tenant sem jobs: code=%d body=%s", code, raw)
	}

	// Sem o {t} no caminho → 400.
	w := httptest.NewRecorder()
	s.ListHandler("s3cret")(w, listReq("", "", "s3cret"))
	if w.Code != http.StatusBadRequest {
		t.Errorf("list sem tenant = %d, want 400", w.Code)
	}
}

func TestListHandlerFiltersOrdersAndLimits(t *testing.T) {
	s, r := testService(t)
	mk := func(minute int, target string) *ScanJob {
		r.now = at(t0.Add(time.Duration(minute) * time.Minute))
		j, _, err := r.Enqueue(EnqueueRequest{Tenant: "acme", Targets: []string{target}})
		if err != nil {
			t.Fatal(err)
		}
		return j
	}
	j0 := mk(0, "10.20.1.1")
	j1 := mk(1, "10.20.1.2")
	j2 := mk(2, "10.20.1.3")
	r.Poll("acme") // j0 → DELIVERED
	r.Ack(j0.JobID, "acme")

	code, raw, lb := doList(t, s, "acme", "")
	if code != http.StatusOK {
		t.Fatalf("list = %d, want 200 (%s)", code, raw)
	}
	sameIDs(t, "padrão (created_at desc)", lb, j2.JobID, j1.JobID, j0.JobID)
	if lb.Total != 3 || lb.Limit != 200 {
		t.Errorf("total=%d limit=%d, want 3 e 200", lb.Total, lb.Limit)
	}
	if lb.Jobs[2].State != StateDone {
		t.Errorf("o job com ack deveria aparecer DONE, got %s", lb.Jobs[2].State)
	}

	for _, tc := range []struct {
		name, query string
		want        []string
		total       int
	}{
		{"state=DONE", "?state=DONE", []string{j0.JobID}, 1},
		{"state em minúsculas", "?state=done", []string{j0.JobID}, 1},
		{"state=PENDING", "?state=PENDING", []string{j2.JobID, j1.JobID}, 2},
		{"state sem ocorrência", "?state=EXPIRED", nil, 0},
		{"limit mantém os mais novos", "?limit=2", []string{j2.JobID, j1.JobID}, 3},
		{"limit com filtro", "?state=PENDING&limit=1", []string{j2.JobID}, 2},
		{"parâmetros vazios = ausentes", "?limit=&state=", []string{j2.JobID, j1.JobID, j0.JobID}, 3},
	} {
		code, raw, got := doList(t, s, "acme", tc.query)
		if code != http.StatusOK {
			t.Errorf("%s: list = %d, want 200 (%s)", tc.name, code, raw)
			continue
		}
		sameIDs(t, tc.name, got, tc.want...)
		if got.Total != tc.total {
			t.Errorf("%s: total = %d, want %d", tc.name, got.Total, tc.total)
		}
	}

	if _, _, got := doList(t, s, "acme", "?limit=100000"); got.Limit != 1000 {
		t.Errorf("limit=100000 → limit efetivo %d, want 1000", got.Limit)
	}
	// Parâmetros inválidos são 400 (um typo não pode virar "nenhum job").
	for _, q := range []string{"?state=APLIED", "?limit=0", "?limit=-3", "?limit=abc"} {
		if code, _, _ := doList(t, s, "acme", q); code != http.StatusBadRequest {
			t.Errorf("list%s = %d, want 400", q, code)
		}
	}
}
