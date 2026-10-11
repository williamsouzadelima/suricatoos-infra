package remediation

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/williamsouzadelima/suricatoos-infra/control-plane/signkeys"
)

const adminSecret = "s3cr3t"

func testService(t *testing.T) (*httptest.Server, *Registry, *signkeys.Key) {
	t.Helper()
	key, err := signkeys.LoadOrCreate("")
	if err != nil {
		t.Fatal(err)
	}
	reg, err := NewRegistry(Config{Path: filepath.Join(t.TempDir(), "rem.json"), Signer: key})
	if err != nil {
		t.Fatal(err)
	}
	svc := NewService(reg, nil, func(string) bool { return false }, adminSecret)
	mux := http.NewServeMux()
	svc.Register(mux)
	return httptest.NewServer(mux), reg, key
}

func agentReq(t *testing.T, method, url, cn, tenant, body string) *http.Response {
	t.Helper()
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req, _ := http.NewRequest(method, url, rdr)
	req.Header.Set("X-Client-Cert-Verify", "SUCCESS")
	req.Header.Set("X-Client-Cert-DN", "CN="+cn+",OU=agent-endpoint,O="+tenant)
	req.Header.Set("X-Client-Cert-Serial", "01")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func adminReq(t *testing.T, method, url, body string, operator string) *http.Response {
	t.Helper()
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req, _ := http.NewRequest(method, url, rdr)
	req.Header.Set("Authorization", "Bearer "+adminSecret)
	if operator != "" {
		req.Header.Set("X-Operator", operator)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestAgentRoutesRequireMTLS(t *testing.T) {
	srv, _, _ := testService(t)
	defer srv.Close()

	// No cert headers at all → 403.
	resp, _ := http.Get(srv.URL + "/v1/remediation-jobs")
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("no-cert poll = %d, want 403", resp.StatusCode)
	}
	resp.Body.Close()

	// Wrong OU → 403.
	req, _ := http.NewRequest("GET", srv.URL+"/v1/remediation-jobs", nil)
	req.Header.Set("X-Client-Cert-Verify", "SUCCESS")
	req.Header.Set("X-Client-Cert-DN", "CN=win1,OU=scanner-sensor,O=acme")
	req.Header.Set("X-Client-Cert-Serial", "01")
	r2, _ := http.DefaultClient.Do(req)
	if r2.StatusCode != http.StatusForbidden {
		t.Errorf("wrong-OU poll = %d, want 403", r2.StatusCode)
	}
	r2.Body.Close()
}

func TestRevokedSerialDenied(t *testing.T) {
	key, _ := signkeys.LoadOrCreate("")
	reg, _ := NewRegistry(Config{Path: filepath.Join(t.TempDir(), "r.json"), Signer: key})
	// This serial is revoked → fail-closed.
	svc := NewService(reg, nil, func(s string) bool { return s == "1" }, adminSecret)
	mux := http.NewServeMux()
	svc.Register(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	resp := agentReq(t, "GET", srv.URL+"/v1/remediation-jobs", "win1", "acme", "")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("revoked serial poll = %d, want 403", resp.StatusCode)
	}
}

func TestNilRevokedIsFailClosed(t *testing.T) {
	key, _ := signkeys.LoadOrCreate("")
	reg, _ := NewRegistry(Config{Path: filepath.Join(t.TempDir(), "r.json"), Signer: key})
	svc := NewService(reg, nil, nil, adminSecret) // CRL not wired → deny all agent routes
	mux := http.NewServeMux()
	svc.Register(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	resp := agentReq(t, "GET", srv.URL+"/v1/remediation-jobs", "win1", "acme", "")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("nil-CRL poll = %d, want 403 (fail-closed)", resp.StatusCode)
	}
}

func TestOperatorRoutesRequireBearer(t *testing.T) {
	srv, _, _ := testService(t)
	defer srv.Close()
	resp, _ := http.Post(srv.URL+"/api/v1/remediation/jobs", "application/json", strings.NewReader(`{}`))
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("no-bearer enqueue = %d, want 401", resp.StatusCode)
	}
	resp.Body.Close()
}

func decodeJob(t *testing.T, resp *http.Response) *RemediationJob {
	t.Helper()
	var wrap struct {
		Job *RemediationJob `json:"job"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&wrap); err != nil {
		t.Fatal(err)
	}
	return wrap.Job
}

func TestFullApprovalFlowHTTP(t *testing.T) {
	srv, _, key := testService(t)
	defer srv.Close()

	// Enqueue (admin) → PENDING_APPROVAL, unsigned.
	body := `{"tenant":"acme","agent_id":"win1","type":"package_patch","payload":{"kb":"KB5041580"}}`
	resp := adminReq(t, "POST", srv.URL+"/api/v1/remediation/jobs", body, "")
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("enqueue = %d, want 201", resp.StatusCode)
	}
	job := decodeJob(t, resp)
	resp.Body.Close()
	if job.State != StatePendingApproval || job.Signature != "" {
		t.Fatalf("enqueued job wrong: state=%s sig=%q", job.State, job.Signature)
	}

	// Poll before approval → 204.
	p := agentReq(t, "GET", srv.URL+"/v1/remediation-jobs", "win1", "acme", "")
	if p.StatusCode != http.StatusNoContent {
		t.Fatalf("poll pre-approval = %d, want 204", p.StatusCode)
	}
	p.Body.Close()

	// Approve (admin + X-Operator) → signed.
	ap := adminReq(t, "POST", srv.URL+"/api/v1/remediation/jobs/"+job.JobID+"/approve", "", "operator@strati")
	if ap.StatusCode != http.StatusOK {
		t.Fatalf("approve = %d, want 200", ap.StatusCode)
	}
	appr := decodeJob(t, ap)
	ap.Body.Close()
	if appr.State != StateApproved || appr.Signature == "" || appr.ApprovedBy != "operator@strati" {
		t.Fatalf("approved job wrong: %+v", appr)
	}
	if !Verify(appr, key.Public()) {
		t.Fatal("approved job must verify against the pubkey")
	}

	// Poll (agent) → 200 signed job; poll again → 204 (delivered).
	p2 := agentReq(t, "GET", srv.URL+"/v1/remediation-jobs", "win1", "acme", "")
	if p2.StatusCode != http.StatusOK {
		t.Fatalf("poll post-approval = %d, want 200", p2.StatusCode)
	}
	delivered := new(RemediationJob)
	json.NewDecoder(p2.Body).Decode(delivered)
	p2.Body.Close()
	if delivered.Signature == "" || !Verify(delivered, key.Public()) {
		t.Fatal("delivered job must carry a verifiable signature")
	}
	p3 := agentReq(t, "GET", srv.URL+"/v1/remediation-jobs", "win1", "acme", "")
	if p3.StatusCode != http.StatusNoContent {
		t.Errorf("second poll = %d, want 204", p3.StatusCode)
	}
	p3.Body.Close()

	// Ack → 204; Report(applied) → 204.
	ack := agentReq(t, "POST", srv.URL+"/v1/remediation-jobs/"+job.JobID+"/ack", "win1", "acme", "")
	if ack.StatusCode != http.StatusNoContent {
		t.Fatalf("ack = %d, want 204", ack.StatusCode)
	}
	ack.Body.Close()
	rep := agentReq(t, "POST", srv.URL+"/v1/remediation-jobs/"+job.JobID+"/report", "win1", "acme", `{"status":"applied","after":"patched"}`)
	if rep.StatusCode != http.StatusNoContent {
		t.Fatalf("report = %d, want 204", rep.StatusCode)
	}
	rep.Body.Close()
}

func TestCrossHostIsolationHTTP(t *testing.T) {
	srv, _, _ := testService(t)
	defer srv.Close()
	body := `{"tenant":"acme","agent_id":"winA","type":"config_hardening","payload":{"set":"x"}}`
	resp := adminReq(t, "POST", srv.URL+"/api/v1/remediation/jobs", body, "")
	job := decodeJob(t, resp)
	resp.Body.Close()
	adminReq(t, "POST", srv.URL+"/api/v1/remediation/jobs/"+job.JobID+"/approve", "", "op").Body.Close()

	// A different agent (winB) must not receive or ack winA's job.
	p := agentReq(t, "GET", srv.URL+"/v1/remediation-jobs", "winB", "acme", "")
	if p.StatusCode != http.StatusNoContent {
		t.Errorf("winB poll = %d, want 204 (not winA's job)", p.StatusCode)
	}
	p.Body.Close()
	ack := agentReq(t, "POST", srv.URL+"/v1/remediation-jobs/"+job.JobID+"/ack", "winB", "acme", "")
	if ack.StatusCode != http.StatusNotFound {
		t.Errorf("winB ack of winA job = %d, want 404", ack.StatusCode)
	}
	ack.Body.Close()
}

func TestApproveNeedsApprover(t *testing.T) {
	srv, _, _ := testService(t)
	defer srv.Close()
	resp := adminReq(t, "POST", srv.URL+"/api/v1/remediation/jobs", `{"tenant":"acme","agent_id":"win1","type":"package_patch","payload":{"kb":"x"}}`, "")
	job := decodeJob(t, resp)
	resp.Body.Close()
	// Approve with no X-Operator and no body approved_by → 400.
	ap := adminReq(t, "POST", srv.URL+"/api/v1/remediation/jobs/"+job.JobID+"/approve", "", "")
	if ap.StatusCode != http.StatusBadRequest {
		t.Errorf("approve w/o approver = %d, want 400", ap.StatusCode)
	}
	ap.Body.Close()
}

func TestReportValidatesStatus(t *testing.T) {
	srv, _, _ := testService(t)
	defer srv.Close()
	resp := adminReq(t, "POST", srv.URL+"/api/v1/remediation/jobs", `{"tenant":"acme","agent_id":"win1","type":"package_patch","payload":{"kb":"x"}}`, "")
	job := decodeJob(t, resp)
	resp.Body.Close()
	adminReq(t, "POST", srv.URL+"/api/v1/remediation/jobs/"+job.JobID+"/approve", "", "op").Body.Close()
	agentReq(t, "GET", srv.URL+"/v1/remediation-jobs", "win1", "acme", "").Body.Close()
	agentReq(t, "POST", srv.URL+"/v1/remediation-jobs/"+job.JobID+"/ack", "win1", "acme", "").Body.Close()
	rep := agentReq(t, "POST", srv.URL+"/v1/remediation-jobs/"+job.JobID+"/report", "win1", "acme", `{"status":"bogus"}`)
	if rep.StatusCode != http.StatusBadRequest {
		t.Errorf("bad status = %d, want 400", rep.StatusCode)
	}
	rep.Body.Close()
}

func TestRejectRequiresOperator(t *testing.T) {
	srv, _, _ := testService(t)
	defer srv.Close()
	resp := adminReq(t, "POST", srv.URL+"/api/v1/remediation/jobs", `{"tenant":"acme","agent_id":"win1","type":"package_patch","payload":{"kb":"x"}}`, "")
	job := decodeJob(t, resp)
	resp.Body.Close()
	r1 := adminReq(t, "POST", srv.URL+"/api/v1/remediation/jobs/"+job.JobID+"/reject", "", "")
	if r1.StatusCode != http.StatusBadRequest {
		t.Errorf("reject sem operador = %d, want 400", r1.StatusCode)
	}
	r1.Body.Close()
	r2 := adminReq(t, "POST", srv.URL+"/api/v1/remediation/jobs/"+job.JobID+"/reject", "", "op")
	if r2.StatusCode != http.StatusNoContent {
		t.Errorf("reject com operador = %d, want 204", r2.StatusCode)
	}
	r2.Body.Close()
}

// lockedBuf is a goroutine-safe log sink: the handlers log from the server's
// goroutine while the test reads.
type lockedBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuf) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// captureLog redirects the std logger into a buffer for the test's lifetime.
func captureLog(t *testing.T) *lockedBuf {
	t.Helper()
	buf := &lockedBuf{}
	prev := log.Writer()
	log.SetOutput(buf)
	t.Cleanup(func() { log.SetOutput(prev) })
	return buf
}

// nginx CLEARS X-Operator on /agent/api/, so over the remote API the operator of a
// reject can only travel in the body (the runbook says so). rejected_by is the
// field; approved_by stays accepted for compatibility; the header still wins.
func TestRejectAcceptsOperatorInBody(t *testing.T) {
	srv, reg, _ := testService(t)
	defer srv.Close()
	reject := func(t *testing.T, id, body, operator string) int {
		t.Helper()
		resp := adminReq(t, "POST", srv.URL+"/api/v1/remediation/jobs/"+id+"/reject", body, operator)
		resp.Body.Close()
		return resp.StatusCode
	}
	stored := func(t *testing.T, id string) *RemediationJob {
		t.Helper()
		got, ok := reg.Get(id, "win1", "acme")
		if !ok {
			t.Fatalf("job %s not found", id)
		}
		return got
	}

	for _, tc := range []struct {
		name, body, header, wantBy string
	}{
		{"rejected_by no corpo", `{"rejected_by":"alice"}`, "", "alice"},
		{"approved_by por compatibilidade", `{"approved_by":"bob"}`, "", "bob"},
		{"rejected_by vence approved_by", `{"rejected_by":"alice","approved_by":"bob"}`, "", "alice"},
		{"o header X-Operator vence o corpo", `{"rejected_by":"alice"}`, "hdr", "hdr"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			j := jobIn(t, reg, StatePendingApproval)
			if code := reject(t, j.JobID, tc.body, tc.header); code != http.StatusNoContent {
				t.Fatalf("reject = %d, want 204", code)
			}
			got := stored(t, j.JobID)
			if got.State != StateRejected || got.ApprovedBy != tc.wantBy {
				t.Errorf("state=%s operator=%q, want REJECTED by %q", got.State, got.ApprovedBy, tc.wantBy)
			}
		})
	}

	// Sem operador em lugar nenhum → 400 e o job NÃO é rejeitado.
	for _, tc := range []struct{ name, body string }{
		{"corpo vazio", ""},
		{"objeto vazio", `{}`},
		{"campo vazio", `{"rejected_by":""}`},
		{"json inválido", `{"rejected_by":`},
		{"tipo errado", `{"rejected_by":42}`},
		{"campo de outra rota não vale", `{"verified_by":"carol"}`},
	} {
		t.Run("400 "+tc.name, func(t *testing.T) {
			j := jobIn(t, reg, StatePendingApproval)
			if code := reject(t, j.JobID, tc.body, ""); code != http.StatusBadRequest {
				t.Errorf("reject = %d, want 400", code)
			}
			if got := stored(t, j.JobID); got.State != StatePendingApproval {
				t.Errorf("a refused reject changed the job: %s", got.State)
			}
		})
	}

	// Id inexistente continua 404 (com operador válido).
	if code := reject(t, "nao-existe", `{"rejected_by":"alice"}`, ""); code != http.StatusNotFound {
		t.Errorf("reject de id inexistente = %d, want 404", code)
	}
}

func TestVerifiedRoute(t *testing.T) {
	srv, reg, _ := testService(t)
	defer srv.Close()
	logs := captureLog(t)
	verified := func(id, body, operator string) *http.Response {
		return adminReq(t, "POST", srv.URL+"/api/v1/remediation/jobs/"+id+"/verified", body, operator)
	}
	status := func(id, body, operator string) int {
		resp := verified(id, body, operator)
		resp.Body.Close()
		return resp.StatusCode
	}

	applied := jobIn(t, reg, StateApplied)
	pending := jobIn(t, reg, StatePendingApproval)

	// Sem bearer → 401 (rota de operador).
	resp, err := http.Post(srv.URL+"/api/v1/remediation/jobs/"+applied.JobID+"/verified",
		"application/json", strings.NewReader(`{"verified_by":"alice"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("verified sem bearer = %d, want 401", resp.StatusCode)
	}

	// Sem verified_by (nem X-Operator) → 400, e o job continua APPLIED.
	for _, body := range []string{"", `{}`, `{"verified_by":""}`, `not json`} {
		if code := status(applied.JobID, body, ""); code != http.StatusBadRequest {
			t.Errorf("verified sem verificador (corpo %q) = %d, want 400", body, code)
		}
	}
	if got := stateOf(t, reg, applied.JobID); got != StateApplied {
		t.Fatalf("um verified recusado mudou o estado para %s", got)
	}

	// Id inexistente → 404.
	if code := status("nao-existe", `{"verified_by":"alice"}`, ""); code != http.StatusNotFound {
		t.Errorf("verified de id inexistente = %d, want 404", code)
	}

	// Estado que não permite (ainda PENDING_APPROVAL) → 409, nada muda.
	if code := status(pending.JobID, `{"verified_by":"alice"}`, ""); code != http.StatusConflict {
		t.Errorf("verified de job PENDING_APPROVAL = %d, want 409", code)
	}
	if got := stateOf(t, reg, pending.JobID); got != StatePendingApproval {
		t.Errorf("um verified recusado mudou o estado para %s", got)
	}

	// verified_by no corpo (o nginx zera o X-Operator) → 200, VERIFIED, e o log de
	// auditoria diz QUEM verificou.
	ok := verified(applied.JobID, `{"verified_by":"alice"}`, "")
	if ok.StatusCode != http.StatusOK {
		t.Fatalf("verified = %d, want 200", ok.StatusCode)
	}
	if job := decodeJob(t, ok); job == nil || job.JobID != applied.JobID || job.State != StateVerified {
		t.Errorf("a resposta deveria trazer o job VERIFIED: %+v", job)
	}
	ok.Body.Close()
	if got := stateOf(t, reg, applied.JobID); got != StateVerified {
		t.Errorf("estado = %s, want VERIFIED", got)
	}
	if out := logs.String(); !strings.Contains(out, applied.JobID) || !strings.Contains(out, `"alice"`) {
		t.Errorf("o log de auditoria deveria citar o job e quem verificou: %q", out)
	}

	// Verificar de novo → 409 (VERIFIED não é APPLIED; ninguém reescreve o fechamento).
	if code := status(applied.JobID, `{"verified_by":"mallory"}`, ""); code != http.StatusConflict {
		t.Errorf("segundo verified = %d, want 409", code)
	}

	// O header X-Operator (sessão gsad, na UI) também vale.
	second := jobIn(t, reg, StateApplied)
	if code := status(second.JobID, "", "operator@strati"); code != http.StatusOK {
		t.Errorf("verified com X-Operator = %d, want 200", code)
	}
	if out := logs.String(); !strings.Contains(out, `"operator@strati"`) {
		t.Errorf("o log deveria citar o X-Operator: %q", out)
	}
}

// listedJob / listBody mirror the listing response (only what the tests read).
type listedJob struct {
	JobID   string   `json:"job_id"`
	Tenant  string   `json:"tenant"`
	AgentID string   `json:"agent_id"`
	State   JobState `json:"state"`
	Result  *struct {
		Status string `json:"status"`
	} `json:"result"`
}

type listBody struct {
	Jobs  []listedJob `json:"jobs"`
	Total int         `json:"total"`
	Limit int         `json:"limit"`
}

func (l listBody) ids() []string {
	out := make([]string, 0, len(l.Jobs))
	for _, j := range l.Jobs {
		out = append(out, j.JobID)
	}
	return out
}

func getList(t *testing.T, srv *httptest.Server, query string) (int, string, listBody) {
	t.Helper()
	resp := adminReq(t, "GET", srv.URL+"/api/v1/remediation/jobs"+query, "", "")
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	var lb listBody
	_ = json.Unmarshal(raw, &lb)
	return resp.StatusCode, string(raw), lb
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

func TestListRouteRequiresBearer(t *testing.T) {
	srv, _, _ := testService(t)
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/api/v1/remediation/jobs")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("list sem bearer = %d, want 401", resp.StatusCode)
	}
	req, _ := http.NewRequest("GET", srv.URL+"/api/v1/remediation/jobs", nil)
	req.Header.Set("Authorization", "Bearer errado")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("list com bearer errado = %d, want 401", resp.StatusCode)
	}
}

func TestListRouteFiltersOrdersAndLimits(t *testing.T) {
	srv, reg, _ := testService(t)
	defer srv.Close()

	// Quatro jobs com CreatedAt distintos (relógio avançando 1 min por job).
	mk := func(minute int, tenant, agent, payload string) *RemediationJob {
		reg.now = at(clockBase.Add(time.Duration(minute) * time.Minute))
		j, err := reg.Enqueue(EnqueueRequest{
			Tenant: tenant, AgentID: agent, Type: TypeConfigHardening,
			Payload: json.RawMessage(payload), TTL: 24 * time.Hour,
		})
		if err != nil {
			t.Fatal(err)
		}
		return j
	}
	j0 := mk(0, "acme", "win1", `{"secret":"TOP-SECRET-PAYLOAD"}`) // PENDING_APPROVAL
	j1 := mk(1, "acme", "win2", `{"set":"x"}`)
	j2 := mk(2, "globex", "win3", `{"set":"y"}`) // PENDING_APPROVAL
	if _, err := reg.Approve(j1.JobID, "op"); err != nil {
		t.Fatal(err)
	}
	j3 := mk(3, "acme", "win1", `{"set":"z"}`)
	if _, err := reg.Approve(j3.JobID, "op"); err != nil {
		t.Fatal(err)
	}
	if _, ok := reg.Poll("win1", "acme"); !ok { // j0 está PENDING_APPROVAL: só j3 é elegível
		t.Fatal("poll deveria entregar j3")
	}
	reg.Ack(j3.JobID, "win1", "acme")
	reg.Report(j3.JobID, "win1", "acme", &Result{Status: "applied", After: "patched"})

	// Padrão: tudo, do mais novo ao mais velho, com o limite padrão.
	code, raw, lb := getList(t, srv, "")
	if code != http.StatusOK {
		t.Fatalf("list = %d, want 200 (%s)", code, raw)
	}
	sameIDs(t, "padrão (created_at desc)", lb, j3.JobID, j2.JobID, j1.JobID, j0.JobID)
	if lb.Total != 4 || lb.Limit != 200 {
		t.Errorf("total=%d limit=%d, want 4 e 200", lb.Total, lb.Limit)
	}

	// O payload NUNCA sai (é opaco para a fila e pode carregar dado sensível); o
	// hash que o amarra à assinatura e a própria assinatura podem.
	if strings.Contains(raw, "TOP-SECRET-PAYLOAD") || strings.Contains(raw, `"payload":`) || strings.Contains(raw, `"nonce"`) {
		t.Errorf("a listagem vazou payload/nonce: %s", raw)
	}
	if !strings.Contains(raw, `"payload_sha256"`) || !strings.Contains(raw, `"signature"`) {
		t.Errorf("a listagem deveria trazer payload_sha256 e signature: %s", raw)
	}
	// O resultado do agente aparece (é o que o operador não via).
	if lb.Jobs[0].JobID != j3.JobID || lb.Jobs[0].State != StateApplied ||
		lb.Jobs[0].Result == nil || lb.Jobs[0].Result.Status != "applied" {
		t.Errorf("j3 deveria vir APPLIED com result.status=applied: %+v", lb.Jobs[0])
	}

	for _, tc := range []struct {
		name, query string
		want        []string
		total       int
	}{
		{"state=APPLIED", "?state=APPLIED", []string{j3.JobID}, 1},
		{"state em minúsculas", "?state=applied", []string{j3.JobID}, 1},
		{"state=PENDING_APPROVAL", "?state=PENDING_APPROVAL", []string{j2.JobID, j0.JobID}, 2},
		{"state=APPROVED", "?state=APPROVED", []string{j1.JobID}, 1},
		{"state sem ocorrência", "?state=VERIFIED", nil, 0},
		{"tenant=acme", "?tenant=acme", []string{j3.JobID, j1.JobID, j0.JobID}, 3},
		{"tenant=globex", "?tenant=globex", []string{j2.JobID}, 1},
		{"tenant desconhecido", "?tenant=nobody", nil, 0},
		{"agent_id=win1", "?agent_id=win1", []string{j3.JobID, j0.JobID}, 2},
		{"tenant+agent_id", "?tenant=acme&agent_id=win2", []string{j1.JobID}, 1},
		{"tenant+state", "?tenant=acme&state=PENDING_APPROVAL", []string{j0.JobID}, 1},
		{"limit corta mantendo os mais novos", "?limit=2", []string{j3.JobID, j2.JobID}, 4},
		{"limit com filtro", "?tenant=acme&limit=1", []string{j3.JobID}, 3},
	} {
		code, raw, got := getList(t, srv, tc.query)
		if code != http.StatusOK {
			t.Errorf("%s: list = %d, want 200 (%s)", tc.name, code, raw)
			continue
		}
		sameIDs(t, tc.name, got, tc.want...)
		if got.Total != tc.total {
			t.Errorf("%s: total = %d, want %d", tc.name, got.Total, tc.total)
		}
	}

	// Lista vazia é [] (nunca null) — o cliente itera sem checar.
	if _, raw, _ := getList(t, srv, "?tenant=nobody"); !strings.Contains(raw, `"jobs":[]`) {
		t.Errorf("lista vazia deveria ser \"jobs\":[]: %s", raw)
	}

	// limit acima do teto é cortado no teto e o efetivo é informado.
	if _, _, got := getList(t, srv, "?limit=100000"); got.Limit != 1000 {
		t.Errorf("limit=100000 → limit efetivo %d, want 1000", got.Limit)
	}
	if _, _, got := getList(t, srv, "?limit=2"); got.Limit != 2 {
		t.Errorf("limit=2 → limit efetivo %d, want 2", got.Limit)
	}

	// Parâmetros inválidos são 400 (um typo não pode virar "nenhum job").
	for _, q := range []string{"?state=APLIED", "?limit=0", "?limit=-3", "?limit=abc"} {
		if code, _, _ := getList(t, srv, q); code != http.StatusBadRequest {
			t.Errorf("list%s = %d, want 400", q, code)
		}
	}
	// Parâmetro presente porém vazio = ausente (usa o padrão).
	if code, _, got := getList(t, srv, "?limit=&state="); code != http.StatusOK || got.Limit != 200 || got.Total != 4 {
		t.Errorf("limit/state vazios deveriam usar o padrão: code=%d limit=%d total=%d", code, got.Limit, got.Total)
	}
}
