package remediation

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
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

// What the agent-route gate logs about a rejected request comes from outside — the cert
// (cn) and its headers — and is quoted, so a hostile value cannot start a line of its own.
func TestAuthLogLinesQuoteWhatComesFromOutside(t *testing.T) {
	evil := "x\nremediation: linha forjada"
	oneLine := func(t *testing.T, logs *lockedBuf) {
		t.Helper()
		if out := logs.String(); strings.Count(out, "\n") != 1 || !strings.Contains(out, "remediation:") {
			t.Errorf("a requisição deveria deixar exatamente UMA linha de log, got: %q", out)
		}
	}
	key, err := signkeys.LoadOrCreate("")
	if err != nil {
		t.Fatal(err)
	}
	reg, err := NewRegistry(Config{Path: filepath.Join(t.TempDir(), "r.json"), Signer: key})
	if err != nil {
		t.Fatal(err)
	}
	poll := func(svc *Service, verify, dn, serial string) int {
		t.Helper()
		req := httptest.NewRequest("GET", "/v1/remediation-jobs", nil)
		req.Header.Set("X-Client-Cert-Verify", verify)
		req.Header.Set("X-Client-Cert-DN", dn)
		req.Header.Set("X-Client-Cert-Serial", serial)
		w := httptest.NewRecorder()
		svc.PollHandler()(w, req)
		return w.Code
	}
	revokedAll := NewService(reg, nil, func(string) bool { return true }, adminSecret)

	t.Run("CRL negada: cn do cert", func(t *testing.T) {
		logs := captureLog(t)
		if code := poll(revokedAll, "SUCCESS", "CN="+evil+",OU=agent-endpoint,O=acme", "01"); code != http.StatusForbidden {
			t.Fatalf("serial revogado = %d, want 403", code)
		}
		oneLine(t, logs)
	})
	t.Run("CRL negada: serial do header", func(t *testing.T) {
		logs := captureLog(t)
		if code := poll(revokedAll, "SUCCESS", "CN=win1,OU=agent-endpoint,O=acme", evil); code != http.StatusForbidden {
			t.Fatalf("serial revogado = %d, want 403", code)
		}
		oneLine(t, logs)
	})
	t.Run("authz negada: header hostil", func(t *testing.T) {
		logs := captureLog(t)
		svc := NewService(reg, nil, func(string) bool { return false }, adminSecret)
		if code := poll(svc, evil, "CN=win1,OU=agent-endpoint,O=acme", "01"); code != http.StatusForbidden {
			t.Fatalf("verify hostil = %d, want 403", code)
		}
		oneLine(t, logs)
	})
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
	ap := adminReq(t, "POST", srv.URL+"/api/v1/remediation/jobs/"+job.JobID+"/approve", "", "operator@example.com")
	if ap.StatusCode != http.StatusOK {
		t.Fatalf("approve = %d, want 200", ap.StatusCode)
	}
	appr := decodeJob(t, ap)
	ap.Body.Close()
	if appr.State != StateApproved || appr.Signature == "" || appr.ApprovedBy != "operator@example.com" {
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

// Approve answers by the kind of failure, like reject and close: an unknown job is 404,
// a job that is not PENDING_APPROVAL is 409, and anything else — a write that fails, a
// signer that is not configured — is the server's problem, 500, with the job back to
// what it was (a 409 would send the operator hunting for a state conflict that is not
// there).
func TestApproveRouteAnswersByTheKindOfFailure(t *testing.T) {
	approve := func(t *testing.T, srv *httptest.Server, id string) int {
		t.Helper()
		resp := adminReq(t, "POST", srv.URL+"/api/v1/remediation/jobs/"+id+"/approve", `{"approved_by":"alice"}`, "")
		resp.Body.Close()
		return resp.StatusCode
	}

	t.Run("an unknown job is 404", func(t *testing.T) {
		srv, _, _ := testService(t)
		defer srv.Close()
		if code := approve(t, srv, "nao-existe"); code != http.StatusNotFound {
			t.Errorf("approve of an unknown job = %d, want 404", code)
		}
	})

	t.Run("a job that is not pending is 409", func(t *testing.T) {
		srv, reg, _ := testService(t)
		defer srv.Close()
		j := jobIn(t, reg, StateApproved)
		if code := approve(t, srv, j.JobID); code != http.StatusConflict {
			t.Errorf("approve of an APPROVED job = %d, want 409", code)
		}
	})

	t.Run("a failed write is 500 and the job is untouched", func(t *testing.T) {
		srv, reg, key := testService(t)
		defer srv.Close()
		logs := captureLog(t)
		j := jobIn(t, reg, StatePendingApproval)
		failSaves(t, reg)
		if code := approve(t, srv, j.JobID); code != http.StatusInternalServerError {
			t.Errorf("approve with a failing write = %d, want 500", code)
		}
		got, _ := reg.Get(j.JobID, "win1", "acme")
		if got.State != StatePendingApproval || got.ApprovedBy != "" || got.Signature != "" || !got.IssuedAt.IsZero() {
			t.Errorf("the failed approve left the job changed: state=%s approved_by=%q signature=%q", got.State, got.ApprovedBy, got.Signature)
		}
		if lines := linesWith(logs, "aprovado por"); len(lines) != 0 {
			t.Errorf("an approval that did not happen was audited: %q", lines)
		}
		// The failure was the write's alone: once it is fixed the very same approval goes through, signed.
		if err := os.Remove(reg.path + ".tmp"); err != nil {
			t.Fatal(err)
		}
		if code := approve(t, srv, j.JobID); code != http.StatusOK {
			t.Fatalf("approve after the write is fixed = %d, want 200", code)
		}
		if got, _ := reg.Get(j.JobID, "win1", "acme"); got.State != StateApproved || !Verify(got, key.Public()) {
			t.Errorf("the retried approval should be APPROVED and verifiable: state=%s", got.State)
		}
	})

	t.Run("a missing signer is 500", func(t *testing.T) {
		reg, err := NewRegistry(Config{Path: filepath.Join(t.TempDir(), "rem.json")}) // no signer
		if err != nil {
			t.Fatal(err)
		}
		mux := http.NewServeMux()
		NewService(reg, nil, func(string) bool { return false }, adminSecret).Register(mux)
		srv := httptest.NewServer(mux)
		defer srv.Close()
		j := enq(t, reg, "win1", "acme")
		if code := approve(t, srv, j.JobID); code != http.StatusInternalServerError {
			t.Errorf("approve without a configured signer = %d, want 500", code)
		}
		if got := stateOf(t, reg, j.JobID); got != StatePendingApproval {
			t.Errorf("the refused approve changed the job to %s", got)
		}
	})
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
			if got.State != StateRejected || got.RejectedBy != tc.wantBy {
				t.Errorf("state=%s rejected_by=%q, want REJECTED by %q", got.State, got.RejectedBy, tc.wantBy)
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
	if code := status(second.JobID, "", "operator@example.com"); code != http.StatusOK {
		t.Errorf("verified com X-Operator = %d, want 200", code)
	}
	if out := logs.String(); !strings.Contains(out, `"operator@example.com"`) {
		t.Errorf("o log deveria citar o X-Operator: %q", out)
	}
}

// listedJob / listBody mirror the listing response (only what the tests read).
type listedJob struct {
	JobID        string   `json:"job_id"`
	Tenant       string   `json:"tenant"`
	AgentID      string   `json:"agent_id"`
	State        JobState `json:"state"`
	ApprovedBy   string   `json:"approved_by"`
	RejectedBy   string   `json:"rejected_by"`
	ClosedBy     string   `json:"closed_by"`
	ClosedReason string   `json:"closed_reason"`
	Result       *struct {
		Status        string `json:"status"`
		RollbackToken string `json:"rollback_token"`
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
	j0 := mk(0, "acme", "win1", `{"marker":"PAYLOAD-MARKER-XYZ"}`) // PENDING_APPROVAL
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

	// A listagem é um resumo técnico e enxuto: payload e nonce não saem (não é uma
	// fronteira de confidencialidade, só mantém o resumo pequeno); saem o hash que
	// amarra o payload à assinatura e a própria assinatura.
	if strings.Contains(raw, "PAYLOAD-MARKER-XYZ") || strings.Contains(raw, `"payload":`) || strings.Contains(raw, `"nonce"`) {
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

// operatorID is the single place that decides WHO acted on approve/reject/verified.
// That identity lands in the audit trail, so it is trimmed and a blank one counts as
// "no operator" (the caller answers 400).
func TestOperatorIDTrimsAndNeverReturnsBlank(t *testing.T) {
	approved := func(b operatorBody) string { return b.ApprovedBy }
	for _, tc := range []struct{ name, header, body, want string }{
		{"header", "alice", "", "alice"},
		{"header is trimmed", "  alice\t", "", "alice"},
		{"body", "", `{"approved_by":"bob"}`, "bob"},
		{"body is trimmed", "", `{"approved_by":"  bob \n"}`, "bob"},
		{"header wins over the body", "alice", `{"approved_by":"bob"}`, "alice"},
		{"blank header falls back to the body", "   ", `{"approved_by":"bob"}`, "bob"},
		{"blank header and no body", "   ", "", ""},
		{"blank body field", "", `{"approved_by":"   "}`, ""},
		{"tabs and newlines only", "", `{"approved_by":"\t\n \r"}`, ""},
		{"no header and no body", "", "", ""},
		{"malformed body", "", `{"approved_by":`, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/x", strings.NewReader(tc.body))
			if tc.header != "" {
				req.Header.Set("X-Operator", tc.header)
			}
			if got := operatorID(httptest.NewRecorder(), req, approved); got != tc.want {
				t.Errorf("operatorID = %q, want %q", got, tc.want)
			}
		})
	}
}

// The audit-bearing operator routes (approve, reject, close, verified) refuse a blank
// operator (400, nothing changes) and record a padded one trimmed.
func TestOperatorRoutesRefuseBlankOperatorAndRecordItTrimmed(t *testing.T) {
	for _, rt := range []struct {
		action, field string
		fresh, after  JobState // state of the job the route acts on, before and after a successful call
		okCode        int
		recorded      func(*RemediationJob) string // where the job keeps the operator; nil = only the audit log does
	}{
		{"approve", "approved_by", StatePendingApproval, StateApproved, http.StatusOK, func(j *RemediationJob) string { return j.ApprovedBy }},
		{"reject", "rejected_by", StatePendingApproval, StateRejected, http.StatusNoContent, func(j *RemediationJob) string { return j.RejectedBy }},
		{"close", "closed_by", StateAcked, StateClosed, http.StatusOK, func(j *RemediationJob) string { return j.ClosedBy }},
		{"verified", "verified_by", StateApplied, StateVerified, http.StatusOK, nil},
	} {
		t.Run(rt.action, func(t *testing.T) {
			srv, reg, _ := testService(t)
			defer srv.Close()
			logs := captureLog(t)
			post := func(id, body string) int {
				t.Helper()
				resp := adminReq(t, "POST", srv.URL+"/api/v1/remediation/jobs/"+id+"/"+rt.action, body, "")
				resp.Body.Close()
				return resp.StatusCode
			}
			j := jobIn(t, reg, rt.fresh)

			// Blank (spaces; tab+newline+space) → 400, and the job is left alone.
			for _, nobody := range []string{"   ", `\t\n `} {
				body := `{"` + rt.field + `":"` + nobody + `"}`
				if code := post(j.JobID, body); code != http.StatusBadRequest {
					t.Errorf("%s with a blank operator (%s) = %d, want 400", rt.action, body, code)
				}
			}
			if got := stateOf(t, reg, j.JobID); got != rt.fresh {
				t.Fatalf("a refused %s changed the job to %s", rt.action, got)
			}

			// Padded → accepted, and recorded without the padding.
			if code := post(j.JobID, `{"`+rt.field+`":"  alice  "}`); code != rt.okCode {
				t.Fatalf("%s with a padded operator = %d, want %d", rt.action, code, rt.okCode)
			}
			if got := stateOf(t, reg, j.JobID); got != rt.after {
				t.Fatalf("state after %s = %s, want %s", rt.action, got, rt.after)
			}
			if rt.recorded != nil { // verified keeps no field: its record is the audit log
				got, _ := reg.Get(j.JobID, "win1", "acme")
				if who := rt.recorded(got); who != "alice" {
					t.Errorf("%s recorded the operator as %q, want %q", rt.action, who, "alice")
				}
			}
			out := logs.String()
			if strings.Contains(out, `"  alice  "`) {
				t.Errorf("the audit log kept the padding: %s", out)
			}
			if rt.action == "verified" && !strings.Contains(out, `verificado por "alice"`) {
				t.Errorf("the audit log should name the trimmed verifier: %s", out)
			}
		})
	}
}

// What the routes answer for a job that went final: the agent's ack is a quiet 204 that
// changes nothing; the operator's approve of a REJECTED or CLOSED job and verify of a
// CLOSED one are 409s that leave the job alone.
func TestRoutesOnRejectedAndClosedJobs(t *testing.T) {
	srv, reg, _ := testService(t)
	defer srv.Close()
	closed := closedFrom(t, reg, StateApplied)
	rejected := jobIn(t, reg, StateRejected)

	operator := func(action, id, body string) int {
		t.Helper()
		resp := adminReq(t, "POST", srv.URL+"/api/v1/remediation/jobs/"+id+"/"+action, body, "")
		resp.Body.Close()
		return resp.StatusCode
	}
	if code := operator("approve", closed.JobID, `{"approved_by":"mallory"}`); code != http.StatusConflict {
		t.Errorf("approve of a CLOSED job = %d, want 409", code)
	}
	if code := operator("approve", rejected.JobID, `{"approved_by":"mallory"}`); code != http.StatusConflict {
		t.Errorf("approve of a REJECTED job = %d, want 409", code)
	}
	if code := operator("verified", closed.JobID, `{"verified_by":"mallory"}`); code != http.StatusConflict {
		t.Errorf("verified of a CLOSED job = %d, want 409", code)
	}
	resp := agentReq(t, "POST", srv.URL+"/v1/remediation-jobs/"+closed.JobID+"/ack", "win1", "acme", "")
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("ack of a CLOSED job = %d, want 204", resp.StatusCode)
	}

	if got, _ := reg.Get(closed.JobID, "win1", "acme"); got.State != StateClosed || got.ApprovedBy != "op" {
		t.Errorf("the CLOSED job changed: state=%s approved_by=%q", got.State, got.ApprovedBy)
	}
	if got, _ := reg.Get(rejected.JobID, "win1", "acme"); got.State != StateRejected || got.ApprovedBy != "" {
		t.Errorf("the REJECTED job changed: state=%s approved_by=%q", got.State, got.ApprovedBy)
	}
}

// Every audit line quotes what comes from outside, tenant and agent included — the
// approve and verify lines too, which used to print them raw. A hostile tenant or agent
// name (the operator sets both at enqueue) must not start a line of its own.
func TestApproveAndVerifiedAuditLinesQuoteTenantAndAgent(t *testing.T) {
	srv, reg, _ := testService(t)
	defer srv.Close()
	logs := captureLog(t)
	evil := "x\nremediation: job fake aprovado por \"mallory\""
	j, err := reg.Enqueue(EnqueueRequest{
		Tenant: evil, AgentID: evil, Type: TypePackagePatch, Payload: json.RawMessage(`{}`), TTL: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}

	start := len(logs.String())
	resp := adminReq(t, "POST", srv.URL+"/api/v1/remediation/jobs/"+j.JobID+"/approve", `{"approved_by":"alice"}`, "")
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("approve = %d, want 200", resp.StatusCode)
	}
	if out := logs.String()[start:]; strings.Count(out, "\n") != 1 || !strings.Contains(out, `aprovado por "alice"`) {
		t.Errorf("the approve audit entry must be ONE line naming the approver, got: %q", out)
	}

	if _, ok := reg.Poll(evil, evil); !ok {
		t.Fatal("poll must deliver the approved job")
	}
	if err := reg.Report(j.JobID, evil, evil, &Result{Status: "applied"}); err != nil {
		t.Fatal(err)
	}
	start = len(logs.String())
	resp = adminReq(t, "POST", srv.URL+"/api/v1/remediation/jobs/"+j.JobID+"/verified", `{"verified_by":"alice"}`, "")
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("verified = %d, want 200", resp.StatusCode)
	}
	if out := logs.String()[start:]; strings.Count(out, "\n") != 1 || !strings.Contains(out, `verificado por "alice"`) {
		t.Errorf("the verified audit entry must be ONE line naming the verifier, got: %q", out)
	}
}

// The close route is an operator route like the others: it answers 401 to anyone
// without the admin bearer (none, empty or wrong), and to everyone when the server has
// no admin secret configured at all (an empty secret closes the route, it does not
// open it to an empty bearer).
func TestCloseRouteRequiresBearer(t *testing.T) {
	srv, reg, _ := testService(t)
	defer srv.Close()
	j := jobIn(t, reg, StateAcked)

	noSecret := httptest.NewServer(func() http.Handler {
		mux := http.NewServeMux()
		NewService(reg, nil, func(string) bool { return false }, "").Register(mux)
		return mux
	}())
	defer noSecret.Close()

	for _, tc := range []struct {
		name, base, auth string
	}{
		{"sem Authorization", srv.URL, ""},
		{"bearer vazio", srv.URL, "Bearer "},
		{"bearer errado", srv.URL, "Bearer errado"},
		{"servidor sem secret e bearer vazio", noSecret.URL, "Bearer "},
		{"servidor sem secret e sem Authorization", noSecret.URL, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req, _ := http.NewRequest("POST", tc.base+"/api/v1/remediation/jobs/"+j.JobID+"/close", strings.NewReader(`{"closed_by":"alice"}`))
			if tc.auth != "" {
				req.Header.Set("Authorization", tc.auth)
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusUnauthorized {
				t.Errorf("close = %d, want 401", resp.StatusCode)
			}
		})
	}
	if got := stateOf(t, reg, j.JobID); got != StateAcked {
		t.Errorf("a refused close changed the job to %s", got)
	}
}

// Closing is an intervention by a person: the operator is required (X-Operator, or
// closed_by in the body since nginx clears the header on /agent/api/) and a missing or
// blank one is a 400 that leaves the job alone. Another route's field does not count.
func TestCloseRouteNeedsTheOperator(t *testing.T) {
	srv, reg, _ := testService(t)
	defer srv.Close()
	j := jobIn(t, reg, StateAcked)
	for _, tc := range []struct{ name, body string }{
		{"corpo vazio", ""},
		{"objeto vazio", `{}`},
		{"campo vazio", `{"closed_by":""}`},
		{"campo em branco", `{"closed_by":"   "}`},
		{"json inválido", `{"closed_by":`},
		{"tipo errado", `{"closed_by":42}`},
		{"só o motivo", `{"reason":"sem dono"}`},
		{"campo de outra rota não vale", `{"rejected_by":"carol","verified_by":"carol","approved_by":"carol"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp := adminReq(t, "POST", srv.URL+"/api/v1/remediation/jobs/"+j.JobID+"/close", tc.body, "")
			resp.Body.Close()
			if resp.StatusCode != http.StatusBadRequest {
				t.Errorf("close = %d, want 400", resp.StatusCode)
			}
			if got := stateOf(t, reg, j.JobID); got != StateAcked {
				t.Errorf("a refused close changed the job to %s", got)
			}
		})
	}
}

// The reason is capped at 1 KiB so the audit line stays sane: counted in bytes, after
// trimming (padding does not count); a longer one is a 400 that leaves the job alone,
// and exactly 1024 bytes goes through.
func TestCloseRouteCapsTheReasonAtOneKiB(t *testing.T) {
	srv, reg, _ := testService(t)
	defer srv.Close()
	j := jobIn(t, reg, StateAcked)
	post := func(reason string) int {
		t.Helper()
		body, err := json.Marshal(map[string]string{"closed_by": "alice", "reason": reason})
		if err != nil {
			t.Fatal(err)
		}
		resp := adminReq(t, "POST", srv.URL+"/api/v1/remediation/jobs/"+j.JobID+"/close", string(body), "")
		resp.Body.Close()
		return resp.StatusCode
	}
	for _, tc := range []struct{ name, reason string }{
		{"1025 bytes", strings.Repeat("x", 1025)},
		{"multibyte: 513 × 2 bytes", strings.Repeat("é", 513)},
		{"huge", strings.Repeat("x", 50<<10)},
	} {
		if code := post(tc.reason); code != http.StatusBadRequest {
			t.Errorf("close with a %s reason = %d, want 400", tc.name, code)
		}
		if got := stateOf(t, reg, j.JobID); got != StateAcked {
			t.Fatalf("a refused close (%s) changed the job to %s", tc.name, got)
		}
	}
	// Padding is trimmed before the cap is applied: 1024 bytes of reason in 1100 of body.
	padded := "   " + strings.Repeat("x", 1024) + strings.Repeat(" ", 73)
	if code := post(padded); code != http.StatusOK {
		t.Fatalf("close with exactly 1024 bytes of reason (padded) = %d, want 200", code)
	}
	if got, _ := reg.Get(j.JobID, "win1", "acme"); got.State != StateClosed || len(got.ClosedReason) != 1024 {
		t.Errorf("state=%s reason=%d bytes, want CLOSED with the whole 1024-byte reason", got.State, len(got.ClosedReason))
	}
}

func TestCloseRoute(t *testing.T) {
	srv, reg, key := testService(t)
	defer srv.Close()
	logs := captureLog(t)
	post := func(id, body, operator string) (int, string) {
		t.Helper()
		resp := adminReq(t, "POST", srv.URL+"/api/v1/remediation/jobs/"+id+"/close", body, operator)
		defer resp.Body.Close()
		raw, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		return resp.StatusCode, string(raw)
	}
	view := func(raw string) listedJob {
		t.Helper()
		var w struct {
			Job listedJob `json:"job"`
		}
		if err := json.Unmarshal([]byte(raw), &w); err != nil {
			t.Fatalf("response is not {\"job\":...}: %v: %s", err, raw)
		}
		return w.Job
	}

	// The jobs the agent holds first (the poll hands out the OLDEST approved one),
	// the never-delivered one last.
	applied := reportedJob(t, reg, appliedRun)
	withHeader := jobIn(t, reg, StateDelivered)
	noReason := jobIn(t, reg, StateDelivered)
	approved := jobIn(t, reg, StateApproved)

	// Unknown id → 404.
	if code, _ := post("nao-existe", `{"closed_by":"alice"}`, ""); code != http.StatusNotFound {
		t.Errorf("close of an unknown id = %d, want 404", code)
	}

	// A job nobody delivered has Reject, not Close → 409, and it is left alone.
	code, raw := post(approved.JobID, `{"closed_by":"alice"}`, "")
	if code != http.StatusConflict {
		t.Errorf("close of an APPROVED job = %d, want 409", code)
	}
	var refusal struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal([]byte(raw), &refusal); err != nil || !strings.Contains(refusal.Error, "APPROVED") {
		t.Errorf("the 409 should explain the state in an {\"error\":...} body, got %q", raw)
	}
	if got := stateOf(t, reg, approved.JobID); got != StateApproved {
		t.Errorf("a refused close changed the job to %s", got)
	}

	// closed_by in the body (the nginx clears X-Operator); the reason is trimmed. The
	// answer is the closed job: who, why, the preserved approver and the agent's
	// result with its rollback_token — what the operator needs to revert by hand.
	code, raw = post(applied.JobID, `{"closed_by":"alice","reason":"  revertido a mão no host  "}`, "")
	if code != http.StatusOK {
		t.Fatalf("close = %d, want 200 (%s)", code, raw)
	}
	got := view(raw)
	if got.JobID != applied.JobID || got.State != StateClosed || got.ClosedBy != "alice" || got.ClosedReason != "revertido a mão no host" ||
		got.ApprovedBy != "op" || got.Result == nil || got.Result.Status != "applied" || got.Result.RollbackToken != "rb-0123" {
		t.Errorf("the response should be the CLOSED job with its approver and result: %+v", got)
	}
	stored, _ := reg.Get(applied.JobID, "win1", "acme")
	if stored.State != StateClosed || stored.ClosedBy != "alice" || stored.ClosedReason != "revertido a mão no host" || !Verify(stored, key.Public()) {
		t.Errorf("stored job wrong: state=%s by=%q reason=%q", stored.State, stored.ClosedBy, stored.ClosedReason)
	}
	if lines := linesWith(logs, `fechado por "alice"`); len(lines) != 1 || !strings.Contains(lines[0], applied.JobID) {
		t.Errorf("want one audit line naming the job and who closed it, got %q", lines)
	}

	// Closing again → 409 (nobody rewrites a closure).
	if code, _ := post(applied.JobID, `{"closed_by":"mallory"}`, ""); code != http.StatusConflict {
		t.Errorf("second close = %d, want 409", code)
	}
	if again, _ := reg.Get(applied.JobID, "win1", "acme"); again.ClosedBy != "alice" {
		t.Errorf("a second close rewrote the closure: closed_by = %q", again.ClosedBy)
	}

	// The header (gsad session, in the UI) wins over closed_by, and the reason still
	// comes from the body.
	if code, raw := post(withHeader.JobID, `{"closed_by":"alice","reason":"manutenção"}`, "operator@example.com"); code != http.StatusOK {
		t.Fatalf("close with X-Operator = %d, want 200 (%s)", code, raw)
	}
	hs, _ := reg.Get(withHeader.JobID, "win1", "acme")
	if hs.ClosedBy != "operator@example.com" || hs.ClosedReason != "manutenção" {
		t.Errorf("X-Operator should win and the body reason be kept: by=%q reason=%q", hs.ClosedBy, hs.ClosedReason)
	}

	// The reason is optional.
	if code, raw := post(noReason.JobID, `{"closed_by":"alice"}`, ""); code != http.StatusOK {
		t.Fatalf("close without a reason = %d, want 200 (%s)", code, raw)
	}
	if nr, _ := reg.Get(noReason.JobID, "win1", "acme"); nr.State != StateClosed || nr.ClosedReason != "" {
		t.Errorf("close without a reason: state=%s reason=%q", nr.State, nr.ClosedReason)
	}
}

// Reject answers 409 — not 500 — for a job it may not reject, naming the state, and
// leaves that job alone; it still answers 204 for one nobody has received (keeping that
// job's approver) and for one that is already REJECTED (a quiet no-op).
func TestRejectRouteRefusesAJobTheAgentHasReceived(t *testing.T) {
	for _, st := range []JobState{StateDelivered, StateAcked, StateApplied, StateFailed, StateVerified, StateExpired, StateClosed} {
		t.Run(string(st), func(t *testing.T) {
			srv, reg, _ := testService(t)
			defer srv.Close()
			j := jobIn(t, reg, st)
			before, _ := reg.Get(j.JobID, "win1", "acme")
			resp := adminReq(t, "POST", srv.URL+"/api/v1/remediation/jobs/"+j.JobID+"/reject", `{"rejected_by":"alice"}`, "")
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusConflict {
				t.Errorf("reject of a %s job = %d, want 409", st, resp.StatusCode)
			}
			var body struct {
				Error string `json:"error"`
			}
			if err := json.NewDecoder(resp.Body).Decode(&body); err != nil || !strings.Contains(body.Error, string(st)) {
				t.Errorf("the 409 should explain the state in an {\"error\":...} body: %+v (%v)", body, err)
			}
			after, _ := reg.Get(j.JobID, "win1", "acme")
			if after.State != st || after.ApprovedBy != before.ApprovedBy || after.RejectedBy != before.RejectedBy {
				t.Errorf("a refused reject changed the job: %+v -> %+v", before, after)
			}
		})
	}
	t.Run("APPROVED keeps its approver", func(t *testing.T) {
		srv, reg, _ := testService(t)
		defer srv.Close()
		j := jobIn(t, reg, StateApproved)
		resp := adminReq(t, "POST", srv.URL+"/api/v1/remediation/jobs/"+j.JobID+"/reject", `{"rejected_by":"alice"}`, "")
		resp.Body.Close()
		if resp.StatusCode != http.StatusNoContent {
			t.Fatalf("reject of an APPROVED job = %d, want 204", resp.StatusCode)
		}
		got, _ := reg.Get(j.JobID, "win1", "acme")
		if got.State != StateRejected || got.RejectedBy != "alice" || got.ApprovedBy != "op" {
			t.Errorf("state=%s rejected_by=%q approved_by=%q, want REJECTED by alice, approved by op", got.State, got.RejectedBy, got.ApprovedBy)
		}
	})
	t.Run("REJECTED again is a quiet 204", func(t *testing.T) {
		srv, reg, _ := testService(t)
		defer srv.Close()
		logs := captureLog(t)
		j := jobIn(t, reg, StateApproved)
		reject := func(who string) int {
			t.Helper()
			resp := adminReq(t, "POST", srv.URL+"/api/v1/remediation/jobs/"+j.JobID+"/reject", `{"rejected_by":"`+who+`"}`, "")
			resp.Body.Close()
			return resp.StatusCode
		}
		if code := reject("alice"); code != http.StatusNoContent {
			t.Fatalf("first reject = %d, want 204", code)
		}
		logged := logs.String()
		if code := reject("bob"); code != http.StatusNoContent {
			t.Errorf("reject of a REJECTED job = %d, want 204", code)
		}
		got, _ := reg.Get(j.JobID, "win1", "acme")
		if got.State != StateRejected || got.RejectedBy != "alice" {
			t.Errorf("the repeated reject changed the job: state=%s rejected_by=%q, want REJECTED by alice", got.State, got.RejectedBy)
		}
		if now := logs.String(); now != logged {
			t.Errorf("a repeated reject must not log: %q", now[len(logged):])
		}
	})
}

// A write that fails is the server's problem, not the operator's: 500, and the job is
// back to what it was (close and reject undo their change before answering).
func TestOperatorWritesThatFailAreServerErrors(t *testing.T) {
	for _, tc := range []struct {
		action, body string
		fresh        JobState
	}{
		{"close", `{"closed_by":"alice"}`, StateAcked},
		{"reject", `{"rejected_by":"alice"}`, StateApproved},
	} {
		t.Run(tc.action, func(t *testing.T) {
			srv, reg, _ := testService(t)
			defer srv.Close()
			j := jobIn(t, reg, tc.fresh)
			failSaves(t, reg)
			resp := adminReq(t, "POST", srv.URL+"/api/v1/remediation/jobs/"+j.JobID+"/"+tc.action, tc.body, "")
			resp.Body.Close()
			if resp.StatusCode != http.StatusInternalServerError {
				t.Errorf("%s with a failing write = %d, want 500", tc.action, resp.StatusCode)
			}
			if got := stateOf(t, reg, j.JobID); got != tc.fresh {
				t.Errorf("the failed %s left the job in %s, want %s", tc.action, got, tc.fresh)
			}
		})
	}
}

// What the agent hears about a report that comes after the queue gave up on the job:
// a job it was handed that went final without its report, or a report that differs from
// the one on record, is a 409 (and one audit line for the operator); an exact retry is a
// quiet 204; a job the agent was never handed is a 404 with a log line of its own, and
// somebody else's job a 404 with none.
func TestReportRouteAnswersALateReportHonestly(t *testing.T) {
	srv, reg, _ := testService(t)
	defer srv.Close()
	logs := captureLog(t)
	report := func(agent, id, body string) (int, string) {
		t.Helper()
		resp := agentReq(t, "POST", srv.URL+"/v1/remediation-jobs/"+id+"/report", agent, "acme", body)
		defer resp.Body.Close()
		raw, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		return resp.StatusCode, string(raw)
	}

	// Delivered jobs first (the poll hands out the OLDEST approved one).
	failed := jobIn(t, reg, StateFailed)   // result: {"status":"failed","after":"patched"}
	applied := jobIn(t, reg, StateApplied) // result: {"status":"applied","after":"patched"}
	closed := closedFrom(t, reg, StateDelivered)
	rejected := jobIn(t, reg, StateRejected)
	approved := jobIn(t, reg, StateApproved)

	// The agent applied a job the operator had already closed.
	{
		before := len(linesWith(logs, "relatório tardio"))
		code, raw := report("win1", closed.JobID, `{"status":"applied","after":"patched","rollback_token":"rb-77"}`)
		if code != http.StatusConflict {
			t.Errorf("late report on a CLOSED job = %d, want 409 (%s)", code, raw)
		}
		if strings.Contains(raw, "rb-77") {
			t.Errorf("the answer must not echo the agent's rollback handle: %s", raw)
		}
		lines := linesWith(logs, "relatório tardio")
		if len(lines) != before+1 || !strings.Contains(lines[len(lines)-1], closed.JobID) {
			t.Errorf("a late report on a CLOSED job should leave one audit line naming it, got %q", lines)
		}
		if got, _ := reg.Get(closed.JobID, "win1", "acme"); got.Result != nil {
			t.Errorf("a refused report stored a result on the CLOSED job: %+v", got.Result)
		}
	}

	// An exact retry of what is on record is a quiet 204; a different report is a 409.
	logged := logs.String()
	if code, raw := report("win1", failed.JobID, `{"status":"failed","after":"patched"}`); code != http.StatusNoContent {
		t.Errorf("identical retry = %d, want 204 (%s)", code, raw)
	}
	if got := logs.String(); got != logged {
		t.Errorf("an identical retry must not log: %q", got[len(logged):])
	}
	if code, raw := report("win1", failed.JobID, `{"status":"applied","after":"patched"}`); code != http.StatusConflict {
		t.Errorf("contradicting report = %d, want 409 (%s)", code, raw)
	}
	if got, _ := reg.Get(failed.JobID, "win1", "acme"); got.State != StateFailed || got.Result.Status != "failed" {
		t.Errorf("the contradicting report rewrote the job: state=%s result=%+v", got.State, got.Result)
	}

	// APPLIED is not final, but its result is on record all the same: the same rule.
	logged = logs.String()
	if code, raw := report("win1", applied.JobID, `{"status":"applied","after":"patched"}`); code != http.StatusNoContent {
		t.Errorf("identical retry on an APPLIED job = %d, want 204 (%s)", code, raw)
	}
	if got := logs.String(); got != logged {
		t.Errorf("an identical retry on an APPLIED job must not log: %q", got[len(logged):])
	}
	if code, raw := report("win1", applied.JobID, `{"status":"failed","after":"WIPED"}`); code != http.StatusConflict {
		t.Errorf("contradicting report on an APPLIED job = %d, want 409 (%s)", code, raw)
	}
	if got, _ := reg.Get(applied.JobID, "win1", "acme"); got.State != StateApplied || got.Result.After != "patched" || len(got.LateReports) != 1 {
		t.Errorf("the contradicting report must leave the APPLIED job as it was and be kept: state=%s result=%+v kept=%+v", got.State, got.Result, got.LateReports)
	}

	// Somebody else's job → 404 and not a word in the log.
	logged = logs.String()
	if code, _ := report("winB", rejected.JobID, `{"status":"applied"}`); code != http.StatusNotFound {
		t.Errorf("report by another agent = %d, want 404", code)
	}
	if got := logs.String(); got != logged {
		t.Errorf("a report by somebody else's agent must not log: %q", got[len(logged):])
	}

	// A job the agent was never handed (rejected before the poll, or still approved) →
	// 404, one "nunca entregue" line each, and nothing kept.
	for name, j := range map[string]*RemediationJob{"REJECTED": rejected, "APPROVED": approved} {
		before := len(linesWith(logs, "relatório de job nunca entregue"))
		if code, raw := report("win1", j.JobID, `{"status":"applied","rollback_token":"rb-55"}`); code != http.StatusNotFound {
			t.Errorf("report of a never-delivered %s job = %d, want 404 (%s)", name, code, raw)
		}
		lines := linesWith(logs, "relatório de job nunca entregue")
		if len(lines) != before+1 || !strings.Contains(lines[len(lines)-1], j.JobID) {
			t.Errorf("a report on a never-delivered %s job should leave one line naming it, got %q", name, lines)
		}
		if got, _ := reg.Get(j.JobID, "win1", "acme"); got.Result != nil || len(got.LateReports) != 0 {
			t.Errorf("the %s job kept something from a report it should never have had: %+v %+v", name, got.Result, got.LateReports)
		}
	}
}

// The listing shows the new state and who rejected/closed — next to the approver the
// job keeps — and the closed job's result (rollback_token included); a job that was
// neither carries none of those keys.
func TestListShowsRejectedAndClosedJobs(t *testing.T) {
	srv, reg, _ := testService(t)
	defer srv.Close()

	applied := reportedJob(t, reg, appliedRun)
	if _, err := reg.Close(applied.JobID, "bob", "revertido a mão"); err != nil {
		t.Fatal(err)
	}
	rejected := jobIn(t, reg, StateApproved)
	if err := reg.Reject(rejected.JobID, "alice"); err != nil {
		t.Fatal(err)
	}
	plain := jobIn(t, reg, StateApproved)

	code, raw, lb := getList(t, srv, "")
	if code != http.StatusOK {
		t.Fatalf("list = %d, want 200 (%s)", code, raw)
	}
	byID := map[string]listedJob{}
	for _, j := range lb.Jobs {
		byID[j.JobID] = j
	}
	if c := byID[applied.JobID]; c.State != StateClosed || c.ClosedBy != "bob" || c.ClosedReason != "revertido a mão" || c.ApprovedBy != "op" ||
		c.Result == nil || c.Result.Status != "applied" || c.Result.RollbackToken != "rb-0123" {
		t.Errorf("closed job in the listing: %+v", c)
	}
	if rj := byID[rejected.JobID]; rj.State != StateRejected || rj.RejectedBy != "alice" || rj.ApprovedBy != "op" || rj.ClosedBy != "" {
		t.Errorf("rejected job in the listing: %+v", rj)
	}

	var keys struct {
		Jobs []map[string]json.RawMessage `json:"jobs"`
	}
	if err := json.Unmarshal([]byte(raw), &keys); err != nil {
		t.Fatal(err)
	}
	for _, j := range keys.Jobs {
		var id string
		_ = json.Unmarshal(j["job_id"], &id)
		if id != plain.JobID {
			continue
		}
		for _, k := range []string{"rejected_by", "rejected_at", "closed_by", "closed_at", "closed_reason"} {
			if _, present := j[k]; present {
				t.Errorf("a job that was neither rejected nor closed should not carry %q: %s", k, raw)
			}
		}
	}

	for _, tc := range []struct{ query, want string }{
		{"?state=CLOSED", applied.JobID},
		{"?state=closed", applied.JobID},
		{"?state=REJECTED", rejected.JobID},
	} {
		code, raw, got := getList(t, srv, tc.query)
		if code != http.StatusOK {
			t.Errorf("list%s = %d, want 200 (%s)", tc.query, code, raw)
			continue
		}
		sameIDs(t, "list"+tc.query, got, tc.want)
	}
	// A bad state is a 400 that names CLOSED among the valid ones.
	resp := adminReq(t, "GET", srv.URL+"/api/v1/remediation/jobs?state=FECHADO", "", "")
	defer resp.Body.Close()
	msg, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusBadRequest || !strings.Contains(string(msg), "CLOSED") {
		t.Errorf("list?state=FECHADO = %d %q, want 400 naming CLOSED", resp.StatusCode, msg)
	}
}

// The status routes say WHEN a job was verified or expired: verified_at in the answer of
// the verified route and in the listing, expired_at in the listing — each only on the job
// it belongs to. A job that was neither carries neither key.
func TestStatusRoutesShowWhenAJobWasVerifiedOrExpired(t *testing.T) {
	srv, reg, _ := testService(t)
	defer srv.Close()
	day := 24 * time.Hour

	reg.now = at(clockBase)
	applied := jobIn(t, reg, StateApplied)
	lapsing := jobIn(t, reg, StateApproved) // 1h TTL, never handed out

	reg.now = at(clockBase.Add(8 * day)) // the agent's first poll after the deadline sweeps it (an Enqueue would too)
	if _, ok := reg.Poll("win1", "acme"); ok {
		t.Fatal("the poll must not deliver a job past its deadline")
	}
	plain := jobIn(t, reg, StatePendingApproval)

	reg.now = at(clockBase.Add(9 * day))
	resp := adminReq(t, "POST", srv.URL+"/api/v1/remediation/jobs/"+applied.JobID+"/verified", `{"verified_by":"alice"}`, "")
	answer := decodeJob(t, resp)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || answer == nil || answer.State != StateVerified || !answer.VerifiedAt.Equal(clockBase.Add(9*day)) {
		t.Errorf("verified = %d, job %+v: want 200 and the VERIFIED job stamped on day 9", resp.StatusCode, answer)
	}

	code, raw, _ := getList(t, srv, "")
	if code != http.StatusOK {
		t.Fatalf("list = %d (%s)", code, raw)
	}
	var parsed struct {
		Jobs []map[string]json.RawMessage `json:"jobs"`
	}
	if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
		t.Fatal(err)
	}
	byID := map[string]map[string]json.RawMessage{}
	for _, j := range parsed.Jobs {
		var id string
		_ = json.Unmarshal(j["job_id"], &id)
		byID[id] = j
	}
	for _, tc := range []struct {
		name              string
		id                string
		verified, expired time.Time // the stamp the listing must show; zero = the key must be absent
	}{
		{"verified", applied.JobID, clockBase.Add(9 * day), time.Time{}},
		{"expired", lapsing.JobID, time.Time{}, clockBase.Add(8 * day)},
		{"neither", plain.JobID, time.Time{}, time.Time{}},
	} {
		for _, k := range []struct {
			key  string
			want time.Time
		}{{"verified_at", tc.verified}, {"expired_at", tc.expired}} {
			rawStamp, present := byID[tc.id][k.key]
			switch {
			case k.want.IsZero() && present:
				t.Errorf("%s job: the listing should not carry %q, got %s", tc.name, k.key, rawStamp)
			case !k.want.IsZero():
				var got time.Time
				if !present || json.Unmarshal(rawStamp, &got) != nil || !got.Equal(k.want) {
					t.Errorf("%s job: %q = %s (present=%v), want %v", tc.name, k.key, rawStamp, present, k.want)
				}
			}
		}
	}
}

// A refused report is not lost: the operator finds it whole — rollback_token included —
// in the listing and in the answer of close, next to the late_reports_total that the
// audit line's "late_report #n" counts against. A job that never had a report refused
// carries neither key. (The listing needs the bearer, like every operator route.)
func TestOperatorSeesTheRefusedLateReports(t *testing.T) {
	srv, reg, _ := testService(t)
	defer srv.Close()
	report := func(id, body string) int {
		t.Helper()
		resp := agentReq(t, "POST", srv.URL+"/v1/remediation-jobs/"+id+"/report", "win1", "acme", body)
		resp.Body.Close()
		return resp.StatusCode
	}
	type keptReport struct {
		Status        string    `json:"status"`
		Detail        string    `json:"detail"`
		Before        string    `json:"before"`
		After         string    `json:"after"`
		RollbackToken string    `json:"rollback_token"`
		RebootPending bool      `json:"reboot_pending"`
		ReportedAt    time.Time `json:"reported_at"`
	}
	type jobWithLate struct {
		JobID            string       `json:"job_id"`
		LateReports      []keptReport `json:"late_reports"`
		LateReportsTotal int          `json:"late_reports_total"`
	}

	// Delivered jobs first (the poll hands out the OLDEST approved one).
	applied := reportedJob(t, reg, appliedRun)
	closed := closedFrom(t, reg, StateDelivered)
	plain := jobIn(t, reg, StateApproved)

	// The agent applied a change after the operator closed the job, and contradicts
	// itself on the APPLIED one: both are refused and kept.
	if code := report(closed.JobID, `{"status":"applied","detail":"ok","before":"v1","after":"v2","rollback_token":"rb-77","reboot_pending":true}`); code != http.StatusConflict {
		t.Fatalf("late report on the CLOSED job = %d, want 409", code)
	}
	if code := report(applied.JobID, `{"status":"failed","after":"WIPED","rollback_token":"rb-88"}`); code != http.StatusConflict {
		t.Fatalf("contradicting report on the APPLIED job = %d, want 409", code)
	}

	code, raw, _ := getList(t, srv, "")
	if code != http.StatusOK {
		t.Fatalf("list = %d (%s)", code, raw)
	}
	var lb struct {
		Jobs []jobWithLate `json:"jobs"`
	}
	if err := json.Unmarshal([]byte(raw), &lb); err != nil {
		t.Fatal(err)
	}
	byID := map[string]jobWithLate{}
	for _, j := range lb.Jobs {
		byID[j.JobID] = j
	}
	c := byID[closed.JobID]
	if c.LateReportsTotal != 1 || len(c.LateReports) != 1 {
		t.Fatalf("CLOSED job: total=%d kept=%d, want 1 and 1 (%s)", c.LateReportsTotal, len(c.LateReports), raw)
	}
	if k := c.LateReports[0]; k.Status != "applied" || k.Detail != "ok" || k.Before != "v1" || k.After != "v2" || k.RollbackToken != "rb-77" || !k.RebootPending || k.ReportedAt.IsZero() {
		t.Errorf("the listing should show the whole refused report: %+v", k)
	}
	if a := byID[applied.JobID]; a.LateReportsTotal != 1 || len(a.LateReports) != 1 || a.LateReports[0].RollbackToken != "rb-88" {
		t.Errorf("APPLIED job in the listing: %+v", a)
	}

	// A job nobody refused anything for has neither key.
	var keys struct {
		Jobs []map[string]json.RawMessage `json:"jobs"`
	}
	if err := json.Unmarshal([]byte(raw), &keys); err != nil {
		t.Fatal(err)
	}
	for _, j := range keys.Jobs {
		var id string
		_ = json.Unmarshal(j["job_id"], &id)
		if id != plain.JobID {
			continue
		}
		for _, k := range []string{"late_reports", "late_reports_total"} {
			if _, present := j[k]; present {
				t.Errorf("a job with no refused report should not carry %q: %s", k, raw)
			}
		}
	}

	// Closing the APPLIED job answers with the job as it is now — refused report included.
	resp := adminReq(t, "POST", srv.URL+"/api/v1/remediation/jobs/"+applied.JobID+"/close", `{"closed_by":"alice"}`, "")
	defer resp.Body.Close()
	var closedAnswer struct {
		Job jobWithLate `json:"job"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&closedAnswer); err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("close = %d (%v)", resp.StatusCode, err)
	}
	if got := closedAnswer.Job; got.LateReportsTotal != 1 || len(got.LateReports) != 1 || got.LateReports[0].RollbackToken != "rb-88" {
		t.Errorf("the close answer should carry the refused report: %+v", got)
	}
}

// The agent that sends the same refused report again (a retry) hears exactly the same
// 409 — it names the kept report — and neither the job nor the log grows.
func TestRepeatedLateReportGetsTheSame409OverHTTP(t *testing.T) {
	srv, reg, _ := testService(t)
	defer srv.Close()
	logs := captureLog(t)
	closed := closedFrom(t, reg, StateDelivered)
	post := func() (int, string) {
		t.Helper()
		resp := agentReq(t, "POST", srv.URL+"/v1/remediation-jobs/"+closed.JobID+"/report", "win1", "acme",
			`{"status":"applied","before":"v1","after":"v2","rollback_token":"rb-77"}`)
		defer resp.Body.Close()
		raw, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		return resp.StatusCode, string(raw)
	}
	code1, first := post()
	if code1 != http.StatusConflict || !strings.Contains(first, "late_report #1") {
		t.Fatalf("first refusal = %d %q, want 409 naming late_report #1", code1, first)
	}
	logged := logs.String()
	code2, second := post()
	if code2 != http.StatusConflict || second != first {
		t.Errorf("the repeat should get the very same 409: %d %q, first was %q", code2, second, first)
	}
	if got := logs.String(); got != logged {
		t.Errorf("a repeated report must not log: %q", got[len(logged):])
	}
	if got, _ := reg.Get(closed.JobID, "win1", "acme"); got.LateReportsTotal != 1 || len(got.LateReports) != 1 {
		t.Errorf("a repeat must not be kept again: total=%d kept=%d", got.LateReportsTotal, len(got.LateReports))
	}
}

// The job the agent polls is the wire contract (schema/remediation-job.schema.json,
// additionalProperties false): the fields of a rejection, a closure, a verification or
// an expiry that never happened, and of late reports that never came, stay off it
// instead of showing up as year-1 timestamps or empty lists.
func TestPollBodyOmitsTheRejectAndCloseFieldsOfALiveJob(t *testing.T) {
	srv, reg, _ := testService(t)
	defer srv.Close()
	jobIn(t, reg, StateApproved)
	resp := agentReq(t, "GET", srv.URL+"/v1/remediation-jobs", "win1", "acme", "")
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(raw), `"approved_by":"op"`) {
		t.Fatalf("poll = %d, want 200 with the approved job: %s", resp.StatusCode, raw)
	}
	for _, key := range []string{`"rejected_`, `"closed_`, `"late_reports`, `"verified_at`, `"expired_at`} {
		if strings.Contains(string(raw), key) {
			t.Errorf("the polled job should not carry %s... fields: %s", key, raw)
		}
	}
}
