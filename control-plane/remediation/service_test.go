package remediation

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

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
