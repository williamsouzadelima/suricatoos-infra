package remediate

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// signedJob builds a job with a payload, signed by priv. mutate (optional) runs
// AFTER the sha256 is computed but BEFORE signing, to craft valid variants.
func signedJob(priv ed25519.PrivateKey, mutate func(*Job)) *Job {
	j := &Job{
		SchemaVersion: "1.0.0",
		JobID:         "job-123",
		Tenant:        "acme",
		AgentID:       "win-abc",
		Type:          TypePackagePatch,
		Payload:       json.RawMessage(`{"kb":"KB5041580"}`),
		Nonce:         "nonce-1",
		State:         "APPROVED",
		IssuedAt:      time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC),
		ExpiresAt:     time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC),
		ApprovedBy:    "op@acme",
	}
	j.PayloadSHA256 = computePayloadSHA256(j.Payload)
	if mutate != nil {
		mutate(j)
	}
	j.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, Canonical(j)))
	return j
}

func serveJob(t *testing.T, job *Job) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/remediation-jobs" {
			_ = json.NewEncoder(w).Encode(job)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
}

func TestPollJobVerifiesAndReturns(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	job := signedJob(priv, nil)
	srv := serveJob(t, job)
	defer srv.Close()

	got, err := PollJob(context.Background(), srv.Client(), srv.URL, pub, job.IssuedAt.Add(time.Minute), time.Minute)
	if err != nil {
		t.Fatalf("PollJob: %v", err)
	}
	if got == nil || got.JobID != "job-123" || string(got.Payload) != `{"kb":"KB5041580"}` {
		t.Fatalf("job inesperado: %+v", got)
	}
}

func TestPollJobRejectsWrongKey(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	job := signedJob(priv, nil)
	srv := serveJob(t, job)
	defer srv.Close()

	got, err := PollJob(context.Background(), srv.Client(), srv.URL, otherPub, job.IssuedAt.Add(time.Minute), time.Minute)
	if err == nil || got != nil {
		t.Fatalf("job assinado por outra chave deve ser rejeitado (got=%v err=%v)", got, err)
	}
}

func TestPollJobRejectsTamperedPayload(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	job := signedJob(priv, nil)
	// Tamper the payload AFTER signing: its sha256 no longer matches the signed one.
	job.Payload = json.RawMessage(`{"kb":"KB0000000"}`)
	srv := serveJob(t, job)
	defer srv.Close()

	got, err := PollJob(context.Background(), srv.Client(), srv.URL, pub, job.IssuedAt.Add(time.Minute), time.Minute)
	if err == nil || got != nil {
		t.Fatalf("payload adulterado deve ser rejeitado (got=%v err=%v)", got, err)
	}
}

func TestPollJobRejectsExpired(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	job := signedJob(priv, nil)
	srv := serveJob(t, job)
	defer srv.Close()

	got, err := PollJob(context.Background(), srv.Client(), srv.URL, pub, job.ExpiresAt.Add(time.Hour), time.Minute)
	if err == nil || got != nil {
		t.Fatalf("job expirado deve ser rejeitado por PollJob (got=%v err=%v)", got, err)
	}
}

func TestPollJobNoContent(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	got, err := PollJob(context.Background(), srv.Client(), srv.URL, pub, time.Now(), time.Minute)
	if err != nil || got != nil {
		t.Fatalf("204 deve dar (nil,nil); got=%v err=%v", got, err)
	}
}

func TestAckAndReportHitCorrectPaths(t *testing.T) {
	var ackPath, reportPath string
	var reported Result
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/ack"):
			ackPath = r.URL.Path
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/report"):
			reportPath = r.URL.Path
			_ = json.NewDecoder(r.Body).Decode(&reported)
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	if err := AckJob(context.Background(), srv.Client(), srv.URL, "job-123"); err != nil {
		t.Fatalf("AckJob: %v", err)
	}
	if ackPath != "/remediation-jobs/job-123/ack" {
		t.Errorf("ack path = %q", ackPath)
	}

	res := &Result{Status: StatusApplied, Detail: "ok", After: "patched"}
	if err := ReportJob(context.Background(), srv.Client(), srv.URL, "job-123", res); err != nil {
		t.Fatalf("ReportJob: %v", err)
	}
	if reportPath != "/remediation-jobs/job-123/report" {
		t.Errorf("report path = %q", reportPath)
	}
	if reported.Status != StatusApplied || reported.After != "patched" {
		t.Errorf("result não chegou íntegro: %+v", reported)
	}
}

func TestReportJobRejectsBadStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("servidor não devia ser chamado com status inválido")
	}))
	defer srv.Close()

	if err := ReportJob(context.Background(), srv.Client(), srv.URL, "j", &Result{Status: "bogus"}); err == nil {
		t.Error("status inválido deve ser rejeitado antes do POST")
	}
}
