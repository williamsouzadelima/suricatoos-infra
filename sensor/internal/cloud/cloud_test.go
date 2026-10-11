package cloud

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// newTestClient wires the Client at a test server (bypassing real mTLS — the
// transport is orthogonal to the request/response logic under test).
func newTestClient(srv *httptest.Server) *Client {
	return &Client{
		cfg: Config{
			JobsURL:      srv.URL + "/agent/v1/scan-jobs",
			ReportURL:    srv.URL + "/ingest/v1/sensor-report",
			HeartbeatURL: srv.URL + "/agent/v1/heartbeat",
		},
		http: srv.Client(),
	}
}

func TestPollJobNoContent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	_, ok, err := newTestClient(srv).PollJob(context.Background())
	if err != nil || ok {
		t.Fatalf("204 deveria ser ok=false sem erro, got ok=%v err=%v", ok, err)
	}
}

func TestPollJobReturnsJob(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || !strings.HasSuffix(r.URL.Path, "/scan-jobs") {
			t.Errorf("poll deveria GET /scan-jobs, got %s %s", r.Method, r.URL.Path)
		}
		json.NewEncoder(w).Encode(Job{JobID: "j1", CorrelationID: "c1", Tenant: "acme",
			Targets: []string{"10.20.0.0/24"}, Ports: "T:1-1000"})
	}))
	defer srv.Close()
	j, ok, err := newTestClient(srv).PollJob(context.Background())
	if err != nil || !ok {
		t.Fatalf("deveria retornar job, got ok=%v err=%v", ok, err)
	}
	if j.JobID != "j1" || j.CorrelationID != "c1" || len(j.Targets) != 1 {
		t.Fatalf("job errado: %+v", j)
	}
}

func TestAckJob(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	if err := newTestClient(srv).AckJob(context.Background(), "j1"); err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(gotPath, "/scan-jobs/j1/ack") {
		t.Fatalf("ack path errado: %s", gotPath)
	}
}

func TestAckJobError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer srv.Close()
	if err := newTestClient(srv).AckJob(context.Background(), "j1"); err == nil {
		t.Fatal("404 deveria retornar erro")
	}
}

func TestPushReport(t *testing.T) {
	var body Report
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		json.Unmarshal(b, &body)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()
	rep := Report{SchemaVersion: "1.0.0", CorrelationID: "c1", SensorID: "s1",
		Findings: json.RawMessage(`[{"host":"10.20.5.5","oid":"o1"}]`)}
	if err := newTestClient(srv).PushReport(context.Background(), rep); err != nil {
		t.Fatal(err)
	}
	if body.CorrelationID != "c1" || string(body.Findings) != `[{"host":"10.20.5.5","oid":"o1"}]` {
		t.Fatalf("report body errado: %+v", body)
	}
}

func TestPushReportRejected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "forbidden", http.StatusForbidden)
	}))
	defer srv.Close()
	rep := Report{SchemaVersion: "1.0.0", CorrelationID: "c1", Findings: json.RawMessage("[]")}
	if err := newTestClient(srv).PushReport(context.Background(), rep); err == nil {
		t.Fatal("403 deveria retornar erro")
	}
}

func TestHeartbeat(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	if err := newTestClient(srv).Heartbeat(context.Background(), Heartbeat{SensorID: "s1", GvmdUp: true}); err != nil {
		t.Fatal(err)
	}
}

// TestPushReportOutlivesClientWideTimeout guards the sensor end of the report path.
// The ingest answers a sensor-report only AFTER it imported the findings (minutes in
// production), so PushReport must not be bound by the short client-wide Timeout that
// bounds poll/ack/heartbeat: a sensor that hangs up first makes the ingest cancel the
// import mid-way, and with no ack the job is re-delivered into the same wall. The
// other calls must KEEP the short timeout (a heartbeat into a black hole must not
// stall the heartbeat loop for minutes).
func TestPushReportOutlivesClientWideTimeout(t *testing.T) {
	const (
		importDelay   = 150 * time.Millisecond // the ingest "importing" the report
		clientTimeout = 50 * time.Millisecond  // stands in for Config.Timeout (60 s)
		reportTimeout = 2 * time.Second        // stands in for Config.ReportTimeout (6 min)
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(importDelay)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	cl := newTestClient(srv)
	hc := *srv.Client() // same Transport, own Timeout
	hc.Timeout = clientTimeout
	cl.http = &hc
	cl.cfg.ReportTimeout = reportTimeout

	rep := Report{SchemaVersion: "1.0.0", CorrelationID: "c1", SensorID: "s1", Findings: json.RawMessage("[]")}
	if err := cl.PushReport(context.Background(), rep); err != nil {
		t.Fatalf("PushReport deveria esperar a resposta lenta (%v > Timeout %v, mas ReportTimeout=%v): %v",
			importDelay, clientTimeout, reportTimeout, err)
	}

	// Same slow handler, same client, AFTER the PushReport above: the other calls must
	// still give up at the client-wide Timeout. Running them last also proves that
	// PushReport did not raise the shared client's Timeout in place (the heartbeat
	// goroutine uses that client concurrently).
	if cl.http.Timeout != clientTimeout {
		t.Errorf("PushReport alterou o Timeout do client compartilhado: %v (esperado %v)", cl.http.Timeout, clientTimeout)
	}
	ctx := context.Background()
	for _, c := range []struct {
		name string
		call func() error
	}{
		{"PollJob", func() error { _, _, err := cl.PollJob(ctx); return err }},
		{"AckJob", func() error { return cl.AckJob(ctx, "j1") }},
		{"Heartbeat", func() error { return cl.Heartbeat(ctx, Heartbeat{SensorID: "s1", GvmdUp: true}) }},
	} {
		err := c.call()
		var ne net.Error
		if !errors.As(err, &ne) || !ne.Timeout() {
			t.Errorf("%s deveria estourar o Timeout do client (%v < %v), got: %v", c.name, clientTimeout, importDelay, err)
		}
	}
}

// TestReportTimeoutDefault pins the sensor end of the report path's timeout chain:
//
//	sensor PushReport  >=  ingest importTimeout+writeSlack (5m30s)  >=  nginx proxy_read_timeout (300s)
//
// The sensor must be the LAST to give up. The ingest budget lives in another module
// (ingest/sensorreport/service.go) and cannot be imported here, so it is mirrored
// below: if the ingest budget grows, this constant and defaultReportTimeout follow.
func TestReportTimeoutDefault(t *testing.T) {
	const ingestBudget = 5*time.Minute + 30*time.Second // ingest importTimeout + writeSlack
	if defaultReportTimeout < ingestBudget {
		t.Fatalf("defaultReportTimeout=%v < orçamento da ingest %v: o sensor desistiria antes da ingest terminar o import",
			defaultReportTimeout, ingestBudget)
	}
	c := &Client{}
	if got := c.reportTimeout(); got != defaultReportTimeout {
		t.Fatalf("ReportTimeout sem valor deveria cair no default %v, got %v", defaultReportTimeout, got)
	}
	c.cfg.ReportTimeout = 90 * time.Second
	if got := c.reportTimeout(); got != 90*time.Second {
		t.Fatalf("ReportTimeout configurado deveria valer, got %v", got)
	}
}

// TestNewUsesSystemTrustForServer is the regression guard for the feature-dead
// blocker (ADR-0007): the mTLS client must verify the cloud's PUBLIC server cert
// against the system trust store (RootCAs nil), NOT the enrollment CA — otherwise
// every phone-home fails after enroll. It must still present the client cert (mTLS).
func TestNewUsesSystemTrustForServer(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "sensor.crt")
	keyFile := filepath.Join(dir, "sensor.key")
	writeSelfSigned(t, certFile, keyFile)

	cl, err := New(Config{JobsURL: "https://x/agent/v1/scan-jobs", CertFile: certFile, KeyFile: keyFile, CAFile: certFile})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	tr, ok := cl.http.Transport.(*http.Transport)
	if !ok || tr.TLSClientConfig == nil {
		t.Fatal("transport/tls config ausente")
	}
	if tr.TLSClientConfig.RootCAs != nil {
		t.Fatal("RootCAs deveria ser nil (system trust p/ o cert público do servidor), não a CA de enroll")
	}
	if tr.TLSClientConfig.GetClientCertificate == nil {
		t.Fatal("GetClientCertificate deveria estar setado (mTLS: sensor apresenta o cert cliente)")
	}
}

// writeSelfSigned writes a throwaway self-signed cert+key so New() can LoadX509KeyPair.
func writeSelfSigned(t *testing.T, certFile, keyFile string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test-sensor"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
}
