// Package cloud is the sensor's phone-home mTLS client to the Suricatoos cloud
// (ADR-0007): poll the next scan job, ack it, push the findings report, and
// heartbeat. Every call is outbound (the sensor never listens), authenticated by
// the sensor's enrolled client cert (O=tenant, OU=scanner-sensor).
package cloud

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Job is a dispatched scan job (schema/scan-job.schema.json).
type Job struct {
	JobID         string   `json:"job_id"`
	CorrelationID string   `json:"correlation_id"`
	Tenant        string   `json:"tenant"`
	Targets       []string `json:"targets"`
	Ports         string   `json:"ports"`
	ScanConfig    string   `json:"scan_config"`
	AliveTest     string   `json:"alive_test"`
	MaxDuration   string   `json:"max_duration"`
}

// Report is the sensor-report payload (schema/sensor-report.schema.json). Findings
// is left as raw JSON so this package doesn't couple to the scanrun Finding type.
type Report struct {
	SchemaVersion string          `json:"schema_version"`
	CorrelationID string          `json:"correlation_id"`
	SensorID      string          `json:"sensor_id"`
	FeedVersion   string          `json:"feed_version,omitempty"`
	CollectedAt   string          `json:"collected_at,omitempty"`
	Findings      json.RawMessage `json:"findings"`
}

// Heartbeat is the periodic liveness payload.
type Heartbeat struct {
	SensorID    string `json:"sensor_id"`
	FeedVersion string `json:"feed_version,omitempty"`
	GvmdUp      bool   `json:"gvmd_up"`
	ActiveJobs  int    `json:"active_jobs"`
}

// Config configures the client. URLs come from the enroll response; the cert/key/ca
// are the enrolled mTLS material on disk.
type Config struct {
	JobsURL      string // .../agent/v1/scan-jobs
	ReportURL    string // .../ingest/v1/sensor-report
	HeartbeatURL string // .../agent/v1/heartbeat
	CertFile     string
	KeyFile      string
	CAFile       string

	// Timeout bounds poll, ack and heartbeat — each a quick round trip (default 60 s).
	Timeout time.Duration
	// ReportTimeout bounds PushReport alone (default defaultReportTimeout).
	ReportTimeout time.Duration
}

// defaultReportTimeout is the PushReport timeout when Config.ReportTimeout is unset.
//
// The ingest answers a sensor-report only AFTER it imported the findings into gvmd
// (minutes for a big scan, versus milliseconds for poll/ack/heartbeat), so PushReport
// cannot share the short client-wide Timeout. The timeouts of the report path form a
// chain, and the sensor must be the LAST link to give up:
//
//	sensor PushReport (this constant, 6 min)
//	  >= ingest importTimeout + writeSlack (5 min 30 s, ingest/sensorreport/service.go)
//	  >= nginx proxy_read_timeout of /ingest/v1/sensor-report (300 s, compose/nginx/default.conf)
//
// If the sensor hangs up first, the connection closes, the ingest request context is
// cancelled and exec.CommandContext kills bridge.py mid-import; with no ack the job is
// re-delivered every few minutes into the same wall until its TTL (a silently lost or a
// duplicated report). Change one link and revisit the others.
const defaultReportTimeout = 6 * time.Minute

// reportTimeout is how long PushReport waits for the ingest's answer.
func (c *Client) reportTimeout() time.Duration {
	if c.cfg.ReportTimeout > 0 {
		return c.cfg.ReportTimeout
	}
	return defaultReportTimeout
}

// Client is the mTLS cloud client.
type Client struct {
	cfg  Config
	http *http.Client
}

// New builds a Client with an mTLS transport. The client cert is reloaded from disk
// per TLS handshake (GetClientCertificate), so a cert rotation (ADR-0007 renew) is
// picked up on the next connection without a restart.
func New(cfg Config) (*Client, error) {
	// Validate the material up front (a bad path should fail loudly at startup).
	if _, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile); err != nil {
		return nil, fmt.Errorf("cert cliente: %w", err)
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	hc := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
					c, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
					return &c, err
				},
				// RootCAs nil → the SERVER cert (the cloud's public Let's Encrypt leaf,
				// e.g. scanner.suricatoos.com) is verified against the SYSTEM trust
				// store, NOT the enrollment CA. The enrollment CA is what the SERVER
				// (nginx) uses to verify the sensor's CLIENT cert (mTLS). Pinning the
				// enrollment CA here made every phone-home fail with "unable to get
				// local issuer certificate" — the same regression fixed in the endpoint
				// agent (see agent/internal/enroll TLSClientConfig). cfg.CAFile is kept
				// for feed-manifest verification (feedsync), not for server auth.
				MinVersion: tls.VersionTLS12,
			},
		},
	}
	return &Client{cfg: cfg, http: hc}, nil
}

// PollJob returns the next job (ok=false on 204 = nothing to do).
func (c *Client) PollJob(ctx context.Context) (*Job, bool, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, c.cfg.JobsURL, nil)
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, false, err
	}
	defer drain(resp)
	if resp.StatusCode == http.StatusNoContent {
		return nil, false, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, false, statusErr("poll", resp)
	}
	var j Job
	if err := json.NewDecoder(resp.Body).Decode(&j); err != nil {
		return nil, false, fmt.Errorf("poll: decode: %w", err)
	}
	return &j, true, nil
}

// AckJob acknowledges receipt of a job.
func (c *Client) AckJob(ctx context.Context, jobID string) error {
	url := c.cfg.JobsURL + "/" + jobID + "/ack"
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer drain(resp)
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		return statusErr("ack", resp)
	}
	return nil
}

// PushReport uploads the findings report. Unlike the other calls it waits up to
// reportTimeout() — not the client-wide Timeout — because the ingest replies only
// after importing the report (see defaultReportTimeout for the timeout chain).
func (c *Client) PushReport(ctx context.Context, r Report) error {
	body, _ := json.Marshal(r)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.ReportURL, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	// Shallow copy of the shared client: same Transport (connection pool, client cert
	// reloaded per handshake), own Timeout. Never raise Timeout on c.http itself — the
	// heartbeat goroutine uses it concurrently and must keep the short one.
	rc := *c.http
	rc.Timeout = c.reportTimeout()
	resp, err := rc.Do(req)
	if err != nil {
		return err
	}
	defer drain(resp)
	if resp.StatusCode != http.StatusAccepted && resp.StatusCode != http.StatusOK {
		return statusErr("report", resp)
	}
	return nil
}

// Heartbeat posts a liveness ping.
func (c *Client) Heartbeat(ctx context.Context, hb Heartbeat) error {
	body, _ := json.Marshal(hb)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.HeartbeatURL, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer drain(resp)
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusAccepted {
		return statusErr("heartbeat", resp)
	}
	return nil
}

func drain(resp *http.Response) {
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()
}

func statusErr(op string, resp *http.Response) error {
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
	return fmt.Errorf("%s: status %d: %s", op, resp.StatusCode, bytes.TrimSpace(b))
}
