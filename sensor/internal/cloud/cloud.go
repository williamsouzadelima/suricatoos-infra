// Package cloud is the sensor's phone-home mTLS client to the Suricatoos cloud
// (ADR-0007): poll the next scan job, ack it, push the findings report, and
// heartbeat. Every call is outbound (the sensor never listens), authenticated by
// the sensor's enrolled client cert (O=tenant, OU=scanner-sensor).
package cloud

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
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
	Timeout      time.Duration
}

// Client is the mTLS cloud client.
type Client struct {
	cfg  Config
	http *http.Client
}

// New builds a Client with an mTLS transport (client cert + pinned CA). The client
// cert is reloaded from disk per TLS handshake (GetClientCertificate), so a cert
// rotation (ADR-0007 renew) is picked up on the next connection without a restart.
func New(cfg Config) (*Client, error) {
	// Validate the material up front (a bad path should fail loudly at startup).
	if _, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile); err != nil {
		return nil, fmt.Errorf("cert cliente: %w", err)
	}
	pool := x509.NewCertPool()
	if cfg.CAFile != "" {
		caPEM, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("ca: %w", err)
		}
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("ca PEM inválido")
		}
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
				RootCAs:    pool,
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

// PushReport uploads the findings report.
func (c *Client) PushReport(ctx context.Context, r Report) error {
	body, _ := json.Marshal(r)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.ReportURL, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
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
