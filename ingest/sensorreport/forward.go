package sensorreport

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/williamsouzadelima/suricatoos-infra/ingest/scanlaunch"
)

// Forwarder pushes imported sensor findings on to the Score (reNgine), tagged by
// the server-derived tenant (ADR-0007 G). It runs AFTER the central-gvmd import,
// so the Score receives the same re-attested, in-scope findings — but the tenant
// is the authoritative cert O, never anything the sensor claimed. Disabled when
// no URL is configured (the findings still land in the central GSA).
type Forwarder struct {
	url    string
	secret string // bearer for the Score's inbound endpoint
	http   *http.Client
}

// NewForwarder builds a Forwarder. An empty url yields a no-op forwarder.
func NewForwarder(url, secret string) *Forwarder {
	return &Forwarder{url: url, secret: secret, http: &http.Client{Timeout: 30 * time.Second}}
}

// Enabled reports whether a Score endpoint is configured.
func (f *Forwarder) Enabled() bool { return f != nil && f.url != "" }

// scorePayload is what the Score's inbound import endpoint receives. The tenant is
// authoritative (server-derived); findings are the in-scope, re-attested set.
type scorePayload struct {
	SchemaVersion string               `json:"schema_version"`
	Tenant        string               `json:"tenant"`
	CorrelationID string               `json:"correlation_id"`
	Source        string               `json:"source"` // always "sensor"
	Findings      []scanlaunch.Finding `json:"findings"`
}

// Forward POSTs the findings to the Score. Errors are returned so the caller can
// log them, but they never fail the sensor-report import (the central GSA already
// has the data); the caller treats a forward error as best-effort.
func (f *Forwarder) Forward(ctx context.Context, tenant, correlationID string, findings []scanlaunch.Finding) error {
	if !f.Enabled() {
		return nil
	}
	body, _ := json.Marshal(scorePayload{
		SchemaVersion: SchemaVersion, Tenant: tenant, CorrelationID: correlationID,
		Source: "sensor", Findings: findings,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, f.url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if f.secret != "" {
		req.Header.Set("Authorization", "Bearer "+f.secret)
	}
	resp, err := f.http.Do(req)
	if err != nil {
		return err
	}
	defer func() { io.Copy(io.Discard, io.LimitReader(resp.Body, 4096)); resp.Body.Close() }()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("score push: status %d: %s", resp.StatusCode, bytes.TrimSpace(b))
	}
	return nil
}
