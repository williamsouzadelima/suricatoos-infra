// Package command implements the agent side of the control-plane command
// channel. The agent polls for a pending command over its mTLS channel and acks
// it once processed. Only "scan_now" — an immediate local inventory re-collect —
// is supported; the agent stays passive and local-only (never a network scan).
//
// The agent always initiates (poll), preserving the outbound-only invariant: no
// inbound listener is added.
package command

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// ScanNow re-runs the local inventory collection now.
const ScanNow = "scan_now"

// Command is a pending instruction returned by the control-plane.
type Command struct {
	ID   string `json:"id"`
	Type string `json:"type"`
}

// Poll fetches the agent's pending command from serverURL+"/commands" over the
// mTLS client hc. It returns (nil, nil) when there is no pending command (the
// control-plane replies 204). serverURL is the enrolled control-plane base
// (ending in /v1), the same value used for enroll/update.
func Poll(ctx context.Context, hc *http.Client, serverURL string) (*Command, error) {
	url := strings.TrimRight(serverURL, "/") + "/commands"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("commands respondeu %d", resp.StatusCode)
	}
	var c Command
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&c); err != nil {
		return nil, fmt.Errorf("decodificar comando: %w", err)
	}
	if c.ID == "" {
		return nil, nil
	}
	return &c, nil
}

// Ack confirms a processed command so the control-plane drops it.
func Ack(ctx context.Context, hc *http.Client, serverURL, id string) error {
	url := strings.TrimRight(serverURL, "/") + "/commands/ack"
	body, _ := json.Marshal(struct {
		ID string `json:"id"`
	}{ID: id})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("ack respondeu %d", resp.StatusCode)
	}
	return nil
}
