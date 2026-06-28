package transport

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
)

// Sender delivers a payload to the ingest plane. A nil return means success and
// the queued item is removed; any error keeps it for retry.
type Sender interface {
	Send(ctx context.Context, payload []byte) error
}

// HTTPSender POSTs payloads to an ingest URL over the provided client, which
// should carry the agent's mTLS configuration.
type HTTPSender struct {
	client *http.Client
	url    string
}

// NewHTTPSender builds an HTTPSender.
func NewHTTPSender(client *http.Client, url string) *HTTPSender {
	return &HTTPSender{client: client, url: url}
}

// Send POSTs payload as application/json; any non-2xx response is an error so
// the item stays queued for retry.
func (h *HTTPSender) Send(ctx context.Context, payload []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.url, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := h.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("ingest respondeu %d", resp.StatusCode)
	}
	return nil
}
