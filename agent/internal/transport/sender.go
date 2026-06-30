package transport

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
)

// ErrPermanent marks a delivery failure that will never succeed on retry — a 4xx
// client error such as a malformed/rejected inventory. The queue DROPS such items
// instead of blocking the whole backlog on them forever (408/429 stay retryable).
var ErrPermanent = errors.New("permanent delivery failure")

// Sender delivers a payload to the ingest plane. A nil return means success and
// the queued item is removed; a transient error keeps it for retry; an error
// wrapping ErrPermanent tells the queue to drop the item.
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
		// 4xx (except 408/429) won't succeed on retry — mark permanent so the
		// queue drops the item instead of blocking forever behind it.
		if resp.StatusCode >= 400 && resp.StatusCode < 500 &&
			resp.StatusCode != http.StatusRequestTimeout && resp.StatusCode != http.StatusTooManyRequests {
			return fmt.Errorf("ingest respondeu %d: %w", resp.StatusCode, ErrPermanent)
		}
		return fmt.Errorf("ingest respondeu %d", resp.StatusCode)
	}
	return nil
}
