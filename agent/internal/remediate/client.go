package remediate

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// maxJobBytes bounds a polled job response (a job carries a small JSON payload).
const maxJobBytes = 1 << 20

// PollJob fetches the next approved remediation job for this agent from
// serverURL+"/remediation-jobs" over the mTLS client hc, and VERIFIES it before
// returning. serverURL is the enrolled control-plane base (ending in /agent/v1),
// the same value command/update use; nginx maps /agent/v1/remediation-jobs to the
// control-plane and forwards the client cert so the control-plane scopes delivery
// to this agent's CN+O.
//
// It returns (nil, nil) when there is no job (the control-plane replies 204). A
// job is returned ONLY if VerifyAt passes against pub (the remediation key pinned
// at enroll): the signature must be valid, cover the payload, bind to this job,
// and fall within its freshness window. A job that fails verification yields a
// non-nil error and is NOT returned — the caller must neither act on nor ack it;
// the control-plane redelivers or expires it. This keeps a forged/corrupt/stale
// job inert (fail-closed), mirroring update.Check's verify-inline discipline.
func PollJob(ctx context.Context, hc *http.Client, serverURL string, pub ed25519.PublicKey, now time.Time, skew time.Duration) (*Job, error) {
	if len(pub) != ed25519.PublicKeySize {
		return nil, errors.New("chave pública de remediação inválida")
	}
	u := strings.TrimRight(serverURL, "/") + "/remediation-jobs"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
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
		return nil, fmt.Errorf("remediation-jobs respondeu %d", resp.StatusCode)
	}
	var j Job
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxJobBytes)).Decode(&j); err != nil {
		return nil, fmt.Errorf("decodificar job de remediação: %w", err)
	}
	if j.JobID == "" {
		return nil, nil
	}
	if !VerifyAt(&j, pub, now, skew) {
		// Fail-closed: a job we cannot verify is treated as absent, not acted on.
		// We do NOT ack it (acking would consume it); the server redelivers/expires.
		return nil, fmt.Errorf("job %s falhou verificação (assinatura/payload/janela) — descartado", j.JobID)
	}
	return &j, nil
}

// AckJob tells the control-plane the agent accepted job id and will apply it
// (POST serverURL+"/remediation-jobs/{id}/ack"). Called only AFTER PollJob
// returned a verified job. The id travels in the path, so it is escaped.
func AckJob(ctx context.Context, hc *http.Client, serverURL, id string) error {
	u := strings.TrimRight(serverURL, "/") + "/remediation-jobs/" + url.PathEscape(id) + "/ack"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, nil)
	if err != nil {
		return err
	}
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

// ReportJob posts the apply result for job id (POST .../report). res.Status MUST
// be StatusApplied or StatusFailed — the control-plane rejects anything else.
func ReportJob(ctx context.Context, hc *http.Client, serverURL, id string, res *Result) error {
	if res == nil {
		return errors.New("result nulo")
	}
	if res.Status != StatusApplied && res.Status != StatusFailed {
		return fmt.Errorf("status inválido %q (deve ser applied|failed)", res.Status)
	}
	body, err := json.Marshal(res)
	if err != nil {
		return err
	}
	u := strings.TrimRight(serverURL, "/") + "/remediation-jobs/" + url.PathEscape(id) + "/report"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(body))
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
		return fmt.Errorf("report respondeu %d", resp.StatusCode)
	}
	return nil
}
