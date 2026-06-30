// Package update performs signed, verified auto-update of the agent binary with
// health-checked rollback, on a channel controlled by the control plane.
//
// Trust model — the update endpoint is reachable WITHOUT mTLS (it sits behind the
// same open /agent/ path as enrollment), so the channel alone is not trusted.
// Instead every manifest is signed by the enrollment CA's Ed25519 key, and the
// agent verifies that signature with the CA public key it pinned at enrollment.
// The binary is fetched over public HTTPS and bound to the manifest by SHA-256.
// So a forged manifest (no CA key) and a tampered binary (sha mismatch) are both
// rejected, and a stale manifest is rejected by an issued_at freshness window.
//
// The update is fully VERIFIED before it is applied; see apply.go for the atomic
// swap + health-checked rollback.
package update

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// canonicalPrefix tags the signed payload; bumping it invalidates old signatures.
const canonicalPrefix = "suricatoos-agent-update-v1"

// freshness bounds reject replayed/stale manifests and absurd clock skew.
const (
	maxManifestAge   = 48 * time.Hour
	maxClockSkewFuture = 5 * time.Minute
)

// Manifest is the control-plane's signed answer to an update check. The agent
// reconstructs the canonical bytes from these fields and verifies Signature
// against the pinned CA public key — so the fields are authenticated, not just
// transport-protected.
type Manifest struct {
	IssuedAt        time.Time `json:"issued_at"`
	OS              string    `json:"os"`
	Arch            string    `json:"arch"`
	Latest          string    `json:"latest"`
	UpdateAvailable bool      `json:"update_available"`
	URL             string    `json:"url"`
	SHA256          string    `json:"sha256"`
	Signature       string    `json:"signature"` // base64(ed25519 over Canonical())
}

// Target is a verified, newer release the agent should move to.
type Target struct {
	Version string
	URL     string
	SHA256  string // lower-case hex
}

// Canonical returns the exact bytes that are signed/verified. The control-plane
// MUST build this identically — field order and formatting are part of the
// contract. A bool renders as "true"/"false"; the time as RFC3339 in UTC.
func Canonical(m Manifest) []byte {
	return []byte(fmt.Sprintf(
		canonicalPrefix+"\nissued_at=%s\nos=%s\narch=%s\nlatest=%s\nupdate=%s\nurl=%s\nsha256=%s\n",
		m.IssuedAt.UTC().Format(time.RFC3339),
		m.OS, m.Arch, m.Latest,
		strconv.FormatBool(m.UpdateAvailable),
		m.URL, strings.ToLower(m.SHA256),
	))
}

// Check queries the control-plane update endpoint for os/arch and the current
// version, verifies the CA signature and freshness, and returns the Target when
// a strictly-newer release is offered (nil when up to date).
//
// serverURL is the control-plane base (the same --server used at enroll, ending
// in /v1). caPub is the enrollment CA's Ed25519 public key (Identity.CAPublicKey).
func Check(ctx context.Context, hc *http.Client, serverURL, currentVersion, goos, goarch string, caPub ed25519.PublicKey, now time.Time) (*Target, error) {
	if len(caPub) != ed25519.PublicKeySize {
		return nil, errors.New("chave pública da CA inválida")
	}
	base := strings.TrimSuffix(serverURL, "/")
	url := fmt.Sprintf("%s/update/check?os=%s&arch=%s&current=%s", base, goos, goarch, currentVersion)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode == http.StatusNoContent {
		return nil, nil // updates disabled server-side
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("update check recusado (%d): %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}

	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("manifesto inválido: %w", err)
	}
	if err := verify(m, goos, goarch, caPub, now); err != nil {
		return nil, err
	}
	if !m.UpdateAvailable || !isNewer(m.Latest, currentVersion) {
		return nil, nil
	}
	if m.URL == "" || len(m.SHA256) != 64 {
		return nil, errors.New("manifesto oferece update sem url/sha256 válidos")
	}
	return &Target{Version: m.Latest, URL: m.URL, SHA256: strings.ToLower(m.SHA256)}, nil
}

// verify checks the signature against the pinned CA key, that the manifest is for
// the platform we asked about, and that it is fresh (anti-replay).
func verify(m Manifest, goos, goarch string, caPub ed25519.PublicKey, now time.Time) error {
	sig, err := base64.StdEncoding.DecodeString(m.Signature)
	if err != nil {
		return fmt.Errorf("assinatura do manifesto malformada: %w", err)
	}
	if !ed25519.Verify(caPub, Canonical(m), sig) {
		return errors.New("assinatura do manifesto não confere com a CA pinada")
	}
	if m.OS != goos || m.Arch != goarch {
		return fmt.Errorf("manifesto é para %s/%s, esperado %s/%s", m.OS, m.Arch, goos, goarch)
	}
	if m.IssuedAt.After(now.Add(maxClockSkewFuture)) {
		return errors.New("manifesto emitido no futuro (clock skew?) — recusado")
	}
	if now.Sub(m.IssuedAt) > maxManifestAge {
		return errors.New("manifesto velho demais (replay?) — recusado")
	}
	return nil
}

// isNewer reports whether version a is strictly newer than b under a small
// semver subset: dot-separated numeric components, with any "-suffix"
// pre-release tag ignored. Non-numeric/garbage components compare as 0, so a
// malformed remote version can never appear "newer" than a real one by trickery.
func isNewer(a, b string) bool {
	pa, pb := parseVer(a), parseVer(b)
	for i := 0; i < 3; i++ {
		if pa[i] != pb[i] {
			return pa[i] > pb[i]
		}
	}
	return false
}

// parseVer extracts up to 3 numeric components from "x.y.z[-suffix]".
// normalizeVersion canonicalizes a version for comparison/storage: strips a
// leading "v", drops any pre-release/build "-suffix", and trims surrounding space.
// Used so a "v1.2.3" manifest and a "1.2.3" compiled binary compare equal in the
// stage/commit logic (raw string equality there would silently disable rollback).
func normalizeVersion(v string) string {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	if i := strings.IndexByte(v, '-'); i >= 0 {
		v = v[:i]
	}
	return v
}

func parseVer(v string) [3]int {
	v = normalizeVersion(v)
	var out [3]int
	for i, part := range strings.SplitN(v, ".", 3) {
		if i > 2 {
			break
		}
		n, err := strconv.Atoi(strings.TrimSpace(part))
		if err == nil && n >= 0 {
			out[i] = n
		}
	}
	return out
}
