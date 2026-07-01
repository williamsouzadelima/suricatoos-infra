// Package update serves the agent auto-update channel: a signed manifest telling
// each agent the latest version and, per os/arch, the binary URL + SHA-256.
//
// The response is signed with the enrollment CA's Ed25519 key (see ca.CA.Sign),
// which agents verify with the CA public key they pinned at enrollment. So the
// manifest is trustworthy even though the endpoint sits on the open /agent/ path
// (no mTLS): a forged manifest can't be signed, and the binary is bound to the
// manifest by SHA-256. The canonical signed bytes MUST match the agent's
// update.Canonical exactly (field order/format are the contract).
package update

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

// Artifact is one downloadable binary for a platform.
type Artifact struct {
	OS     string `json:"os"`
	Arch   string `json:"arch"`
	URL    string `json:"url"`
	SHA256 string `json:"sha256"` // 64 hex chars
}

// ManifestConfig is the operator-provided update channel (UPDATE_MANIFEST_FILE).
type ManifestConfig struct {
	Version   string     `json:"version"`
	Artifacts []Artifact `json:"artifacts"`
}

// Signer signs the canonical manifest bytes (implemented by ca.CA).
type Signer interface{ Sign(msg []byte) []byte }

// Service answers update checks. A nil config means the channel is disabled
// (the endpoint returns 204) — safe default until an operator configures it.
type Service struct {
	cfg      *ManifestConfig
	signer   Signer // primary (the CA key today) — verified by the DEPLOYED fleet
	signerV2 Signer // secondary dedicated update key (ADR-0007 risk #3); nil = single-sign
}

// NewService builds a Service. cfg may be nil (auto-update disabled).
func NewService(cfg *ManifestConfig, signer Signer) *Service {
	return &Service{cfg: cfg, signer: signer}
}

// WithUpdateKey adds a SECONDARY signature from a dedicated update-signing key.
// This is the fleet-migration step for key separation (ADR-0007 risk #3): the
// primary signature stays signed by the CA key so already-deployed agents (which
// pinned only the CA pubkey) keep verifying; new agents that received update_pubkey
// at enroll verify the secondary signature. Once the fleet has re-enrolled, the CA
// primary signature can be dropped so the CA key no longer signs updates.
func (s *Service) WithUpdateKey(k Signer) *Service { s.signerV2 = k; return s }

// LoadConfig reads and validates a manifest config file. Each artifact must carry
// os, arch, an https url and a 64-hex SHA-256, and version must be non-empty.
func LoadConfig(path string) (*ManifestConfig, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c ManifestConfig
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("manifest config inválido: %w", err)
	}
	if strings.TrimSpace(c.Version) == "" {
		return nil, fmt.Errorf("manifest config: version vazio")
	}
	for i, a := range c.Artifacts {
		if a.OS == "" || a.Arch == "" {
			return nil, fmt.Errorf("artifact %d: os/arch obrigatórios", i)
		}
		if !strings.HasPrefix(a.URL, "https://") {
			return nil, fmt.Errorf("artifact %s/%s: url deve ser https", a.OS, a.Arch)
		}
		if len(a.SHA256) != 64 {
			return nil, fmt.Errorf("artifact %s/%s: sha256 deve ter 64 hex", a.OS, a.Arch)
		}
	}
	return &c, nil
}

// response is the signed JSON returned to agents; field names/types mirror the
// agent's update.Manifest.
type response struct {
	IssuedAt        time.Time `json:"issued_at"`
	OS              string    `json:"os"`
	Arch            string    `json:"arch"`
	Latest          string    `json:"latest"`
	UpdateAvailable bool      `json:"update_available"`
	URL             string    `json:"url"`
	SHA256          string    `json:"sha256"`
	Signature       string    `json:"signature"`              // primary (CA key) — legacy fleet
	SignatureV2     string    `json:"signature_v2,omitempty"` // dedicated update key (ADR-0007)
}

// Handler serves GET /update/check?os=&arch=&current=.
func (s *Service) Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.cfg == nil {
			w.WriteHeader(http.StatusNoContent) // channel disabled
			return
		}
		q := r.URL.Query()
		goos, goarch, current := q.Get("os"), q.Get("arch"), q.Get("current")
		if goos == "" || goarch == "" {
			http.Error(w, "os e arch obrigatórios", http.StatusBadRequest)
			return
		}
		now := time.Now().UTC().Truncate(time.Second)
		resp := response{IssuedAt: now, OS: goos, Arch: goarch, Latest: s.cfg.Version}
		if a, ok := s.artifact(goos, goarch); ok && isNewer(s.cfg.Version, current) {
			resp.UpdateAvailable = true
			resp.URL = a.URL
			resp.SHA256 = strings.ToLower(a.SHA256)
		}
		// Both signatures cover the SAME canonical bytes (which exclude the
		// signature fields), so a client can verify whichever key it holds.
		msg := canonical(resp)
		resp.Signature = base64.StdEncoding.EncodeToString(s.signer.Sign(msg))
		if s.signerV2 != nil {
			resp.SignatureV2 = base64.StdEncoding.EncodeToString(s.signerV2.Sign(msg))
		}

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(resp)
	}
}

func (s *Service) artifact(goos, goarch string) (Artifact, bool) {
	for _, a := range s.cfg.Artifacts {
		if a.OS == goos && a.Arch == goarch {
			return a, true
		}
	}
	return Artifact{}, false
}

// canonical builds the exact bytes signed/verified. MUST match the agent's
// update.Canonical byte-for-byte.
func canonical(r response) []byte {
	return []byte(fmt.Sprintf(
		"suricatoos-agent-update-v1\nissued_at=%s\nos=%s\narch=%s\nlatest=%s\nupdate=%s\nurl=%s\nsha256=%s\n",
		r.IssuedAt.UTC().Format(time.RFC3339),
		r.OS, r.Arch, r.Latest,
		strconv.FormatBool(r.UpdateAvailable),
		r.URL, strings.ToLower(r.SHA256),
	))
}

// isNewer reports whether a is strictly newer than b (same semver subset as the
// agent: dot-separated numeric components, pre-release suffix ignored).
func isNewer(a, b string) bool {
	pa, pb := parseVer(a), parseVer(b)
	for i := 0; i < 3; i++ {
		if pa[i] != pb[i] {
			return pa[i] > pb[i]
		}
	}
	return false
}

func parseVer(v string) [3]int {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	if i := strings.IndexByte(v, '-'); i >= 0 {
		v = v[:i]
	}
	var out [3]int
	for i, part := range strings.SplitN(v, ".", 3) {
		if i > 2 {
			break
		}
		if n, err := strconv.Atoi(strings.TrimSpace(part)); err == nil && n >= 0 {
			out[i] = n
		}
	}
	return out
}
