package feed

import (
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Signer signs the manifest (Ed25519). *ca.CA satisfies it. Per ADR-0007 risk #3
// this SHOULD be a dedicated feed-signing key distinct from the cert-issuing key;
// until the key-separation slice lands, main passes the CA and the sensor verifies
// with the CA public key it already pinned at enroll.
type Signer interface{ Sign(msg []byte) []byte }

// Authorizer validates the forwarded mTLS headers for a sensor route (verify + OU
// + CRL). Returns ok=false and writes the response on failure. The sensorjobs
// package provides a compatible checker; feed takes it as a func to avoid coupling.
type Authorizer func(w http.ResponseWriter, r *http.Request) bool

// Service serves the signed feed manifest and the content-addressed blobs.
type Service struct {
	root        string        // feed root directory (read-only mirror the cloud already syncs)
	feedVersion func() string // current feed version/serial
	signer      Signer
	authz       Authorizer

	mu       sync.Mutex
	cached   *Manifest
	cachedAt time.Time
	ttl      time.Duration
	now      func() time.Time
}

// Config configures a feed Service.
type Config struct {
	Root        string
	FeedVersion func() string
	Signer      Signer
	Authz       Authorizer
	CacheTTL    time.Duration // rebuild the manifest at most this often (default 5m)
}

// New builds a feed Service.
func New(cfg Config) *Service {
	ttl := cfg.CacheTTL
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	fv := cfg.FeedVersion
	if fv == nil {
		fv = func() string { return "" }
	}
	return &Service{root: cfg.Root, feedVersion: fv, signer: cfg.Signer, authz: cfg.Authz, ttl: ttl, now: time.Now}
}

// Register mounts the feed routes.
func (s *Service) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/feed/manifest", s.handleManifest)
	mux.HandleFunc("GET /v1/feed/blob/{sha256}", s.handleBlob)
}

// handleManifest returns the current signed manifest (cached + rebuilt per TTL).
func (s *Service) handleManifest(w http.ResponseWriter, r *http.Request) {
	if s.authz != nil && !s.authz(w, r) {
		return
	}
	m, err := s.manifest()
	if err != nil {
		log.Printf("feed: build manifest: %v", err)
		http.Error(w, "manifest indisponível", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(m)
}

// handleBlob streams the file whose content hash is {sha256}. It is served by hash
// (content-addressed), so it supports Range (resumable) via http.ServeContent and
// can be cached indefinitely — the bytes for a hash never change.
func (s *Service) handleBlob(w http.ResponseWriter, r *http.Request) {
	if s.authz != nil && !s.authz(w, r) {
		return
	}
	sum := r.PathValue("sha256")
	if !validHash(sum) {
		http.Error(w, "hash inválido", http.StatusBadRequest)
		return
	}
	m, err := s.manifest()
	if err != nil {
		http.Error(w, "manifest indisponível", http.StatusServiceUnavailable)
		return
	}
	// Only a hash present in the current manifest is servable — this both maps the
	// hash to a real path and prevents serving arbitrary files.
	var rel string
	for _, f := range m.Files {
		if f.SHA256 == sum {
			rel = f.Path
			break
		}
	}
	if rel == "" {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	// filepath.Join cleans the path; rel came from the manifest (our own walk), and
	// validHash already bounded {sha256}, so no user-controlled traversal reaches here.
	full := filepath.Join(s.root, filepath.FromSlash(rel))
	f, err := os.Open(full)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || fi.IsDir() {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	w.Header().Set("ETag", `"`+sum+`"`)
	http.ServeContent(w, r, "", fi.ModTime(), f) // handles Range + conditional requests
}

// manifest returns a signed manifest, rebuilding from disk when the cache is stale.
func (s *Service) manifest() (*Manifest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cached != nil && s.now().Sub(s.cachedAt) < s.ttl {
		return s.cached, nil
	}
	m, err := BuildManifest(s.root, s.feedVersion())
	if err != nil {
		return nil, err
	}
	if s.signer != nil {
		m.Signature = base64.StdEncoding.EncodeToString(s.signer.Sign(m.Canonical()))
	}
	s.cached = m
	s.cachedAt = s.now()
	return m, nil
}
