// Package feedsync keeps the sensor's LOCAL Greenbone feed in sync with the cloud
// mirror (ADR-0007). It fetches the signed manifest, VERIFIES the signature with
// the CA public key the sensor pinned at enroll, then downloads only the blobs it
// is missing — each addressed by SHA-256 and re-hashed on arrival, so a tampered
// blob is rejected. Files land by content hash and are linked into place, so a
// partial sync never corrupts the live feed.
//
// Integrity (ADR-0007 risk #2): the manifest signature stops a swapped manifest;
// the per-blob hash stops a swapped blob; and because the upstream Greenbone GPG
// detached signatures are ordinary files in the feed, they ride along in the
// mirror and the sensor's own gvmd NASL signature check still holds.
package feedsync

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

const canonicalPrefix = "suricatoos-feed-manifest-v1"

// FileEntry / Manifest mirror control-plane/feed (kept independent — the two
// modules don't share code, only the wire format + the canonical signing bytes).
type FileEntry struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

type Manifest struct {
	FeedVersion string      `json:"feed_version"`
	Files       []FileEntry `json:"files"`
	Signature   string      `json:"signature"`
}

// canonical rebuilds the exact bytes the cloud signed (must match feed.Canonical).
func (m *Manifest) canonical() []byte {
	files := append([]FileEntry(nil), m.Files...)
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	var b strings.Builder
	b.WriteString(canonicalPrefix + "\n")
	b.WriteString("feed_version=" + m.FeedVersion + "\n")
	for _, f := range files {
		b.WriteString(f.Path + "\t" + strings.ToLower(f.SHA256) + "\t" + strconv.FormatInt(f.Size, 10) + "\n")
	}
	return []byte(b.String())
}

// Config drives one sync.
type Config struct {
	ManifestURL string            // .../agent/v1/feed/manifest
	BlobURLBase string            // .../agent/v1/feed/blob  (blob = base + "/" + sha256)
	FeedDir     string            // local feed root to populate
	VerifyKey   ed25519.PublicKey // pinned CA pubkey (verifies the manifest signature)
	Client      *http.Client
	MaxBlobSize int64 // per-blob cap (default 512 MiB)
}

// Syncer performs feed syncs.
type Syncer struct {
	cfg Config
}

// New builds a Syncer.
func New(cfg Config) *Syncer {
	if cfg.Client == nil {
		cfg.Client = &http.Client{Timeout: 10 * time.Minute}
	}
	if cfg.MaxBlobSize <= 0 {
		cfg.MaxBlobSize = 512 << 20
	}
	return &Syncer{cfg: cfg}
}

// VerifyKeyFromCACert extracts the Ed25519 public key from a PEM CA cert (the
// ca.crt the sensor received at enroll), for verifying the manifest signature.
func VerifyKeyFromCACert(pemBytes []byte) (ed25519.PublicKey, error) {
	rest := pemBytes
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		if pk, ok := cert.PublicKey.(ed25519.PublicKey); ok {
			return pk, nil
		}
	}
	return nil, fmt.Errorf("nenhuma chave Ed25519 no ca.crt")
}

// Result summarizes a sync.
type Result struct {
	FeedVersion  string
	TotalFiles   int
	Downloaded   int
	AlreadyLocal int
}

// Sync fetches+verifies the manifest and downloads any missing/changed blobs into
// FeedDir (each verified by hash), then writes version.json. Idempotent: a file
// already present with the right hash is left untouched.
func (s *Syncer) Sync(ctx context.Context) (*Result, error) {
	m, err := s.fetchManifest(ctx)
	if err != nil {
		return nil, err
	}
	if len(s.cfg.VerifyKey) == 0 {
		return nil, fmt.Errorf("VerifyKey ausente — recusando manifest não verificável")
	}
	sig, err := base64.StdEncoding.DecodeString(m.Signature)
	if err != nil || !ed25519.Verify(s.cfg.VerifyKey, m.canonical(), sig) {
		return nil, fmt.Errorf("assinatura do manifest inválida — abortando (possível MITM)")
	}

	res := &Result{FeedVersion: m.FeedVersion, TotalFiles: len(m.Files)}
	for _, f := range m.Files {
		dest := filepath.Join(s.cfg.FeedDir, filepath.FromSlash(f.Path))
		if hashMatches(dest, f.SHA256) {
			res.AlreadyLocal++
			continue
		}
		if err := s.downloadBlob(ctx, f, dest); err != nil {
			return res, fmt.Errorf("blob %s (%s): %w", f.Path, f.SHA256[:12], err)
		}
		res.Downloaded++
	}
	if err := s.writeVersion(m.FeedVersion); err != nil {
		return res, err
	}
	return res, nil
}

func (s *Syncer) fetchManifest(ctx context.Context) (*Manifest, error) {
	req, err := newReq(ctx, s.cfg.ManifestURL)
	if err != nil {
		return nil, err
	}
	resp, err := s.cfg.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("manifest: status %d", resp.StatusCode)
	}
	var m Manifest
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<20)).Decode(&m); err != nil {
		return nil, fmt.Errorf("manifest: decode: %w", err)
	}
	return &m, nil
}

// downloadBlob fetches one blob by hash, verifying its SHA-256 as it streams, and
// atomically renames it into place (temp + rename) so a partial download never
// becomes a live feed file.
func (s *Syncer) downloadBlob(ctx context.Context, f FileEntry, dest string) error {
	req, err := newReq(ctx, s.cfg.BlobURLBase+"/"+f.SHA256)
	if err != nil {
		return err
	}
	resp, err := s.cfg.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(dest), ".blob-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())

	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(tmp, h), io.LimitReader(resp.Body, s.cfg.MaxBlobSize+1))
	if err != nil {
		tmp.Close()
		return err
	}
	tmp.Close()
	if n > s.cfg.MaxBlobSize {
		return fmt.Errorf("blob excede MaxBlobSize")
	}
	got := hex.EncodeToString(h.Sum(nil))
	if got != strings.ToLower(f.SHA256) {
		return fmt.Errorf("hash não confere: got %s want %s", got[:12], f.SHA256[:12])
	}
	if n != f.Size {
		return fmt.Errorf("tamanho não confere: got %d want %d", n, f.Size)
	}
	return os.Rename(tmp.Name(), dest)
}

func (s *Syncer) writeVersion(v string) error {
	if err := os.MkdirAll(s.cfg.FeedDir, 0o755); err != nil {
		return err
	}
	b, _ := json.Marshal(map[string]string{"feed_version": v})
	p := filepath.Join(s.cfg.FeedDir, "version.json")
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

// hashMatches reports whether the file at path already has the given SHA-256.
func hashMatches(path, want string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return false
	}
	return hex.EncodeToString(h.Sum(nil)) == strings.ToLower(want)
}

// newReq builds a GET request with the sync context.
func newReq(ctx context.Context, url string) (*http.Request, error) {
	return http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
}
