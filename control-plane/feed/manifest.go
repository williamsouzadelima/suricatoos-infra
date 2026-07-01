// Package feed serves the Greenbone feed (NVT/SCAP/CERT/Notus) to internal
// scanner sensors over the mTLS phone-home channel (ADR-0007). The sensor runs a
// full local GVM and needs the multi-GB feed, but the client site's only
// guaranteed egress is sensor→cloud:443 — so the cloud MIRRORS the feed it already
// syncs, rather than the sensor pulling from Greenbone directly.
//
// Integrity model (ADR-0007 risk #2, NASL runs as code): the manifest is signed
// (Ed25519, verified sensor-side against the pinned CA public key), blobs are
// CONTENT-ADDRESSED by SHA-256 (a tampered blob fails its hash), and the upstream
// Greenbone GPG detached signatures are preserved in the mirror so the sensor's
// own NASL signature check still holds even against a fully MITM'd network.
package feed

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// canonicalPrefix is the domain-separation tag signed over (mirrors update.go).
const canonicalPrefix = "suricatoos-feed-manifest-v1"

// FileEntry is one feed file, addressed by its content hash.
type FileEntry struct {
	Path   string `json:"path"`   // path relative to the feed root (forward slashes)
	SHA256 string `json:"sha256"` // lower-hex content hash (the blob id)
	Size   int64  `json:"size"`
}

// Manifest is the signed list of every feed file at a given feed version.
type Manifest struct {
	FeedVersion string      `json:"feed_version"`
	Files       []FileEntry `json:"files"`
	Signature   string      `json:"signature,omitempty"` // base64 Ed25519 over Canonical()
}

// Canonical returns the deterministic byte string that is signed/verified. Files
// are sorted by path so the same tree always yields the same bytes. The signature
// field is excluded (it signs everything else).
func (m *Manifest) Canonical() []byte {
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

// BuildManifest walks root and returns a manifest of every regular file, hashed.
// feedVersion identifies this snapshot (e.g. the feed's timestamp/serial).
func BuildManifest(root, feedVersion string) (*Manifest, error) {
	m := &Manifest{FeedVersion: feedVersion}
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !d.Type().IsRegular() {
			return nil
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		sum, size, err := hashFile(p)
		if err != nil {
			return err
		}
		m.Files = append(m.Files, FileEntry{Path: filepath.ToSlash(rel), SHA256: sum, Size: size})
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("build manifest de %s: %w", root, err)
	}
	sort.Slice(m.Files, func(i, j int) bool { return m.Files[i].Path < m.Files[j].Path })
	return m, nil
}

// hashFile returns the lower-hex SHA-256 and byte size of a file.
func hashFile(p string) (string, int64, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

// validHash reports whether s is a 64-char lower-hex SHA-256 (guards the blob
// route against path traversal: only a hash can name a blob).
func validHash(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
