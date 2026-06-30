package update

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

var fixedTime = time.Date(2026, 6, 30, 3, 0, 0, 0, time.UTC)

// goldenCanonical pins the exact signed bytes. The control-plane has the same
// golden in its own test; if either drifts, signatures stop verifying.
const goldenCanonical = "suricatoos-agent-update-v1\n" +
	"issued_at=2026-06-30T03:00:00Z\n" +
	"os=linux\narch=amd64\nlatest=0.1.1\nupdate=true\n" +
	"url=https://example.test/bin\n" +
	"sha256=" + sha64 + "\n"

const sha64 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func TestCanonicalGolden(t *testing.T) {
	m := Manifest{
		IssuedAt: fixedTime, OS: "linux", Arch: "amd64", Latest: "0.1.1",
		UpdateAvailable: true, URL: "https://example.test/bin", SHA256: sha64,
	}
	if got := string(Canonical(m)); got != goldenCanonical {
		t.Fatalf("canonical drift:\n got=%q\nwant=%q", got, goldenCanonical)
	}
}

func TestIsNewer(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"0.1.1", "0.1.0", true},
		{"0.2.0", "0.1.9", true},
		{"1.0.0", "0.9.9", true},
		{"0.1.0", "0.1.0", false},
		{"0.1.0", "0.1.1", false},
		{"0.1.0", "0.0.0-dev", true},
		{"v0.1.1", "0.1.0", true}, // leading v tolerated
		{"garbage", "0.1.0", false},
		{"0.1.1-rc1", "0.1.0", true}, // pre-release suffix ignored
	}
	for _, c := range cases {
		if got := isNewer(c.a, c.b); got != c.want {
			t.Errorf("isNewer(%q,%q)=%v want %v", c.a, c.b, got, c.want)
		}
	}
}

// signedManifestServer serves a CA-signed manifest for the given fields.
func signedManifestServer(t *testing.T, priv ed25519.PrivateKey, m Manifest) *httptest.Server {
	t.Helper()
	m.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, Canonical(m)))
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(m)
	}))
}

func TestCheckAcceptsNewerSigned(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	m := Manifest{IssuedAt: fixedTime, OS: "linux", Arch: "amd64", Latest: "0.1.1",
		UpdateAvailable: true, URL: "https://example.test/bin", SHA256: sha64}
	srv := signedManifestServer(t, priv, m)
	defer srv.Close()

	tgt, err := Check(context.Background(), srv.Client(), srv.URL, "0.1.0", "linux", "amd64", pub, fixedTime)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if tgt == nil || tgt.Version != "0.1.1" || tgt.SHA256 != sha64 {
		t.Fatalf("unexpected target: %+v", tgt)
	}
}

func TestCheckRejectsTamperedSignature(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	_, attacker, _ := ed25519.GenerateKey(nil)
	m := Manifest{IssuedAt: fixedTime, OS: "linux", Arch: "amd64", Latest: "0.1.1",
		UpdateAvailable: true, URL: "https://evil.test/bin", SHA256: sha64}
	// Sign with the WRONG (attacker) key.
	srv := signedManifestServer(t, attacker, m)
	defer srv.Close()
	if _, err := Check(context.Background(), srv.Client(), srv.URL, "0.1.0", "linux", "amd64", pub, fixedTime); err == nil {
		t.Fatal("expected rejection of manifest not signed by the CA")
	}
	_ = priv
}

func TestCheckRejectsStaleAndWrongPlatform(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	// stale: issued 3 days ago
	stale := Manifest{IssuedAt: fixedTime.Add(-72 * time.Hour), OS: "linux", Arch: "amd64",
		Latest: "0.1.1", UpdateAvailable: true, URL: "https://example.test/bin", SHA256: sha64}
	srv := signedManifestServer(t, priv, stale)
	if _, err := Check(context.Background(), srv.Client(), srv.URL, "0.1.0", "linux", "amd64", pub, fixedTime); err == nil {
		t.Error("expected rejection of stale manifest")
	}
	srv.Close()

	// wrong platform: manifest says windows but we asked linux
	wrong := Manifest{IssuedAt: fixedTime, OS: "windows", Arch: "amd64", Latest: "0.1.1",
		UpdateAvailable: true, URL: "https://example.test/bin", SHA256: sha64}
	srv2 := signedManifestServer(t, priv, wrong)
	defer srv2.Close()
	if _, err := Check(context.Background(), srv2.Client(), srv2.URL, "0.1.0", "linux", "amd64", pub, fixedTime); err == nil {
		t.Error("expected rejection of wrong-platform manifest")
	}
}

func TestCheckUpToDateReturnsNil(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	m := Manifest{IssuedAt: fixedTime, OS: "linux", Arch: "amd64", Latest: "0.1.0",
		UpdateAvailable: false}
	srv := signedManifestServer(t, priv, m)
	defer srv.Close()
	tgt, err := Check(context.Background(), srv.Client(), srv.URL, "0.1.0", "linux", "amd64", pub, fixedTime)
	if err != nil || tgt != nil {
		t.Fatalf("expected no update, got tgt=%+v err=%v", tgt, err)
	}
}

func TestDownloadVerifiesSHA(t *testing.T) {
	payload := []byte("#!/bin/true\nbinary-bytes\n")
	sum := sha256.Sum256(payload)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(payload)
	}))
	defer srv.Close()
	dir := t.TempDir()

	// good sha
	p, err := Download(context.Background(), srv.Client(), Target{URL: srv.URL, SHA256: hex.EncodeToString(sum[:])}, dir)
	if err != nil {
		t.Fatalf("Download: %v", err)
	}
	got, _ := os.ReadFile(p)
	if string(got) != string(payload) {
		t.Fatal("downloaded content mismatch")
	}

	// bad sha → error + no leftover temp
	if _, err := Download(context.Background(), srv.Client(), Target{URL: srv.URL, SHA256: sha64}, dir); err == nil {
		t.Fatal("expected sha256 mismatch error")
	}
}

// versionScript writes an executable that prints a version line like the real
// `suricatoos-agent version`, so Apply's smoke-test can exec it. (POSIX hosts.)
func versionScript(t *testing.T, path, version string) {
	t.Helper()
	body := "#!/bin/sh\necho \"suricatoos-agent " + version + " (commit test, built test)\"\n"
	if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
}

// TestApplyCommitFlow exercises the happy path: smoke-test, swap, marker, restart,
// then a stability commit of the new version (backup + marker removed, floor set).
func TestApplyCommitFlow(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell smoke-test script is POSIX")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "agent")
	os.WriteFile(bin, []byte("OLD"), 0o755)
	newBin := filepath.Join(dir, "new")
	versionScript(t, newBin, "0.1.1")

	restarted := 0
	restart := func() error { restarted++; return nil }

	if err := Apply(Target{Version: "0.1.1"}, newBin, bin, dir, "0.1.0", restart, fixedTime); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if _, err := os.Stat(bin + ".bak"); err != nil {
		t.Fatal("backup missing")
	}
	if restarted != 1 {
		t.Fatalf("expected 1 restart, got %d", restarted)
	}

	// Healthy boot of the new version: BeginBoot counts, CommitIfHealthy commits.
	if rb, _ := BeginBoot(dir, "0.1.1", restart); rb {
		t.Fatal("unexpected rollback on first healthy boot")
	}
	committed, err := CommitIfHealthy(dir, "0.1.1")
	if err != nil || !committed {
		t.Fatalf("expected commit, got committed=%v err=%v", committed, err)
	}
	if _, err := os.Stat(bin + ".bak"); !os.IsNotExist(err) {
		t.Fatal("backup should be gone after commit")
	}
	if _, err := os.Stat(stagePath(dir)); !os.IsNotExist(err) {
		t.Fatal("stage marker should be gone after commit")
	}
	// Floor advanced to the committed version.
	if ok, _ := Allowed(dir, "0.1.0"); ok {
		t.Fatal("a version below the floor must be refused after commit")
	}
}

// TestCrashLoopRollback: the new binary boots but crashes before commit; after
// maxBootAttempts BeginBoot restores the backup, quarantines, and restarts.
func TestCrashLoopRollback(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell smoke-test script is POSIX")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "agent")
	os.WriteFile(bin, []byte("OLD-GOOD"), 0o755)
	newBin := filepath.Join(dir, "new")
	versionScript(t, newBin, "0.1.1") // smoke-test passes (reports 0.1.1) but then "crashes" at boot

	restart := func() error { return nil }
	if err := Apply(Target{Version: "0.1.1"}, newBin, bin, dir, "0.1.0", restart, fixedTime); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	var rolledBack bool
	for i := 0; i < maxBootAttempts+1; i++ {
		if rolledBack, _ = BeginBoot(dir, "0.1.1", restart); rolledBack {
			break
		}
	}
	if !rolledBack {
		t.Fatal("expected rollback after repeated failed boots")
	}
	if b, _ := os.ReadFile(bin); string(b) != "OLD-GOOD" {
		t.Fatalf("rollback should have restored the previous binary, got %q", b)
	}
	if _, err := os.Stat(stagePath(dir)); !os.IsNotExist(err) {
		t.Fatal("stage marker should be cleared after rollback")
	}
	// Quarantined: the failed version must not be applied again.
	if ok, _ := Allowed(dir, "0.1.1"); ok {
		t.Fatal("rolled-back version must be quarantined")
	}
}

// TestSmokeTestRejectsBadBinary: a binary that reports the wrong version (or
// cannot exec) is refused BEFORE the swap — the live binary is untouched.
func TestSmokeTestRejectsBadBinary(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell smoke-test script is POSIX")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "agent")
	os.WriteFile(bin, []byte("ORIGINAL"), 0o755)

	// wrong version
	wrong := filepath.Join(dir, "wrong")
	versionScript(t, wrong, "9.9.9")
	if err := Apply(Target{Version: "0.1.1"}, wrong, bin, dir, "0.1.0", func() error { return nil }, fixedTime); err == nil {
		t.Fatal("expected smoke-test to reject wrong-version binary")
	}
	if b, _ := os.ReadFile(bin); string(b) != "ORIGINAL" {
		t.Fatal("live binary must be untouched when smoke-test fails")
	}
	if _, err := os.Stat(stagePath(dir)); !os.IsNotExist(err) {
		t.Fatal("no stage marker should be written when smoke-test fails")
	}

	// non-executable garbage
	garbage := filepath.Join(dir, "garbage")
	os.WriteFile(garbage, []byte("\x00not a program"), 0o755)
	if err := Apply(Target{Version: "0.1.1"}, garbage, bin, dir, "0.1.0", func() error { return nil }, fixedTime); err == nil {
		t.Fatal("expected smoke-test to reject non-executable binary")
	}
}

// TestPolicyFloorAndQuarantine checks the persisted version policy directly.
func TestPolicyFloorAndQuarantine(t *testing.T) {
	dir := t.TempDir()
	if ok, _ := Allowed(dir, "0.1.0"); !ok {
		t.Fatal("fresh state should allow any version")
	}
	recordCommitted(dir, "0.2.0")
	if ok, _ := Allowed(dir, "0.1.9"); ok {
		t.Fatal("version below floor must be refused")
	}
	if ok, _ := Allowed(dir, "0.3.0"); !ok {
		t.Fatal("version above floor must be allowed")
	}
	recordFailed(dir, "0.3.0")
	if ok, _ := Allowed(dir, "0.3.0"); ok {
		t.Fatal("quarantined version must be refused")
	}
	if ok, _ := Allowed(dir, "0.4.0"); !ok {
		t.Fatal("a newer version than the quarantined one must be allowed")
	}
}
