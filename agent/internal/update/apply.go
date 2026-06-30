package update

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// maxBootAttempts bounds how many times a freshly-swapped binary may start
// without committing (reaching CommitIfHealthy) before we auto-roll back to the
// backed-up previous binary. This is the crash-loop safety net.
const maxBootAttempts = 3

// stage is the on-disk marker describing an in-flight update. It lets a restarted
// agent decide whether the swap succeeded (commit) or is crash-looping (rollback).
// Versions are stored NORMALIZED so a "v1.2.3" manifest vs "1.2.3" binary skew
// can never silently disable the rollback comparison.
type stage struct {
	PrevVersion   string    `json:"prev_version"`   // normalized
	TargetVersion string    `json:"target_version"` // normalized
	BinaryPath    string    `json:"binary_path"`
	BackupPath    string    `json:"backup_path"`
	StagedAt      time.Time `json:"staged_at"`
	Attempts      int       `json:"attempts"`
}

func stagePath(stateDir string) string { return filepath.Join(stateDir, "update.stage.json") }

func readStage(stateDir string) (*stage, error) {
	b, err := os.ReadFile(stagePath(stateDir))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var s stage
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

func writeStage(stateDir string, s *stage) error {
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	tmp := stagePath(stateDir) + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, stagePath(stateDir))
}

// Download fetches target.URL into a temp file in destDir (same filesystem as the
// binary, so the later swap is an atomic rename), streaming through SHA-256 and
// refusing the file unless the digest matches target.SHA256. The data is fsync'd
// before return so a crash can't leave a torn binary staged. The verified temp
// path is returned; the caller passes it to Apply.
func Download(ctx context.Context, hc *http.Client, target Target, destDir string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.URL, nil)
	if err != nil {
		return "", err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download do binário falhou (%d)", resp.StatusCode)
	}

	tmp, err := os.CreateTemp(destDir, ".suricatoos-agent-update-*")
	if err != nil {
		return "", err
	}
	tmpName := tmp.Name()
	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(tmp, h), io.LimitReader(resp.Body, 512<<20)); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return "", err
	}
	if err := tmp.Sync(); err != nil { // durabilidade: o binário novo é o arquivo mais crítico
		tmp.Close()
		os.Remove(tmpName)
		return "", err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return "", err
	}
	got := hex.EncodeToString(h.Sum(nil))
	if got != target.SHA256 {
		os.Remove(tmpName)
		return "", fmt.Errorf("sha256 do binário não confere: esperado %s, obtido %s", target.SHA256, got)
	}
	return tmpName, nil
}

// Apply installs the already-verified tmpPath over binaryPath. Before touching the
// live binary it SMOKE-TESTS the downloaded file (executes `version` and confirms
// it runs and reports the expected version) — so a wrong-arch, corrupt, or
// mis-versioned artifact is rejected BEFORE any swap, when rollback is still free.
// It then backs up the current binary (preserving a good backup across retries),
// swaps the new one in (atomic on POSIX; rename-aside on Windows), records a stage
// marker, and asks restart() to bounce the service.
func Apply(target Target, tmpPath, binaryPath, stateDir, runningVersion string, restart func() error, now time.Time) error {
	if err := os.Chmod(tmpPath, 0o755); err != nil {
		os.Remove(tmpPath)
		return err
	}
	// Pre-swap validation: the new binary must actually execute and report the
	// version the manifest promised. This is the strongest guard against bricking.
	if err := smokeTest(target, tmpPath); err != nil {
		os.Remove(tmpPath)
		return err
	}

	targetNorm, prevNorm := normalizeVersion(target.Version), normalizeVersion(runningVersion)
	backup := binaryPath + ".bak"

	// Idempotency: if a stage already targets this exact version and its backup is
	// intact, re-applying must NOT overwrite the good backup with the (possibly
	// already-swapped) current binary — that would poison rollback. Just re-restart.
	if s, _ := readStage(stateDir); s != nil && s.TargetVersion == targetNorm {
		if _, err := os.Stat(s.BackupPath); err == nil {
			os.Remove(tmpPath)
			return restart()
		}
	}

	if err := copyFile(binaryPath, backup, 0o755); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("backup do binário atual: %w", err)
	}
	if err := swap(tmpPath, binaryPath); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("troca do binário: %w", err)
	}
	if err := writeStage(stateDir, &stage{
		PrevVersion:   prevNorm,
		TargetVersion: targetNorm,
		BinaryPath:    binaryPath,
		BackupPath:    backup,
		StagedAt:      now.UTC(),
	}); err != nil {
		return fmt.Errorf("update aplicado, mas marcador não gravado (sem rollback automático): %w", err)
	}
	return restart()
}

// smokeTest runs the downloaded binary's `version` command and confirms it both
// executes (catching wrong-arch/corrupt artifacts) and reports the expected
// version (catching manifest/binary version skew that would otherwise loop).
func smokeTest(target Target, path string) error {
	runnable := path
	if runtime.GOOS == "windows" {
		runnable = path + ".exe" // Windows precisa da extensão p/ executar
		if err := copyFile(path, runnable, 0o755); err != nil {
			return err
		}
		defer os.Remove(runnable)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, runnable, "version").CombinedOutput()
	if err != nil {
		return fmt.Errorf("smoke-test: binário baixado não executa: %w", err)
	}
	want := normalizeVersion(target.Version)
	for _, f := range strings.Fields(string(out)) {
		if normalizeVersion(f) == want {
			return nil
		}
	}
	return fmt.Errorf("smoke-test: binário reporta versão diferente de %s (saída: %q)", want, strings.TrimSpace(string(out)))
}

// BeginBoot is called at the very start of the daemon. If a staged update is in
// flight it counts this boot attempt and, once attempts exceed maxBootAttempts
// without a commit, rolls back to the backup, quarantines the failed version, and
// restarts. It returns true when it performed a rollback.
func BeginBoot(stateDir, runningVersion string, restart func() error) (rolledBack bool, err error) {
	s, err := readStage(stateDir)
	if err != nil || s == nil {
		return false, err
	}
	cur := normalizeVersion(runningVersion)
	switch {
	case cur == s.TargetVersion:
		// The new binary is running. Count the attempt; if it keeps crashing
		// before CommitIfHealthy, roll back.
		s.Attempts++
		if s.Attempts > maxBootAttempts {
			if e := rollback(stateDir, s, restart); e != nil {
				return false, e
			}
			return true, nil
		}
		return false, writeStage(stateDir, s)
	case cur == s.PrevVersion:
		// Still the old binary (swap didn't take effect, or we already rolled
		// back). Clean up the stage so we don't loop.
		clearStage(stateDir, s)
		return false, nil
	default:
		// Running version matches neither (e.g. a third version). Count it too so a
		// persistent mismatch still trips rollback instead of looping forever.
		s.Attempts++
		if s.Attempts > maxBootAttempts {
			if e := rollback(stateDir, s, restart); e != nil {
				return false, e
			}
			return true, nil
		}
		return false, writeStage(stateDir, s)
	}
}

// CommitIfHealthy is called once the daemon has proven RUNTIME liveness (not just
// that the constructor returned). If the running binary is the staged target, the
// update is committed: the backup and stage marker are removed and the version
// floor is advanced. Returns true when a commit occurred.
func CommitIfHealthy(stateDir, runningVersion string) (committed bool, err error) {
	s, err := readStage(stateDir)
	if err != nil || s == nil {
		return false, err
	}
	if normalizeVersion(runningVersion) != s.TargetVersion {
		return false, nil
	}
	recordCommitted(stateDir, s.TargetVersion) // advance floor, drop from quarantine
	clearStage(stateDir, s)
	return true, nil
}

// rollback restores the backup over the binary, quarantines the failed target so
// it is not re-applied, and restarts so the previous known-good version runs.
func rollback(stateDir string, s *stage, restart func() error) error {
	if s.BackupPath == "" {
		return errors.New("rollback impossível: sem backup")
	}
	if err := copyFile(s.BackupPath, s.BinaryPath, 0o755); err != nil {
		return fmt.Errorf("rollback (restaurar backup): %w", err)
	}
	recordFailed(stateDir, s.TargetVersion)
	clearStage(stateDir, s)
	return restart()
}

// clearStage removes the backup and the stage marker (best-effort).
func clearStage(stateDir string, s *stage) {
	if s.BackupPath != "" {
		os.Remove(s.BackupPath)
	}
	os.Remove(stagePath(stateDir))
}

// swap moves src over dst atomically. On POSIX a direct rename replaces the file
// while the running process keeps the old inode. On Windows the target is locked
// while running, so fall back to renaming the current binary aside first.
func swap(src, dst string) error {
	if err := os.Rename(src, dst); err == nil {
		return nil
	}
	aside := dst + ".old"
	os.Remove(aside)
	if err := os.Rename(dst, aside); err != nil {
		return err
	}
	if err := os.Rename(src, dst); err != nil {
		_ = os.Rename(aside, dst) // restore the moved-aside original before giving up
		return err
	}
	return nil
}

// copyFile copies src to dst with the given mode, syncing to disk so a crash mid
// update can't leave a truncated backup/binary.
func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	if err := out.Sync(); err != nil {
		out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	return os.Chmod(dst, mode)
}
