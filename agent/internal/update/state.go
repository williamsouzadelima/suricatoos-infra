package update

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// policyState persists cross-update decisions so the agent doesn't re-apply a bad
// release forever or accept a downgrade:
//   - Floor:      highest version ever committed; manifests below it are refused
//     (anti-rollback to a superseded/known-vulnerable build via replay).
//   - Quarantine: versions that crash-looped and were rolled back; refused until a
//     strictly-newer fix ships, so update→crash→rollback→update churn can't happen.
type policyState struct {
	Floor      string   `json:"floor"`
	Quarantine []string `json:"quarantine"`
}

func policyPath(stateDir string) string { return filepath.Join(stateDir, "update.policy.json") }

func readPolicy(stateDir string) policyState {
	var p policyState
	if b, err := os.ReadFile(policyPath(stateDir)); err == nil {
		_ = json.Unmarshal(b, &p)
	}
	return p
}

func writePolicy(stateDir string, p policyState) {
	if b, err := json.Marshal(p); err == nil {
		tmp := policyPath(stateDir) + ".tmp"
		if os.WriteFile(tmp, b, 0o600) == nil {
			_ = os.Rename(tmp, policyPath(stateDir))
		}
	}
}

// Allowed reports whether a verified target version may be applied under the
// persisted policy (floor + quarantine). The reason is for logging when blocked.
func Allowed(stateDir, targetVersion string) (bool, string) {
	norm := normalizeVersion(targetVersion)
	p := readPolicy(stateDir)
	if p.Floor != "" && isNewer(p.Floor, norm) {
		return false, "abaixo do floor de versão (" + p.Floor + ")"
	}
	for _, q := range p.Quarantine {
		if q == norm {
			return false, "versão em quarentena (falhou anteriormente)"
		}
	}
	return true, ""
}

// recordCommitted advances the floor to the committed version and clears it from
// quarantine (a successful boot supersedes any prior failure of that version).
func recordCommitted(stateDir, normVersion string) {
	p := readPolicy(stateDir)
	if p.Floor == "" || isNewer(normVersion, p.Floor) {
		p.Floor = normVersion
	}
	p.Quarantine = remove(p.Quarantine, normVersion)
	// Prune quarantine entries at/below the floor — they can never be offered again.
	kept := p.Quarantine[:0]
	for _, q := range p.Quarantine {
		if isNewer(q, p.Floor) {
			kept = append(kept, q)
		}
	}
	p.Quarantine = kept
	writePolicy(stateDir, p)
}

// recordFailed quarantines a version that crash-looped and was rolled back.
func recordFailed(stateDir, normVersion string) {
	p := readPolicy(stateDir)
	for _, q := range p.Quarantine {
		if q == normVersion {
			return
		}
	}
	p.Quarantine = append(p.Quarantine, normVersion)
	writePolicy(stateDir, p)
}

func remove(s []string, v string) []string {
	out := s[:0]
	for _, x := range s {
		if x != v {
			out = append(out, x)
		}
	}
	return out
}
