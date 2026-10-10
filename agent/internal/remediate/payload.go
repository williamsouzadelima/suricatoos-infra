package remediate

import (
	"encoding/json"
	"errors"
	"fmt"
)

// PackagePatchPayload describes ONE update to apply (job type package_patch). The
// queue treats the payload as opaque; only the executor's handler interprets it.
// Source selects the engine; the rest identifies the update.
type PackagePatchPayload struct {
	Source  string `json:"source"`            // "wua" | "winget"
	ID      string `json:"id"`                // WUA UpdateID or winget package id
	KB      string `json:"kb,omitempty"`      // e.g. "KB5041580" (WUA) — validation/audit
	Version string `json:"version,omitempty"` // winget target version
}

// ConfigHardeningPayload describes ONE security setting to enforce (job type
// config_hardening), keyed by the CIS rule it satisfies. Source selects how the
// handler reads/writes it.
type ConfigHardeningPayload struct {
	RuleRef string `json:"rule_ref"` // CIS rule number, e.g. "18.9.x" (cite only the number)
	Source  string `json:"source"`   // "registry" | "secedit" | "auditpol"
	Key     string `json:"key"`      // registry path / policy name
	Value   string `json:"value"`    // desired value
}

// ParsePackagePatch decodes and validates a package_patch payload. It rejects an
// unknown engine or a missing id so a malformed job never reaches a handler.
func ParsePackagePatch(raw json.RawMessage) (*PackagePatchPayload, error) {
	var p PackagePatchPayload
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, fmt.Errorf("payload package_patch inválido: %w", err)
	}
	if p.Source != "wua" && p.Source != "winget" {
		return nil, fmt.Errorf("source inválido %q (esperado wua|winget)", p.Source)
	}
	if p.ID == "" {
		return nil, errors.New("package_patch sem id")
	}
	return &p, nil
}

// ParseConfigHardening decodes and validates a config_hardening payload.
func ParseConfigHardening(raw json.RawMessage) (*ConfigHardeningPayload, error) {
	var p ConfigHardeningPayload
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, fmt.Errorf("payload config_hardening inválido: %w", err)
	}
	if p.RuleRef == "" {
		return nil, errors.New("config_hardening sem rule_ref")
	}
	switch p.Source {
	case "registry", "secedit", "auditpol":
	default:
		return nil, fmt.Errorf("source inválido %q (esperado registry|secedit|auditpol)", p.Source)
	}
	if p.Key == "" {
		return nil, errors.New("config_hardening sem key")
	}
	return &p, nil
}
