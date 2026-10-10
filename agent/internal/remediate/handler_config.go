package remediate

import (
	"context"
	"fmt"
	"strings"
)

// settingEngine is the OS-touching seam for ONE config source
// (registry|secedit|auditpol). Real implementations are LAB-gated; a pending stub
// ships here so nothing writes. Tests inject fakes.
type settingEngine interface {
	// read returns the current value of the setting (for drift detection + rollback).
	read(ctx context.Context, p *ConfigHardeningPayload) (current string, err error)
	// write enforces the desired value.
	write(ctx context.Context, p *ConfigHardeningPayload) error
}

// ConfigHardeningHandler applies a config_hardening job by dispatching to the
// engine named by the payload's Source. It refuses settings owned by central
// policy, refuses high-blast-radius settings unless the operator opted in out of
// band, no-ops when already compliant, and captures the prior value into
// Result.Before so the cloud can drive a rollback.
type ConfigHardeningHandler struct {
	engines map[string]settingEngine
	// allowHighImpact gates the classic lockout/breakage footguns (SMBv1, NTLM/LM,
	// LSA, UAC, RDP/NLA, user-rights). It is FALSE in production and only an
	// explicit, out-of-band operator opt-in (agent-side config, never the job)
	// flips it — so a signed job alone can never trip a high-radius change.
	allowHighImpact bool
}

func newConfigHardeningHandler(engines map[string]settingEngine, allowHighImpact bool) *ConfigHardeningHandler {
	return &ConfigHardeningHandler{engines: engines, allowHighImpact: allowHighImpact}
}

// NewConfigHardeningHandler returns the production handler. Its engines are PENDING
// (real registry/secedit/auditpol writes are the LAB-gated slice), so until that
// lands every job reports FAILED and NOTHING is written to the OS. High-impact
// settings are refused by default.
func NewConfigHardeningHandler() *ConfigHardeningHandler {
	return newConfigHardeningHandler(map[string]settingEngine{
		"registry": pendingSettingEngine{},
		"secedit":  pendingSettingEngine{},
		"auditpol": pendingSettingEngine{},
	}, false)
}

// Type implements Handler.
func (*ConfigHardeningHandler) Type() Type { return TypeConfigHardening }

// Apply implements Handler. Authenticity + window/idempotency are already enforced
// by the executor; this method decides WHETHER the setting is applicable and, if
// so, drives it to the desired value idempotently.
func (h *ConfigHardeningHandler) Apply(ctx context.Context, j *Job) (*Result, error) {
	p, err := ParseConfigHardening(j.Payload)
	if err != nil {
		return nil, err
	}
	// Never fight centralized policy: a setting under ...\SOFTWARE\Policies\ is
	// owned by GPO/Intune/WSUS, so a local write would be reverted by gpupdate and
	// give a false "fixed". Refuse and let the operator change the POLICY instead.
	if p.Source == "registry" && isPolicyManaged(p.Key) {
		return nil, fmt.Errorf("%q é gerido por política (GPO/Intune); corrigir na política, não localmente [%s]", p.Key, p.RuleRef)
	}
	// High blast radius (SMBv1/NTLM/LSA/UAC/RDP/user-rights): a wrong value here can
	// lock the host out or break auth, and rollback is not guaranteed. Refuse unless
	// the operator explicitly opted in out of band.
	if isHighImpact(p) && !h.allowHighImpact {
		return nil, fmt.Errorf("configuração de alto raio (%s) exige opt-in explícito do operador fora de banda; não aplicada [%s]", p.Key, p.RuleRef)
	}
	eng, ok := h.engines[p.Source]
	if !ok {
		return nil, fmt.Errorf("sem motor de config para source %q", p.Source)
	}
	current, err := eng.read(ctx, p)
	if err != nil {
		return nil, fmt.Errorf("ler %s via %s: %w", p.Key, p.Source, err)
	}
	if current == p.Value {
		return &Result{
			Before: current,
			After:  current,
			Detail: fmt.Sprintf("já em conformidade (no-op idempotente): %s=%s [%s]", p.Key, p.Value, p.RuleRef),
		}, nil
	}
	if err := eng.write(ctx, p); err != nil {
		return &Result{Before: current}, fmt.Errorf("escrever %s via %s: %w", p.Key, p.Source, err)
	}
	return &Result{
		Before: current,
		After:  p.Value,
		Detail: fmt.Sprintf("hardening aplicado: %s=%s [%s] (rollback = restaurar Before)", p.Key, p.Value, p.RuleRef),
	}, nil
}

// isPolicyManaged reports whether a registry key lives under a Policies hive that
// central management (GPO/Intune) owns. It is tolerant of the hive prefix and of
// forward/back slashes.
func isPolicyManaged(key string) bool {
	k := strings.ToLower(strings.ReplaceAll(key, "/", `\`))
	return strings.Contains(k, `\software\policies\`) || strings.HasPrefix(k, `software\policies\`)
}

// highImpactMarkers is a conservative denylist of the classic lockout/breakage
// footguns the plan calls out. Matched as case-insensitive substrings of the key;
// extend it as the authored ruleset grows.
var highImpactMarkers = []string{
	"smb1", "lanmanserver", "mrxsmb10", // SMBv1 / SMB stack
	"lmcompatibilitylevel", "restrictsendingntlm", "ntlmminserver", "ntlmminclient", // NTLM/LM auth
	"restrictanonymous", "nolmhash", "limitblankpassword", `\control\lsa`, // LSA security options
	"enablelua", "consentpromptbehavior", "filteradministratortoken", // UAC
	"fdenytsconnections", "usernetworkauthentication", "terminal server", // RDP / NLA
	"sedeny", "selogonright", "seremoteinteractivelogonright", // user-rights (lockout risk)
}

// isHighImpact reports whether enforcing this setting carries a high blast radius.
func isHighImpact(p *ConfigHardeningPayload) bool {
	k := strings.ToLower(strings.ReplaceAll(p.Key, "/", `\`))
	for _, m := range highImpactMarkers {
		if strings.Contains(k, m) {
			return true
		}
	}
	return false
}

// pendingSettingEngine is the inert default until the real OS engines land (LAB).
type pendingSettingEngine struct{}

func (pendingSettingEngine) read(context.Context, *ConfigHardeningPayload) (string, error) {
	return "", errEnginePending
}

func (pendingSettingEngine) write(context.Context, *ConfigHardeningPayload) error {
	return errEnginePending
}
