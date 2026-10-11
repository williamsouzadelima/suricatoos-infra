package aiproviders

import (
	"errors"
	"strings"
)

// The FREE-models rule (AI_FREE_MODELS_ONLY, default on). The scanner's AI runs
// on the free tiers of the two routers, at zero cost:
//
//   - a model is FREE when its id ends in ":free" with something before the suffix
//     (both routers mark their free variants this way), or when it is the
//     "openrouter/free" router on OpenRouter (it picks an available free model);
//   - with the rule on, the registry accepts only the openrouter/unorouter kinds and
//     only free models, and the planner refuses to call any other model.
//
// Free models do NOT guarantee zero data retention (the free providers may log or
// train on prompts), so enabling one takes the operator's explicit acknowledgment
// of that data policy (data_policy_ack) — see Registry.Upsert.
const (
	// FreeSuffix marks a free model id on both routers.
	FreeSuffix = ":free"
	// OpenRouterFreeRouter is OpenRouter's router over its free models.
	OpenRouterFreeRouter = "openrouter/free"
	// FreeRule is the rule in words, as the policy endpoint reports it.
	FreeRule = "sufixo :free ou openrouter/free"

	// PresetOpenRouterFree and PresetUnoRouterFree are the fixed ids of the
	// pre-configured providers (EnsurePresets).
	PresetOpenRouterFree = "openrouter-free"
	PresetUnoRouterFree  = "unorouter-free"

	// presetBy is the updated_by of a preset nobody has edited yet.
	presetBy = "preset"
)

// ErrFreeOnly refuses a provider outside the free-models-only rule (kind other
// than openrouter/unorouter, or a model that is not free). Mapped to HTTP 422,
// like ErrGovernance.
var ErrFreeOnly = errors.New("só modelos gratuitos (AI_FREE_MODELS_ONLY=true)")

// IsFreeModel reports whether model is free under the rule above. The comparison
// is exact (case-sensitive): router ids are lowercase.
func IsFreeModel(kind, model string) bool {
	if kind == KindOpenRouter && model == OpenRouterFreeRouter {
		return true
	}
	base, ok := strings.CutSuffix(model, FreeSuffix)
	return ok && base != ""
}

// freeOnlyKind reports whether kind is allowed under the rule (the two routers
// whose catalogs define the ":free" convention).
func freeOnlyKind(kind string) bool {
	return kind == KindOpenRouter || kind == KindUnoRouter
}

// OfficialBaseURL is the official API endpoint of a router kind (openrouter or
// unorouter), "" for any other kind. With the free-models-only rule on it is the
// ONLY place a stored key may be sent: upsert pins base_url to it, and the models
// listing and the planner refuse any other endpoint. ":free" (and zero cost) only
// means something on these endpoints.
func OfficialBaseURL(kind string) string {
	if !freeOnlyKind(kind) {
		return ""
	}
	return defaultBaseURL(kind)
}

// IsOfficialEndpoint reports whether baseURL is kind's official endpoint (a
// trailing slash is tolerated; anything else must match exactly).
func IsOfficialEndpoint(kind, baseURL string) bool {
	official := OfficialBaseURL(kind)
	return official != "" && strings.TrimRight(baseURL, "/") == official
}

// preset is one pre-configured provider: born DISABLED, without a key and without
// the acknowledgment, so the operator only pastes the key, acknowledges and enables.
type preset struct {
	id, name, kind, model string
}

var presets = []preset{
	{PresetOpenRouterFree, "OpenRouter — modelos gratuitos", KindOpenRouter, OpenRouterFreeRouter},
	{PresetUnoRouterFree, "UnoRouter — modelos gratuitos", KindUnoRouter, "deepseek-v4-flash:free"},
}

// PresetIDs returns the preset ids in priority order (OpenRouter first).
func PresetIDs() []string {
	ids := make([]string, len(presets))
	for i, p := range presets {
		ids[i] = p.id
	}
	return ids
}

// EnsurePresets creates each preset whose id does not exist yet and persists the
// store. It NEVER touches an existing id, so an operator's edits (key, model,
// name, enabling) survive every boot; a preset the operator deleted is created
// again. It returns the ids it created (empty when all already existed).
func (r *Registry) EnsurePresets() ([]string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var created []string
	for _, ps := range presets {
		if _, ok := r.providers[ps.id]; ok {
			continue
		}
		r.providers[ps.id] = &Provider{
			ID: ps.id, Name: ps.name, Kind: ps.kind, BaseURL: defaultBaseURL(ps.kind), Model: ps.model,
			UpdatedBy: presetBy, UpdatedAt: r.now(),
		}
		created = append(created, ps.id)
	}
	if len(created) == 0 {
		return nil, nil
	}
	if err := r.saveLocked(); err != nil {
		for _, id := range created {
			delete(r.providers, id)
		}
		return nil, err
	}
	return created, nil
}
