package planner

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sort"
	"strings"

	"github.com/williamsouzadelima/suricatoos-infra/control-plane/aiproviders"
)

// RegistryResolver resolves the ENABLED providers from the aiproviders registry,
// in priority order, decrypting their keys server-side. With an explicit id list
// (AI_PLANNER_PROVIDER_ID, comma-separated) it uses those, in that order. Without
// one: with the free-models rule on, ONLY the presets (openrouter-free, then
// unorouter-free), and any other provider is ignored; with it off, every enabled
// provider, the presets first and then the rest by name. A provider that cannot
// be used (missing, disabled, no key) is skipped. Each provider carries its
// governance terms (UE/ZDR/acknowledgment), which the Planner re-checks at use
// time. The plaintext key never leaves the process except in the outbound request
// the HTTPLLM makes.
type RegistryResolver struct {
	reg *aiproviders.Registry
	ids []string
}

// NewRegistryResolver builds a resolver over reg. providerIDs is a comma-separated
// priority list; empty = every enabled provider in the default order.
func NewRegistryResolver(reg *aiproviders.Registry, providerIDs string) *RegistryResolver {
	var ids []string
	seen := map[string]bool{}
	for _, id := range strings.Split(providerIDs, ",") {
		id = strings.TrimSpace(id)
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		ids = append(ids, id)
	}
	return &RegistryResolver{reg: reg, ids: ids}
}

// Resolve implements planner.ProviderResolver.
func (r *RegistryResolver) Resolve(_ context.Context) ([]Provider, error) {
	ids := r.ids
	explicit := len(ids) > 0
	if !explicit {
		ids = r.defaultOrder()
		if len(ids) == 0 {
			if r.reg.FreeModelsOnly() {
				return nil, errors.New("nenhum provedor de IA habilitado entre os presets (com AI_FREE_MODELS_ONLY=true o planner usa só openrouter-free e unorouter-free)")
			}
			return nil, errors.New("nenhum provedor de IA habilitado")
		}
	}
	var out []Provider
	var skipped []string
	for _, id := range ids {
		key, pub, err := r.reg.DecryptedKey(id)
		if err != nil {
			skipped = append(skipped, fmt.Sprintf("%s: %v", id, err))
			continue
		}
		out = append(out, Provider{
			ID: pub.ID, Name: pub.Name, Kind: pub.Kind,
			BaseURL: pub.BaseURL, APIKey: key, Model: pub.Model,
			EURegion: pub.EURegion, ZDR: pub.ZDR, DataPolicyAck: pub.DataPolicyAck,
		})
	}
	if len(out) == 0 {
		if explicit {
			return nil, fmt.Errorf("nenhum provedor de IA utilizável em AI_PLANNER_PROVIDER_ID (%s)", strings.Join(skipped, "; "))
		}
		return nil, fmt.Errorf("nenhum provedor de IA utilizável (%s)", strings.Join(skipped, "; "))
	}
	return out, nil
}

// defaultOrder lists the enabled providers in priority order. With the free-models
// rule on, ONLY the presets — openrouter-free, then unorouter-free; any other
// enabled provider is ignored (and logged), as the UI says. With it off, the
// presets first, then the rest in the registry's order (name, then id).
func (r *RegistryResolver) defaultOrder() []string {
	rank := map[string]int{}
	for i, id := range aiproviders.PresetIDs() {
		rank[id] = i + 1
	}
	pos := func(id string) int {
		if n, ok := rank[id]; ok {
			return n
		}
		return len(rank) + 1
	}
	presetsOnly := r.reg.FreeModelsOnly()
	var enabled []aiproviders.PublicProvider
	var ignored []string
	for _, p := range r.reg.List() {
		if !p.Enabled {
			continue
		}
		if _, preset := rank[p.ID]; presetsOnly && !preset {
			ignored = append(ignored, p.ID)
			continue
		}
		enabled = append(enabled, p)
	}
	if len(ignored) > 0 {
		log.Printf("remediation-planner: com AI_FREE_MODELS_ONLY=true a ordem padrão usa só os presets; ignorados: %s", strings.Join(ignored, ", "))
	}
	sort.SliceStable(enabled, func(i, j int) bool { return pos(enabled[i].ID) < pos(enabled[j].ID) })
	ids := make([]string, len(enabled))
	for i, p := range enabled {
		ids[i] = p.ID
	}
	return ids
}
