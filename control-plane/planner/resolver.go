package planner

import (
	"context"
	"errors"

	"github.com/williamsouzadelima/suricatoos-infra/control-plane/aiproviders"
)

// RegistryResolver resolves an ENABLED provider from the aiproviders registry and
// decrypts its key server-side. With a providerID it uses that one; otherwise the
// first enabled provider (List is ordered by name). The plaintext key never leaves
// the process except in the outbound request the HTTPLLM makes.
type RegistryResolver struct {
	reg        *aiproviders.Registry
	providerID string
}

// NewRegistryResolver builds a resolver over reg. providerID may be empty (= first
// enabled provider).
func NewRegistryResolver(reg *aiproviders.Registry, providerID string) *RegistryResolver {
	return &RegistryResolver{reg: reg, providerID: providerID}
}

// Resolve implements planner.ProviderResolver.
func (r *RegistryResolver) Resolve(_ context.Context) (Provider, error) {
	id := r.providerID
	if id == "" {
		for _, p := range r.reg.List() {
			if p.Enabled {
				id = p.ID
				break
			}
		}
	}
	if id == "" {
		return Provider{}, errors.New("nenhum provedor de IA habilitado")
	}
	key, pub, err := r.reg.DecryptedKey(id)
	if err != nil {
		return Provider{}, err
	}
	return Provider{Name: pub.Name, BaseURL: pub.BaseURL, APIKey: key, Model: pub.Model}, nil
}
