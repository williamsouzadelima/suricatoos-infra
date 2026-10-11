package planner

import (
	"context"
	"strings"
	"testing"

	"github.com/williamsouzadelima/suricatoos-infra/control-plane/aiproviders"
)

func TestRegistryResolver_PicksFirstEnabled(t *testing.T) {
	kek := make([]byte, 32) // AES-256 key (zeros ok for the test)
	reg, err := aiproviders.NewRegistry("", kek)
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	if _, err := reg.Upsert(aiproviders.UpsertInput{
		Name: "AAA Desabilitado", Kind: aiproviders.KindOpenAICompatible, BaseURL: "https://a/v1",
		EURegion: true, ZDR: true, Enabled: false, APIKey: "k-off",
	}, "op"); err != nil {
		t.Fatalf("upsert off: %v", err)
	}
	if _, err := reg.Upsert(aiproviders.UpsertInput{
		Name: "ZZZ Habilitado", Kind: aiproviders.KindOpenRouter,
		EURegion: true, ZDR: true, Enabled: true, APIKey: "sk-live-1234",
	}, "op"); err != nil {
		t.Fatalf("upsert on: %v", err)
	}
	provs, err := NewRegistryResolver(reg, "").Resolve(context.Background())
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if len(provs) != 1 {
		t.Fatalf("só o habilitado é candidato: %+v", provs)
	}
	prov := provs[0]
	if prov.Name != "ZZZ Habilitado" || prov.APIKey != "sk-live-1234" || prov.BaseURL != "https://openrouter.ai/api/v1" ||
		prov.Kind != aiproviders.KindOpenRouter || prov.ID == "" {
		t.Fatalf("resolveu o provedor errado: %+v", prov)
	}
}

func TestRegistryResolver_NoneEnabledErrors(t *testing.T) {
	kek := make([]byte, 32)
	reg, _ := aiproviders.NewRegistry("", kek)
	_, _ = reg.Upsert(aiproviders.UpsertInput{
		Name: "Off", Kind: aiproviders.KindOpenRouter, EURegion: true, ZDR: true, Enabled: false, APIKey: "k",
	}, "op")
	if _, err := NewRegistryResolver(reg, "").Resolve(context.Background()); err == nil {
		t.Fatal("nenhum provedor habilitado deveria dar erro")
	}
}

// freeRegistry is a free-only registry with both presets ready to use (key pasted,
// acknowledged, enabled), plus extra providers. The presets are RENAMED so that
// name order (AAA < Mu < Zeta) disagrees with the required priority (openrouter-
// free, unorouter-free, rest): only the id-based ranking yields the right order.
func freeRegistry(t *testing.T) *aiproviders.Registry {
	t.Helper()
	reg, err := aiproviders.NewRegistry("", make([]byte, 32), aiproviders.WithFreeModelsOnly(true))
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	if _, err := reg.EnsurePresets(); err != nil {
		t.Fatalf("EnsurePresets: %v", err)
	}
	for _, in := range []aiproviders.UpsertInput{
		{ID: aiproviders.PresetUnoRouterFree, Name: "Mu UnoRouter", Kind: aiproviders.KindUnoRouter, Model: "deepseek-v4-flash:free", Enabled: true, DataPolicyAck: true, APIKey: "k-uno"},
		{ID: aiproviders.PresetOpenRouterFree, Name: "Zeta OpenRouter", Kind: aiproviders.KindOpenRouter, Model: "openrouter/free", Enabled: true, DataPolicyAck: true, APIKey: "k-or"},
		// Sorts FIRST by name, but goes after both presets.
		{Name: "AAA Outro", Kind: aiproviders.KindOpenRouter, Model: "vendor/a:free", Enabled: true, DataPolicyAck: true, APIKey: "k-aaa"},
		{Name: "BBB Desligado", Kind: aiproviders.KindOpenRouter, Model: "vendor/b:free", Enabled: false, APIKey: "k-bbb"},
	} {
		if _, err := reg.Upsert(in, "op"); err != nil {
			t.Fatalf("upsert %s: %v", in.Name, err)
		}
	}
	return reg
}

func names(provs []Provider) string {
	var out []string
	for _, p := range provs {
		out = append(out, p.Name)
	}
	return strings.Join(out, " | ")
}

func TestRegistryResolver_DefaultOrderPutsPresetsFirst(t *testing.T) {
	provs, err := NewRegistryResolver(freeRegistry(t), "").Resolve(context.Background())
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	want := "Zeta OpenRouter | Mu UnoRouter | AAA Outro"
	if got := names(provs); got != want {
		t.Fatalf("ordem = %q, want %q", got, want)
	}
	if provs[0].ID != aiproviders.PresetOpenRouterFree || provs[0].APIKey != "k-or" || provs[0].Kind != aiproviders.KindOpenRouter || provs[0].Model != "openrouter/free" {
		t.Fatalf("1º candidato incompleto: %+v", provs[0])
	}
	if provs[1].APIKey != "k-uno" || provs[1].Kind != aiproviders.KindUnoRouter {
		t.Fatalf("2º candidato incompleto: %+v", provs[1])
	}
}

func TestRegistryResolver_ExplicitListKeepsOrderAndSkipsUnusable(t *testing.T) {
	reg := freeRegistry(t)
	// Operator's priority: UnoRouter first; unknown ids and repeats are ignored.
	provs, err := NewRegistryResolver(reg, " unorouter-free, nao-existe ,openrouter-free,unorouter-free,").Resolve(context.Background())
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got := names(provs); got != "Mu UnoRouter | Zeta OpenRouter" {
		t.Fatalf("a lista explícita manda na ordem: %q", got)
	}
	// A disabled provider in the list is skipped (the next one serves).
	if _, err := reg.Upsert(aiproviders.UpsertInput{ID: aiproviders.PresetUnoRouterFree, Name: "Mu UnoRouter", Kind: aiproviders.KindUnoRouter, Model: "deepseek-v4-flash:free", Enabled: false}, "op"); err != nil {
		t.Fatalf("desabilitar: %v", err)
	}
	provs, err = NewRegistryResolver(reg, "unorouter-free,openrouter-free").Resolve(context.Background())
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got := names(provs); got != "Zeta OpenRouter" {
		t.Fatalf("provedor desabilitado deveria ser pulado: %q", got)
	}
}

func TestRegistryResolver_ExplicitListNoneUsableErrors(t *testing.T) {
	reg := freeRegistry(t)
	_, err := NewRegistryResolver(reg, "nao-existe,BBB").Resolve(context.Background())
	if err == nil {
		t.Fatal("lista sem nenhum provedor utilizável deveria dar erro")
	}
	if !strings.Contains(err.Error(), "nao-existe") {
		t.Fatalf("o erro deveria dizer qual id falhou: %v", err)
	}
}
