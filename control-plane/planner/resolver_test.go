package planner

import (
	"context"
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
	prov, err := NewRegistryResolver(reg, "").Resolve(context.Background())
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if prov.Name != "ZZZ Habilitado" || prov.APIKey != "sk-live-1234" || prov.BaseURL != "https://openrouter.ai/api/v1" {
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
