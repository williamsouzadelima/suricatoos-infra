package aiproviders

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// newFreeReg is a registry with the free-models-only rule ON (the production
// default, AI_FREE_MODELS_ONLY=true).
func newFreeReg(t *testing.T) *Registry {
	t.Helper()
	kek, _ := randBytes(kekSize)
	r, err := NewRegistry("", kek, WithFreeModelsOnly(true))
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	return r
}

// freeInput is an OpenRouter provider on the free router, enabled, with the
// data-policy acknowledgment: the "ready to use" shape under the free rule.
func freeInput() UpsertInput {
	return UpsertInput{
		Name: "OpenRouter grátis", Kind: KindOpenRouter, Model: "openrouter/free",
		Enabled: true, DataPolicyAck: true, APIKey: testKey,
	}
}

func TestIsFreeModel(t *testing.T) {
	for _, c := range []struct {
		kind, model string
		want        bool
	}{
		{KindOpenRouter, "x:free", true},
		{KindUnoRouter, "x:free", true},
		{KindOpenRouter, "nvidia/nemotron-3-super-120b-a12b:free", true},
		{KindUnoRouter, "deepseek-v4-flash:free", true},
		{KindOpenRouter, "openrouter/free", true},
		// The free ROUTER only exists on OpenRouter.
		{KindUnoRouter, "openrouter/free", false},
		{KindOpenAICompatible, "openrouter/free", false},
		{KindOpenRouter, "gpt-5.5", false},
		{KindOpenRouter, "openrouter/auto", false},
		{KindOpenRouter, "x:freeze", false},
		{KindOpenRouter, ":free", false}, // nothing before the suffix
		{KindOpenRouter, "", false},
		{KindOpenRouter, "x:FREE", false}, // exact, case-sensitive suffix
	} {
		if got := IsFreeModel(c.kind, c.model); got != c.want {
			t.Errorf("IsFreeModel(%q, %q) = %v, want %v", c.kind, c.model, got, c.want)
		}
	}
}

func TestFreeOnly_RejectsKindOutsideTheRouters(t *testing.T) {
	r := newFreeReg(t)
	in := freeInput()
	in.Kind, in.BaseURL, in.Model = KindOpenAICompatible, "https://api.example/v1", "x:free"
	_, err := r.Upsert(in, "op")
	if !errors.Is(err, ErrFreeOnly) {
		t.Fatalf("openai_compatible com a regra ligada deveria dar ErrFreeOnly, veio %v", err)
	}
	if !strings.Contains(err.Error(), "openai_compatible") {
		t.Fatalf("a mensagem deveria citar o tipo recusado: %v", err)
	}
	if n := len(r.List()); n != 0 {
		t.Fatalf("nada deveria ser gravado, há %d provedor(es)", n)
	}
}

func TestFreeOnly_RejectsNonFreeModel(t *testing.T) {
	r := newFreeReg(t)
	for _, c := range []struct{ kind, model string }{
		{KindOpenRouter, "openai/gpt-5.5"},
		{KindOpenRouter, "openrouter/auto"},
		{KindOpenRouter, "vendor/x:freeze"},
		{KindOpenRouter, ""}, // no model = the account default, which may be paid
		{KindUnoRouter, "openrouter/free"},
	} {
		in := freeInput()
		// Disabled on purpose: the model rule holds even just to STORE a provider.
		in.Kind, in.Model, in.Enabled = c.kind, c.model, false
		_, err := r.Upsert(in, "op")
		if !errors.Is(err, ErrFreeOnly) {
			t.Errorf("kind=%s model=%q: esperava ErrFreeOnly, veio %v", c.kind, c.model, err)
			continue
		}
		if !strings.Contains(err.Error(), ":free") {
			t.Errorf("kind=%s model=%q: a mensagem deveria explicar a regra (:free): %v", c.kind, c.model, err)
		}
	}
	if n := len(r.List()); n != 0 {
		t.Fatalf("nada deveria ser gravado, há %d provedor(es)", n)
	}
}

func TestFreeOnly_EnableRequiresDataPolicyAck(t *testing.T) {
	r := newFreeReg(t)
	in := freeInput()
	in.DataPolicyAck = false
	_, err := r.Upsert(in, "op")
	if !errors.Is(err, ErrGovernance) {
		t.Fatalf("gratuito habilitado sem ciência deveria dar ErrGovernance, veio %v", err)
	}
	if !strings.Contains(err.Error(), "data_policy_ack") {
		t.Fatalf("a mensagem de governança deveria citar a ciência (data_policy_ack): %v", err)
	}
	// The same provider may be STORED while disabled (the operator acknowledges later).
	in.Enabled = false
	pub, err := r.Upsert(in, "op")
	if err != nil {
		t.Fatalf("gratuito desabilitado sem ciência deveria salvar: %v", err)
	}
	if pub.DataPolicyAck || pub.DataPolicyAckBy != "" || !pub.DataPolicyAckAt.IsZero() {
		t.Fatalf("sem ciência não pode haver registro de ciência: %+v", pub)
	}
}

func TestFreeOnly_EUAndZDRStillEnableWithoutAck(t *testing.T) {
	// The governance bar is (UE && ZDR) || (free && ack): a free model on a provider
	// flagged UE + ZDR does not need the acknowledgment.
	r := newFreeReg(t)
	in := freeInput()
	in.DataPolicyAck, in.EURegion, in.ZDR = false, true, true
	if _, err := r.Upsert(in, "op"); err != nil {
		t.Fatalf("gratuito UE+ZDR deveria habilitar sem ciência: %v", err)
	}
}

func TestFreeOnly_AckRecordsOperatorAndTime(t *testing.T) {
	r := newFreeReg(t)
	t0 := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
	r.now = func() time.Time { return t0 }
	pub, err := r.Upsert(freeInput(), "alice")
	if err != nil {
		t.Fatalf("gratuito com ciência deveria habilitar: %v", err)
	}
	if !pub.Enabled || !pub.DataPolicyAck || pub.DataPolicyAckBy != "alice" || !pub.DataPolicyAckAt.Equal(t0) {
		t.Fatalf("a ciência deveria gravar quem/quando: %+v", pub)
	}

	// A later edit that keeps the ack does not rewrite who acknowledged, nor when.
	r.now = func() time.Time { return t0.Add(time.Hour) }
	up := freeInput()
	up.ID, up.Name, up.APIKey = pub.ID, "Renomeado", ""
	pub2, err := r.Upsert(up, "bob")
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if pub2.DataPolicyAckBy != "alice" || !pub2.DataPolicyAckAt.Equal(t0) || pub2.UpdatedBy != "bob" {
		t.Fatalf("editar mantendo a ciência não deveria reescrever quem/quando: %+v", pub2)
	}

	// Withdrawing the ack (and disabling) clears the record.
	up.Enabled, up.DataPolicyAck = false, false
	pub3, err := r.Upsert(up, "bob")
	if err != nil {
		t.Fatalf("retirar a ciência: %v", err)
	}
	if pub3.DataPolicyAck || pub3.DataPolicyAckBy != "" || !pub3.DataPolicyAckAt.IsZero() {
		t.Fatalf("retirar a ciência deveria limpar o registro: %+v", pub3)
	}

	// Acknowledging again records the NEW operator and time.
	up.Enabled, up.DataPolicyAck = true, true
	pub4, err := r.Upsert(up, "carol")
	if err != nil {
		t.Fatalf("nova ciência: %v", err)
	}
	if pub4.DataPolicyAckBy != "carol" || !pub4.DataPolicyAckAt.Equal(t0.Add(time.Hour)) {
		t.Fatalf("nova ciência deveria gravar o novo operador/hora: %+v", pub4)
	}
}

func TestFreeRuleOff_KeepsOldGovernance(t *testing.T) {
	r := newReg(t) // rule OFF
	// A paid model on a generic gateway is still allowed when UE + ZDR (old bar).
	paid := UpsertInput{
		Name: "Gateway UE", Kind: KindOpenAICompatible, BaseURL: "https://gw.example/v1",
		Model: "openai/gpt-5.5", EURegion: true, ZDR: true, Enabled: true, APIKey: "k",
	}
	if _, err := r.Upsert(paid, "op"); err != nil {
		t.Fatalf("regra desligada: pago UE+ZDR deveria habilitar: %v", err)
	}
	// ... and still refused without UE + ZDR, even with the ack (the ack covers FREE models only).
	paid.EURegion, paid.DataPolicyAck = false, true
	if _, err := r.Upsert(paid, "op"); !errors.Is(err, ErrGovernance) {
		t.Fatalf("regra desligada: pago fora de UE+ZDR deveria dar ErrGovernance, veio %v", err)
	}
	// The free path (free model + ack) is available with the rule off as well.
	if _, err := r.Upsert(freeInput(), "op"); err != nil {
		t.Fatalf("regra desligada: gratuito com ciência deveria habilitar: %v", err)
	}
}

func TestPresets_CreatedOnceWithExactValues(t *testing.T) {
	r := newFreeReg(t)
	created, err := r.EnsurePresets()
	if err != nil {
		t.Fatalf("EnsurePresets: %v", err)
	}
	if got := strings.Join(created, ","); got != "openrouter-free,unorouter-free" {
		t.Fatalf("presets criados = %q", got)
	}
	want := []PublicProvider{
		{ID: "openrouter-free", Name: "OpenRouter — modelos gratuitos", Kind: "openrouter", BaseURL: "https://openrouter.ai/api/v1", Model: "openrouter/free"},
		{ID: "unorouter-free", Name: "UnoRouter — modelos gratuitos", Kind: "unorouter", BaseURL: "https://api.unorouter.com/v1", Model: "deepseek-v4-flash:free"},
	}
	for _, w := range want {
		got, ok := r.Get(w.ID)
		if !ok {
			t.Fatalf("preset %s ausente", w.ID)
		}
		if got.Name != w.Name || got.Kind != w.Kind || got.BaseURL != w.BaseURL || got.Model != w.Model {
			t.Fatalf("preset %s = %+v, want %+v", w.ID, got, w)
		}
		if got.Enabled || got.HasKey || got.KeyLast4 != "" || got.EURegion || got.ZDR || got.DataPolicyAck {
			t.Fatalf("preset %s deveria nascer desabilitado, sem chave e sem ciência: %+v", w.ID, got)
		}
	}
	again, err := r.EnsurePresets()
	if err != nil || len(again) != 0 {
		t.Fatalf("2ª chamada não deveria criar nada: %v err=%v", again, err)
	}
	if n := len(r.List()); n != 2 {
		t.Fatalf("esperava 2 provedores, há %d", n)
	}
}

func TestPresets_NeverOverwriteOperatorEdits(t *testing.T) {
	r := newFreeReg(t)
	if _, err := r.EnsurePresets(); err != nil {
		t.Fatalf("EnsurePresets: %v", err)
	}
	// The "only paste the key" flow: key + ack + enable on the preset (switching its model).
	pub, err := r.Upsert(UpsertInput{
		ID: PresetOpenRouterFree, Name: "Meu OpenRouter", Kind: KindOpenRouter,
		Model: "nvidia/nemotron-3-super-120b-a12b:free", Enabled: true, DataPolicyAck: true, APIKey: testKey,
	}, "op")
	if err != nil {
		t.Fatalf("editar preset: %v", err)
	}
	if !pub.Enabled || !pub.HasKey {
		t.Fatalf("preset editado deveria estar habilitado e com chave: %+v", pub)
	}
	// ... and deletes the UnoRouter one.
	if !r.Delete(PresetUnoRouterFree) {
		t.Fatal("delete do preset unorouter-free falhou")
	}

	created, err := r.EnsurePresets()
	if err != nil {
		t.Fatalf("EnsurePresets: %v", err)
	}
	// Only the missing preset is ensured again; the edited one stays as the operator left it.
	if got := strings.Join(created, ","); got != PresetUnoRouterFree {
		t.Fatalf("só o preset ausente deveria ser recriado, veio %q", got)
	}
	got, _ := r.Get(PresetOpenRouterFree)
	if got.Name != "Meu OpenRouter" || got.Model != "nvidia/nemotron-3-super-120b-a12b:free" ||
		!got.Enabled || !got.HasKey || !got.DataPolicyAck {
		t.Fatalf("EnsurePresets sobrescreveu a edição do operador: %+v", got)
	}
	key, _, err := r.DecryptedKey(PresetOpenRouterFree)
	if err != nil || key != testKey {
		t.Fatalf("a chave colada deveria continuar: %q err=%v", key, err)
	}
}

func TestPresets_Persisted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "providers.json")
	kek, _ := randBytes(kekSize)
	r1, err := NewRegistry(path, kek, WithFreeModelsOnly(true))
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	if _, err := r1.EnsurePresets(); err != nil {
		t.Fatalf("EnsurePresets: %v", err)
	}
	r2, err := NewRegistry(path, kek, WithFreeModelsOnly(true))
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if _, ok := r2.Get(PresetUnoRouterFree); !ok {
		t.Fatal("preset deveria sobreviver ao reload")
	}
	created, err := r2.EnsurePresets()
	if err != nil || len(created) != 0 {
		t.Fatalf("após o reload nada deveria ser criado: %v err=%v", created, err)
	}
}
