package aiproviders

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// The stored key belongs to the recipient it was pasted for: its kind AND its
// endpoint. An update that changes either one without a NEW api_key would take the
// stored key somewhere else, so it is refused (ErrKeyRebind → 422) and NOTHING
// changes. With a new key the change goes through, and the data-policy
// acknowledgment starts over (another recipient, another acknowledgment). Saving a
// record of the SAME kind to pin its official endpoint keeps the key (the
// documented exception for legacy records).

const msgKeyRebind = "cole a chave de novo ao trocar o tipo/endpoint"

var t0 = time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)

// fileFreeReg is a file-backed registry with the free-models-only rule on, so a
// test can prove a refused upsert does not even rewrite the store.
func fileFreeReg(t *testing.T) (*Registry, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ai-providers.json")
	kek, _ := randBytes(kekSize)
	r, err := NewRegistry(path, kek, WithFreeModelsOnly(true))
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	return r, path
}

// keyedPreset leaves the openrouter-free preset ready to use: key pasted,
// acknowledged by alice at t0, enabled.
func keyedPreset(t *testing.T, r *Registry) PublicProvider {
	t.Helper()
	if _, err := r.EnsurePresets(); err != nil {
		t.Fatalf("EnsurePresets: %v", err)
	}
	r.now = func() time.Time { return t0 }
	pub, err := r.Upsert(UpsertInput{
		ID: PresetOpenRouterFree, Name: "OpenRouter — modelos gratuitos", Kind: KindOpenRouter,
		Model: OpenRouterFreeRouter, Enabled: true, DataPolicyAck: true, APIKey: testKey,
	}, "alice")
	if err != nil {
		t.Fatalf("preparar o preset: %v", err)
	}
	return pub
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ler %s: %v", path, err)
	}
	return b
}

// I3: OpenRouter key on the preset, then a request switches the kind to UnoRouter
// without a new key — with the free rule on, where the endpoint would become the
// OTHER router's official one.
func TestUpsert_KindSwitchWithoutNewKeyIsRefusedAndChangesNothing(t *testing.T) {
	r, path := fileFreeReg(t)
	before := keyedPreset(t, r)
	stored := readFile(t, path)
	r.now = func() time.Time { return t0.Add(time.Hour) }

	_, err := r.Upsert(UpsertInput{
		ID: PresetOpenRouterFree, Name: before.Name, Kind: KindUnoRouter,
		Model: "deepseek-v4-flash:free", Enabled: true, DataPolicyAck: true,
	}, "mallory")
	if !errors.Is(err, ErrKeyRebind) {
		t.Fatalf("trocar o tipo sem chave nova deveria dar ErrKeyRebind, veio %v", err)
	}
	if !strings.Contains(err.Error(), msgKeyRebind) {
		t.Fatalf("a mensagem deveria pedir a chave de novo (%q): %v", msgKeyRebind, err)
	}
	after, _ := r.Get(PresetOpenRouterFree)
	if !reflect.DeepEqual(after, before) {
		t.Fatalf("o registro mudou:\n antes  %+v\n depois %+v", before, after)
	}
	if !bytes.Equal(readFile(t, path), stored) {
		t.Fatal("o pedido recusado regravou o store")
	}
	key, pub, err := r.DecryptedKey(PresetOpenRouterFree)
	if err != nil || key != testKey || pub.Kind != KindOpenRouter || pub.BaseURL != OfficialBaseURL(KindOpenRouter) {
		t.Fatalf("a chave deveria seguir presa ao OpenRouter: kind=%q base=%q err=%v", pub.Kind, pub.BaseURL, err)
	}
}

// With the rule OFF the base_url is the operator's: repointing a key-bearing
// provider (or switching its kind) without a new key is refused all the same —
// this closes "a session repoints a key-bearing provider" in the legacy mode.
func TestUpsert_RuleOffRepointWithoutNewKeyIsRefused(t *testing.T) {
	r := newReg(t) // rule off
	gw := UpsertInput{
		Name: "Gateway UE", Kind: KindOpenAICompatible, BaseURL: "https://gw.example/v1",
		Model: "openai/gpt-5.5", EURegion: true, ZDR: true, Enabled: true, APIKey: testKey,
	}
	id := mustUpsert(t, r, gw)
	before, _ := r.Get(id)
	gw.ID, gw.APIKey = id, ""
	for _, c := range []struct{ name, kind, base string }{
		{"outra base", KindOpenAICompatible, "https://outro.example/v1"},
		{"mesmo host, outro caminho", KindOpenAICompatible, "https://gw.example/v2"},
		{"outro tipo (endpoint oficial dele)", KindOpenRouter, ""},
		{"outro tipo, mesma base", KindUnoRouter, "https://gw.example/v1"},
	} {
		in := gw
		in.Kind, in.BaseURL = c.kind, c.base
		if _, err := r.Upsert(in, "intruso"); !errors.Is(err, ErrKeyRebind) {
			t.Errorf("%s: esperava ErrKeyRebind, veio %v", c.name, err)
		}
	}
	if after, _ := r.Get(id); !reflect.DeepEqual(after, before) {
		t.Fatalf("pedidos recusados mudaram o registro:\n antes  %+v\n depois %+v", before, after)
	}

	// The same endpoint (a trailing slash is the same destination) is not a move:
	// metadata edits keep working and keep the key.
	in := gw
	in.Name, in.BaseURL = "Gateway UE renomeado", "https://gw.example/v1/"
	if _, err := r.Upsert(in, "op"); err != nil {
		t.Fatalf("editar sem mudar o destino deveria passar: %v", err)
	}
	if key, _, err := r.DecryptedKey(id); err != nil || key != testKey {
		t.Fatalf("a chave deveria continuar: %q err=%v", key, err)
	}
}

// The documented exception, narrowed: a record of the SAME kind may be saved again
// to pin its official endpoint, keeping the key, ONLY when its old endpoint already
// sat on that official host (case-insensitive, same port) — the key keeps going to
// the host it was pasted for. From any other host (a proxy, the other router, the
// official host on another port) the key stays where it is: 422. Rule off here;
// rule on in TestModels_LegacyRecordOnTheOtherRoutersHostKeepsItsKeyThere and
// TestModels_RefusesLegacyForeignEndpoint.
func TestUpsert_PinningTheOfficialEndpointKeepsTheKeyOnlyFromTheOfficialHost(t *testing.T) {
	r := newReg(t) // rule off: a custom endpoint is allowed
	for _, base := range []string{"https://openrouter.ai/v1", "https://OPENROUTER.AI/api/v1"} {
		id := mustUpsert(t, r, UpsertInput{Name: "Host oficial", Kind: KindOpenRouter, BaseURL: base, Model: "openai/gpt-5.5", APIKey: testKey})
		pub, err := r.Upsert(UpsertInput{ID: id, Name: "Host oficial", Kind: KindOpenRouter, Model: "openai/gpt-5.5"}, "op")
		if err != nil {
			t.Fatalf("%s: mesmo host oficial, salvar de novo fixando o endpoint deveria passar: %v", base, err)
		}
		if pub.BaseURL != OfficialBaseURL(KindOpenRouter) || !pub.HasKey || pub.KeyLast4 != last4(testKey) {
			t.Fatalf("%s: deveria fixar o oficial e manter a chave: %+v", base, pub)
		}
	}

	for _, c := range []struct{ name, kind, base string }{
		{"proxy", KindOpenRouter, "https://proxy.example/v1"},
		{"host do outro roteador", KindUnoRouter, "https://openrouter.ai/api/v1"},
		{"host oficial em outra porta", KindOpenRouter, "https://openrouter.ai:8443/api/v1"},
	} {
		id := mustUpsert(t, r, UpsertInput{Name: c.name, Kind: c.kind, BaseURL: c.base, Model: "x:free", APIKey: testKey})
		before, _ := r.Get(id)
		if _, err := r.Upsert(UpsertInput{ID: id, Name: c.name, Kind: c.kind, Model: "x:free"}, "op"); !errors.Is(err, ErrKeyRebind) {
			t.Errorf("%s: fixar o oficial vindo de outro host sem chave nova deveria dar ErrKeyRebind, veio %v", c.name, err)
		}
		if after, _ := r.Get(id); !reflect.DeepEqual(after, before) {
			t.Errorf("%s: pedido recusado mudou o registro:\n antes  %+v\n depois %+v", c.name, before, after)
		}
	}
}

// The legacy shape the narrowed exception exists for: a record of kind unorouter
// whose base_url sits on OpenRouter's host and holds an OpenRouter key (saved while
// the rule was off). With the rule on, saving it again without a new key would pin
// api.unorouter.com and send that key there: refused (422), the record and the
// store stay as they were, and no router is contacted. With a new key the save pins
// the official endpoint and only the NEW key travels — to UnoRouter.
func TestModels_LegacyRecordOnTheOtherRoutersHostKeepsItsKeyThere(t *testing.T) {
	const orKey = "sk-or-v1-CHAVE-DO-OPENROUTER-0001"
	const unoKey = "sk-uno-CHAVE-NOVA-0002"
	up := newUpstream(t, serveCatalog) // answers for BOTH official hosts and records each Host
	path := filepath.Join(t.TempDir(), "providers.json")
	kek, _ := randBytes(kekSize)
	old, err := NewRegistry(path, kek) // rule off, as before the rule
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	id := mustUpsert(t, old, UpsertInput{Name: "Uno antigo", Kind: KindUnoRouter, BaseURL: OfficialBaseURL(KindOpenRouter), Model: "deepseek-v4-flash:free", APIKey: orKey})

	reg, err := NewRegistry(path, kek, WithFreeModelsOnly(true)) // same store, rule on
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	srv, _, _ := serveModels(t, reg, up)
	before, _ := reg.Get(id)
	stored := readFile(t, path)

	resave := `{"id":"` + id + `","name":"Uno antigo","kind":"unorouter","model":"deepseek-v4-flash:free"}`
	resp, b := do(t, srv, "POST", "/api/v1/ai/providers", "s3cret", resave)
	if resp.StatusCode != http.StatusUnprocessableEntity || !strings.Contains(decodeModels(t, b).Error, msgKeyRebind) {
		t.Fatalf("salvar de novo sem chave nova = %d %s, want 422 (%s)", resp.StatusCode, b, msgKeyRebind)
	}
	if after, _ := reg.Get(id); !reflect.DeepEqual(after, before) {
		t.Fatalf("o registro mudou:\n antes  %+v\n depois %+v", before, after)
	}
	if !bytes.Equal(readFile(t, path), stored) {
		t.Fatal("o pedido recusado regravou o store")
	}
	if resp, b := do(t, srv, "GET", "/api/v1/ai/providers/"+id+"/models", "s3cret", ""); resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("lista de modelos do registro antigo = %d %s, want 422", resp.StatusCode, b)
	}
	if n := up.count(); n != 0 {
		t.Fatalf("nenhum roteador pode ser contatado: %d chamada(s), hosts %q", n, up.seenHosts())
	}

	repaste := `{"id":"` + id + `","name":"Uno antigo","kind":"unorouter","model":"deepseek-v4-flash:free","api_key":"` + unoKey + `"}`
	if resp, b := do(t, srv, "POST", "/api/v1/ai/providers", "s3cret", repaste); resp.StatusCode != http.StatusOK {
		t.Fatalf("salvar com chave nova = %d: %s", resp.StatusCode, b)
	}
	if resp, b := do(t, srv, "GET", "/api/v1/ai/providers/"+id+"/models", "s3cret", ""); resp.StatusCode != http.StatusOK {
		t.Fatalf("lista de modelos após colar a chave = %d: %s", resp.StatusCode, b)
	}
	if h := up.seenHosts(); h != "api.unorouter.com" || up.lastAuth() != "Bearer "+unoKey {
		t.Fatalf("só a chave nova vai, e só ao UnoRouter: hosts %q auth %q", h, up.lastAuth())
	}
}

// With a NEW key the kind/endpoint change goes through, and the acknowledgment
// starts over: the previous one (given for another recipient) never carries over.
func TestUpsert_NewKeyWithKindSwitchStartsTheAckOver(t *testing.T) {
	r := newFreeReg(t)
	keyedPreset(t, r) // acknowledged by alice at t0

	// The same request brings the new key AND the acknowledgment: the provider stays
	// enabled, with a NEW acknowledgment (bob, t1) — never alice's.
	t1 := t0.Add(time.Hour)
	r.now = func() time.Time { return t1 }
	pub, err := r.Upsert(UpsertInput{
		ID: PresetOpenRouterFree, Name: "Agora UnoRouter", Kind: KindUnoRouter,
		Model: "deepseek-v4-flash:free", Enabled: true, DataPolicyAck: true, APIKey: "sk-uno-NOVA-0001",
	}, "bob")
	if err != nil {
		t.Fatalf("trocar o tipo com chave nova e ciência deveria passar: %v", err)
	}
	if pub.Kind != KindUnoRouter || pub.BaseURL != OfficialBaseURL(KindUnoRouter) || pub.KeyLast4 != "0001" || !pub.Enabled {
		t.Fatalf("troca com chave nova: %+v", pub)
	}
	if !pub.DataPolicyAck || pub.DataPolicyAckBy != "bob" || !pub.DataPolicyAckAt.Equal(t1) {
		t.Fatalf("outro destinatário ⇒ nova ciência (bob, t1), veio by=%q at=%s", pub.DataPolicyAckBy, pub.DataPolicyAckAt)
	}

	// Without the acknowledgment in the same request the provider cannot stay
	// enabled: enabling is refused (and nothing changes) ...
	t2 := t1.Add(time.Hour)
	r.now = func() time.Time { return t2 }
	before, _ := r.Get(PresetOpenRouterFree)
	back := UpsertInput{
		ID: PresetOpenRouterFree, Name: "De volta", Kind: KindOpenRouter,
		Model: OpenRouterFreeRouter, Enabled: true, APIKey: "sk-or-NOVA-0002",
	}
	if _, err := r.Upsert(back, "carol"); !errors.Is(err, ErrGovernance) {
		t.Fatalf("habilitar sem a ciência no mesmo pedido deveria dar ErrGovernance, veio %v", err)
	}
	if after, _ := r.Get(PresetOpenRouterFree); !reflect.DeepEqual(after, before) {
		t.Fatalf("pedido recusado mudou o registro:\n antes  %+v\n depois %+v", before, after)
	}
	// ... and saved disabled, the switch replaces the key and zeroes the acknowledgment.
	back.Enabled = false
	pub, err = r.Upsert(back, "carol")
	if err != nil {
		t.Fatalf("trocar o tipo com chave nova, desabilitado: %v", err)
	}
	if pub.Enabled || pub.KeyLast4 != "0002" || pub.DataPolicyAck || pub.DataPolicyAckBy != "" || !pub.DataPolicyAckAt.IsZero() {
		t.Fatalf("chave nova sem ciência ⇒ desabilitado e ciência zerada: %+v", pub)
	}
}

// A new key for the SAME recipient (kind and endpoint unchanged) is not a move:
// the acknowledgment given for that recipient stays as it was.
func TestUpsert_NewKeySameRecipientKeepsTheAck(t *testing.T) {
	r := newFreeReg(t)
	keyedPreset(t, r)
	r.now = func() time.Time { return t0.Add(time.Hour) }
	pub, err := r.Upsert(UpsertInput{
		ID: PresetOpenRouterFree, Name: "OpenRouter — modelos gratuitos", Kind: KindOpenRouter,
		Model: OpenRouterFreeRouter, Enabled: true, DataPolicyAck: true, APIKey: "sk-or-ROTACIONADA-0003",
	}, "bob")
	if err != nil {
		t.Fatalf("trocar só a chave: %v", err)
	}
	if pub.KeyLast4 != "0003" || pub.DataPolicyAckBy != "alice" || !pub.DataPolicyAckAt.Equal(t0) {
		t.Fatalf("mesmo destinatário: chave nova, ciência mantida (alice, t0): %+v", pub)
	}
}

// Over HTTP: the session route answers 422 with the message, in JSON.
func TestService_KindSwitchWithoutNewKeyIs422(t *testing.T) {
	srv, reg, _, _ := modelsHarness(t, true, nil)
	keyedPreset(t, reg)
	body := `{"id":"openrouter-free","name":"OpenRouter — modelos gratuitos","kind":"unorouter","model":"deepseek-v4-flash:free","enabled":true,"data_policy_ack":true}`
	resp, b := doSession(t, srv, "POST", "/ai/providers", body)
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("troca de tipo sem chave = %d, want 422: %s", resp.StatusCode, b)
	}
	var e struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(b, &e); err != nil || !strings.Contains(e.Error, msgKeyRebind) {
		t.Fatalf("o 422 deveria trazer %q em JSON: %s", msgKeyRebind, b)
	}
}
