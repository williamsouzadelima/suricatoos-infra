package planner

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/williamsouzadelima/suricatoos-infra/control-plane/aiproviders"
)

// At use time the planner applies the SAME governance bar as the registry
// (aiproviders.GovernanceRefusal): a provider that fails it is SKIPPED — the
// reason goes to the log, never a secret — and the next one is tried.

func TestPlan_FreeOnlySkipsAProviderWithoutTheAck(t *testing.T) {
	noAck := freeA
	noAck.DataPolicyAck = false
	noAck.EURegion, noAck.ZDR = true, true // the self-declared flags do not replace it
	llm := &scriptLLM{byModel: map[string]scripted{freeA.Model: okScript(), freeB.Model: okScript()}}

	plan, err := New(llm, fakeResolver{provs: []Provider{noAck, freeB}}, freeCfg()).Plan(context.Background(), sampleReq())
	if err != nil || plan.Provider != freeB.Name {
		t.Fatalf("o provedor sem ciência deveria ser pulado e o próximo atender: plan=%+v err=%v", plan, err)
	}
	if llm.called() != freeB.Model {
		t.Fatalf("o provedor sem ciência não pode ser chamado: chamadas=%s", llm.called())
	}

	// Alone, it is refused before any call (the free rule's 403), with the reason.
	_, err = New(llm, fakeResolver{provs: []Provider{noAck}}, freeCfg()).Plan(context.Background(), sampleReq())
	if !errors.Is(err, ErrNonFreeModel) || !strings.Contains(err.Error(), "data_policy_ack") {
		t.Fatalf("sozinho e sem ciência: esperava a recusa citando a ciência, veio %v", err)
	}
	if llm.called() != freeB.Model {
		t.Fatalf("nenhuma chamada nova ao provedor sem ciência: %s", llm.called())
	}
}

// With the rule off the legacy bar holds at use time: (UE && ZDR) || (free on the
// official endpoint && acknowledgment).
func TestPlan_RuleOffAppliesTheLegacyBar(t *testing.T) {
	cfg := Config{ConsentGranted: true} // rule off
	below := Provider{ID: "gw", Name: "Gateway sem UE/ZDR", Kind: "openai_compatible", BaseURL: "https://gw.example/v1", APIKey: "k", Model: "m"}
	noAck := freeA
	noAck.DataPolicyAck = false
	for _, prov := range []Provider{below, noAck} {
		llm := &scriptLLM{byModel: map[string]scripted{prov.Model: okScript()}}
		_, err := New(llm, fakeResolver{provs: []Provider{prov}}, cfg).Plan(context.Background(), sampleReq())
		if !errors.Is(err, ErrUngoverned) || !strings.Contains(err.Error(), prov.Name) {
			t.Fatalf("%s: esperava ErrUngoverned citando o provedor, veio %v", prov.Name, err)
		}
		if llm.called() != "" {
			t.Fatalf("%s: provedor fora da régua não pode ser chamado: %s", prov.Name, llm.called())
		}
	}
	ue := below
	ue.EURegion, ue.ZDR = true, true
	for _, prov := range []Provider{ue, freeA} {
		llm := &scriptLLM{byModel: map[string]scripted{prov.Model: okScript()}}
		if _, err := New(llm, fakeResolver{provs: []Provider{prov}}, cfg).Plan(context.Background(), sampleReq()); err != nil {
			t.Fatalf("%s: dentro da régua deveria atender: %v", prov.Name, err)
		}
	}
}

// M3: with the rule off, a ":free" id off the router's official endpoint is NOT
// free — it pays: it consumes the budget and is barred by the ceiling.
func TestPlan_FreeSuffixOffTheOfficialEndpointIsNotFree(t *testing.T) {
	gw := Provider{ID: "gw", Name: "Gateway UE", Kind: "openai_compatible", BaseURL: "https://gw.example/v1", APIKey: "k", Model: "openai/gpt-5.5:free", EURegion: true, ZDR: true}
	huge := Usage{PromptTokens: 1_000_000, CompletionTokens: 1_000_000}
	llm := &scriptLLM{byModel: map[string]scripted{gw.Model: {resp: ChatResponse{Content: okContent, Usage: huge}}}}
	p := New(llm, fakeResolver{provs: []Provider{gw}}, Config{ConsentGranted: true, MonthlyBudgetUSD: 0.001, USDPer1kTokens: 0.005})
	if _, err := p.Plan(context.Background(), sampleReq()); err != nil {
		t.Fatalf("1ª chamada (dentro do teto): %v", err)
	}
	if _, err := p.Plan(context.Background(), sampleReq()); !errors.Is(err, ErrBudget) {
		t.Fatalf(":free fora do endpoint oficial é pago: a 2ª chamada deveria ser barrada pelo teto, veio %v", err)
	}
	if llm.called() != gw.Model {
		t.Fatalf("só 1 chamada deveria ir ao modelo: %s", llm.called())
	}
}

// M7 over real HTTP: a 404 from the first provider — e.g. OpenRouter's "No
// endpoints found matching your data policy" — goes on to the second.
func TestPlan_404FromTheFirstProviderCallsTheSecond(t *testing.T) {
	var firstHits, secondHits int32
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&firstHits, 1)
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":{"message":"No endpoints found matching your data policy","code":404}}`))
	}))
	defer first.Close()
	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&secondHits, 1)
		_, _ = w.Write(chatBody(okContent))
	}))
	defer second.Close()
	llm := routedLLM(hostRouter{hostOf(officialOR): first, hostOf(officialUno): second})

	plan, err := New(llm, fakeResolver{provs: []Provider{freeA, freeB}}, freeCfg()).Plan(context.Background(), sampleReq())
	if err != nil || plan.Provider != freeB.Name {
		t.Fatalf("o 404 do 1º provedor deveria levar ao 2º: plan=%+v err=%v", plan, err)
	}
	if atomic.LoadInt32(&firstHits) != 1 || atomic.LoadInt32(&secondHits) != 1 {
		t.Fatalf("chamadas: 1º=%d 2º=%d, want 1 e 1", firstHits, secondHits)
	}
}

// M7: when every provider fails, the error lists each attempt's status — with a
// short, sanitized excerpt of the provider's body at most, and no secret.
func TestPlan_AllFailedAggregatesEachAttemptWithoutSecrets(t *testing.T) {
	const key = "sk-or-v1-SEGREDO-0123456789abcdef"
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("{\"error\":\"sem rota para " + r.Header.Get("Authorization") +
			"\n\x1b[31m outra: sk-or-v1-OUTRA-CHAVE-9999\x00 " + strings.Repeat("x", 600) + "\"}"))
	}))
	defer first.Close()
	hung := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body) // only then does net/http notice the client leaving
		select {
		case <-r.Context().Done():
		case <-time.After(5 * time.Second):
		}
	}))
	defer hung.Close()
	// A short per-attempt timeout (60 s in production) makes the second one time out.
	llm := &HTTPLLM{hc: &http.Client{Timeout: 300 * time.Millisecond, Transport: hostRouter{hostOf(officialOR): first, hostOf(officialUno): hung}}}
	a := freeA
	a.APIKey = key

	_, err := New(llm, fakeResolver{provs: []Provider{a, freeB}}, freeCfg()).Plan(context.Background(), sampleReq())
	if err == nil || errors.Is(err, ErrTimeout) {
		t.Fatalf("todos falhando (sem estourar o tempo total) deveria dar o erro agregado, veio %v", err)
	}
	msg := err.Error()
	for _, want := range []string{a.Name + ": provedor respondeu 404", freeB.Name + `: Post "` + officialUno + `/chat/completions"`} {
		if !strings.Contains(msg, want) {
			t.Fatalf("o erro deveria agregar cada tentativa (%q): %s", want, msg)
		}
	}
	// The client timeout reads "context deadline exceeded" or "net/http: request
	// canceled (Client.Timeout exceeded …)", depending on where it fires.
	if !strings.Contains(msg, "deadline exceeded") && !strings.Contains(msg, "Client.Timeout") {
		t.Fatalf("a tentativa do 2º provedor deveria aparecer como tempo esgotado: %s", msg)
	}
	if strings.Contains(msg, key) || strings.Contains(msg, "OUTRA-CHAVE") {
		t.Fatalf("o erro carrega uma chave: %s", msg)
	}
	if strings.ContainsAny(msg, "\n\r\x1b\x00") || !utf8.ValidString(msg) {
		t.Fatalf("o trecho do provedor deveria vir saneado: %q", msg)
	}
	if strings.Contains(msg, strings.Repeat("x", 161)) {
		t.Fatalf("o trecho do provedor deveria ser curto: %s", msg)
	}
}

// --- end to end: registry → resolver → planner (real HTTP client) -----------

// countingServer answers a valid draft and records the hits and the Authorization.
type countingServer struct {
	srv  *httptest.Server
	hits int32
	auth atomic.Value
}

func newCountingServer(t *testing.T) *countingServer {
	t.Helper()
	c := &countingServer{}
	c.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&c.hits, 1)
		c.auth.Store(r.Header.Get("Authorization"))
		_, _ = w.Write(chatBody(okContent))
	}))
	t.Cleanup(c.srv.Close)
	return c
}

func (c *countingServer) count() int32 { return atomic.LoadInt32(&c.hits) }

// M4, image rollback: the image before this PR does not know data_policy_ack*, so
// its first write drops those fields; back on the new image, the preset is ENABLED
// without the acknowledgment. The planner skips it — no network at all.
func TestPlan_RolledBackStoreWithoutTheAckIsSkipped(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ai-providers.json")
	kek := make([]byte, 32)
	reg, err := aiproviders.NewRegistry(path, kek, aiproviders.WithFreeModelsOnly(true))
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	if _, err := reg.EnsurePresets(); err != nil {
		t.Fatalf("EnsurePresets: %v", err)
	}
	if _, err := reg.Upsert(aiproviders.UpsertInput{
		ID: aiproviders.PresetOpenRouterFree, Name: "OpenRouter — modelos gratuitos", Kind: aiproviders.KindOpenRouter,
		Model: "openrouter/free", Enabled: true, DataPolicyAck: true, APIKey: "sk-or-v1-CHAVE-0001",
	}, "op"); err != nil {
		t.Fatalf("preparar: %v", err)
	}
	stripAckFields(t, path)
	reg2, err := aiproviders.NewRegistry(path, kek, aiproviders.WithFreeModelsOnly(true))
	if err != nil {
		t.Fatalf("recarregar: %v", err)
	}
	if p, _ := reg2.Get(aiproviders.PresetOpenRouterFree); !p.Enabled || !p.HasKey || p.DataPolicyAck {
		t.Fatalf("cenário: o preset deveria voltar habilitado, com chave e sem ciência: %+v", p)
	}

	cs := newCountingServer(t)
	llm := routedLLM(hostRouter{hostOf(officialOR): cs.srv, hostOf(officialUno): cs.srv})
	_, err = New(llm, NewRegistryResolver(reg2, ""), freeCfg()).Plan(context.Background(), sampleReq())
	if !errors.Is(err, ErrNonFreeModel) || !strings.Contains(err.Error(), "data_policy_ack") {
		t.Fatalf("registro sem ciência deveria ser pulado (recusa citando a ciência), veio %v", err)
	}
	if n := cs.count(); n != 0 {
		t.Fatalf("o planner chamou a rede com um provedor sem ciência: %d chamada(s)", n)
	}
}

// stripAckFields rewrites the store the way the image before this PR does: it
// does not know data_policy_ack*, so those fields are gone after its first write.
func stripAckFields(t *testing.T, path string) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ler o store: %v", err)
	}
	var list []map[string]any
	if err := json.Unmarshal(b, &list); err != nil {
		t.Fatalf("store inválido: %v", err)
	}
	for _, p := range list {
		delete(p, "data_policy_ack")
		delete(p, "data_policy_ack_by")
		delete(p, "data_policy_ack_at")
	}
	out, _ := json.Marshal(list)
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatalf("gravar o store: %v", err)
	}
}

// I3 end to end: switching the kind of the key-bearing preset without a new key is
// refused by the registry, and the planner keeps sending that key only to the
// router it was pasted for — never to the other one.
func TestPlan_KindSwitchNeverTakesTheKeyToTheOtherRouter(t *testing.T) {
	const orKey = "sk-or-v1-CHAVE-OPENROUTER-0001"
	reg, err := aiproviders.NewRegistry("", make([]byte, 32), aiproviders.WithFreeModelsOnly(true))
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	if _, err := reg.EnsurePresets(); err != nil {
		t.Fatalf("EnsurePresets: %v", err)
	}
	if _, err := reg.Upsert(aiproviders.UpsertInput{
		ID: aiproviders.PresetOpenRouterFree, Name: "OpenRouter — modelos gratuitos", Kind: aiproviders.KindOpenRouter,
		Model: "openrouter/free", Enabled: true, DataPolicyAck: true, APIKey: orKey,
	}, "op"); err != nil {
		t.Fatalf("colar a chave: %v", err)
	}
	if _, err := reg.Upsert(aiproviders.UpsertInput{
		ID: aiproviders.PresetOpenRouterFree, Name: "OpenRouter — modelos gratuitos", Kind: aiproviders.KindUnoRouter,
		Model: "deepseek-v4-flash:free", Enabled: true, DataPolicyAck: true,
	}, "intruso"); !errors.Is(err, aiproviders.ErrKeyRebind) {
		t.Fatalf("trocar o tipo sem chave nova deveria ser recusado, veio %v", err)
	}

	or, uno := newCountingServer(t), newCountingServer(t)
	llm := routedLLM(hostRouter{hostOf(officialOR): or.srv, hostOf(officialUno): uno.srv})
	plan, err := New(llm, NewRegistryResolver(reg, ""), freeCfg()).Plan(context.Background(), sampleReq())
	if err != nil || plan.Provider != "OpenRouter — modelos gratuitos" {
		t.Fatalf("o preset intacto deveria atender: plan=%+v err=%v", plan, err)
	}
	if uno.count() != 0 {
		t.Fatalf("a chave do OpenRouter foi ao UnoRouter: %d chamada(s)", uno.count())
	}
	if or.count() != 1 || or.auth.Load() != "Bearer "+orKey {
		t.Fatalf("a chave deveria ir só ao OpenRouter: hits=%d auth=%v", or.count(), or.auth.Load())
	}
}
