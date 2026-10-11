package planner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
)

// scriptLLM answers per provider BaseURL and records the order of the calls.
type scriptLLM struct {
	byBase map[string]scripted
	calls  []string
}

type scripted struct {
	resp ChatResponse
	err  error
}

func (s *scriptLLM) Chat(_ context.Context, req ChatRequest) (ChatResponse, error) {
	s.calls = append(s.calls, req.BaseURL)
	r, ok := s.byBase[req.BaseURL]
	if !ok {
		return ChatResponse{}, fmt.Errorf("base inesperada %q", req.BaseURL)
	}
	return r.resp, r.err
}

var (
	freeA = Provider{ID: "openrouter-free", Name: "OpenRouter grátis", Kind: "openrouter", BaseURL: "https://a/v1", APIKey: "ka", Model: "openrouter/free"}
	freeB = Provider{ID: "unorouter-free", Name: "UnoRouter grátis", Kind: "unorouter", BaseURL: "https://b/v1", APIKey: "kb", Model: "deepseek-v4-flash:free"}
	paidP = Provider{ID: "pago", Name: "Pago", Kind: "openrouter", BaseURL: "https://p/v1", APIKey: "kp", Model: "openai/gpt-5.5"}
)

func okScript() scripted { return scripted{resp: ChatResponse{Content: okContent}} }

func freeCfg() Config { return Config{ConsentGranted: true, FreeModelsOnly: true} }

// timeoutErr is a net.Error that reports a timeout (what http.Client returns when
// its Timeout fires, wrapped in *url.Error).
type timeoutErr struct{}

func (timeoutErr) Error() string   { return "Client.Timeout exceeded while awaiting headers" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

func TestPlan_FreeOnlyRefusesPaidModelBeforeAnyNetwork(t *testing.T) {
	// The real HTTP client against a counting server: proves ZERO network calls.
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		_, _ = w.Write(chatBody(okContent))
	}))
	defer srv.Close()
	paid := paidP
	paid.BaseURL = srv.URL

	_, err := New(NewHTTPLLM(), fakeResolver{provs: []Provider{paid}}, freeCfg()).Plan(context.Background(), sampleReq())
	if !errors.Is(err, ErrNonFreeModel) {
		t.Fatalf("modelo pago com a regra ligada deveria dar ErrNonFreeModel, veio %v", err)
	}
	if n := atomic.LoadInt32(&hits); n != 0 {
		t.Fatalf("NENHUMA chamada de rede pode ir a um modelo pago com a regra ligada: %d", n)
	}
}

func TestPlan_FreeOnlySkipsPaidAndUsesFree(t *testing.T) {
	llm := &scriptLLM{byBase: map[string]scripted{freeB.BaseURL: okScript()}}
	plan, err := New(llm, fakeResolver{provs: []Provider{paidP, freeB}}, freeCfg()).Plan(context.Background(), sampleReq())
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if strings.Join(llm.calls, ",") != freeB.BaseURL {
		t.Fatalf("só o gratuito deveria ser chamado, chamadas = %v", llm.calls)
	}
	if plan.Provider != freeB.Name || plan.Model != freeB.Model {
		t.Fatalf("o plano deveria registrar o provedor que redigiu: %s/%s", plan.Provider, plan.Model)
	}
}

func TestPlan_FreeRuleOffAllowsPaid(t *testing.T) {
	llm := &scriptLLM{byBase: map[string]scripted{paidP.BaseURL: okScript()}}
	cfg := Config{ConsentGranted: true} // FreeModelsOnly off: old behavior
	if _, err := New(llm, fakeResolver{provs: []Provider{paidP}}, cfg).Plan(context.Background(), sampleReq()); err != nil {
		t.Fatalf("regra desligada: modelo pago deveria ser chamado: %v", err)
	}
	if len(llm.calls) != 1 {
		t.Fatalf("chamadas = %v", llm.calls)
	}
}

func TestPlan_FallsBackOnRetryableErrors(t *testing.T) {
	for _, c := range []struct {
		name string
		err  error
	}{
		{"429", &StatusError{Code: http.StatusTooManyRequests}},
		{"500", &StatusError{Code: http.StatusInternalServerError}},
		{"503", &StatusError{Code: http.StatusServiceUnavailable}},
		{"timeout", &url.Error{Op: "Post", URL: "https://a/v1/chat/completions", Err: timeoutErr{}}},
		{"rede", &url.Error{Op: "Post", URL: "https://a/v1/chat/completions", Err: &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connection refused")}}},
	} {
		t.Run(c.name, func(t *testing.T) {
			llm := &scriptLLM{byBase: map[string]scripted{
				freeA.BaseURL: {err: c.err},
				freeB.BaseURL: okScript(),
			}}
			plan, err := New(llm, fakeResolver{provs: []Provider{freeA, freeB}}, freeCfg()).Plan(context.Background(), sampleReq())
			if err != nil {
				t.Fatalf("deveria cair p/ o próximo provedor: %v", err)
			}
			if strings.Join(llm.calls, ",") != freeA.BaseURL+","+freeB.BaseURL {
				t.Fatalf("ordem de chamadas = %v", llm.calls)
			}
			if plan.Provider != freeB.Name {
				t.Fatalf("o plano deveria vir do 2º provedor: %s", plan.Provider)
			}
		})
	}
}

func TestPlan_NoFallbackOnRequestErrors(t *testing.T) {
	for _, code := range []int{400, 401, 403, 404, 422} {
		llm := &scriptLLM{byBase: map[string]scripted{
			freeA.BaseURL: {err: &StatusError{Code: code}},
			freeB.BaseURL: okScript(),
		}}
		_, err := New(llm, fakeResolver{provs: []Provider{freeA, freeB}}, freeCfg()).Plan(context.Background(), sampleReq())
		if err == nil {
			t.Fatalf("%d: erro do pedido deveria parar (sem fallback)", code)
		}
		if len(llm.calls) != 1 {
			t.Fatalf("%d: não deveria tentar o próximo, chamadas = %v", code, llm.calls)
		}
	}
	// An unclassified error (not 429/5xx/timeout/network) also stops.
	llm := &scriptLLM{byBase: map[string]scripted{
		freeA.BaseURL: {err: errors.New("provedor não retornou conteúdo")},
		freeB.BaseURL: okScript(),
	}}
	if _, err := New(llm, fakeResolver{provs: []Provider{freeA, freeB}}, freeCfg()).Plan(context.Background(), sampleReq()); err == nil || len(llm.calls) != 1 {
		t.Fatalf("erro não classificado deveria parar: err=%v chamadas=%v", err, llm.calls)
	}
}

func TestPlan_AllProvidersFailReportsEach(t *testing.T) {
	llm := &scriptLLM{byBase: map[string]scripted{
		freeA.BaseURL: {err: &StatusError{Code: http.StatusTooManyRequests}},
		freeB.BaseURL: {err: &StatusError{Code: http.StatusBadGateway}},
	}}
	_, err := New(llm, fakeResolver{provs: []Provider{freeA, freeB}}, freeCfg()).Plan(context.Background(), sampleReq())
	if err == nil || len(llm.calls) != 2 {
		t.Fatalf("todos falhando: err=%v chamadas=%v", err, llm.calls)
	}
	if errors.Is(err, ErrBudget) || errors.Is(err, ErrNonFreeModel) || errors.Is(err, ErrConsentOff) {
		t.Fatalf("falha de provedor não é recusa de governança: %v", err)
	}
	for _, name := range []string{freeA.Name, freeB.Name} {
		if !strings.Contains(err.Error(), name) {
			t.Fatalf("o erro deveria citar %q: %v", name, err)
		}
	}
}

func TestPlan_CancelledContextStopsFallback(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // the operator's request went away
	llm := &scriptLLM{byBase: map[string]scripted{
		freeA.BaseURL: {err: &url.Error{Op: "Post", URL: "https://a/v1/chat/completions", Err: context.Canceled}},
		freeB.BaseURL: okScript(),
	}}
	if _, err := New(llm, fakeResolver{provs: []Provider{freeA, freeB}}, freeCfg()).Plan(ctx, sampleReq()); err == nil {
		t.Fatal("contexto cancelado deveria dar erro")
	}
	if len(llm.calls) != 1 {
		t.Fatalf("com o pedido cancelado não se tenta o próximo provedor: %v", llm.calls)
	}
}

// switchResolver lets a test change the candidates between Plan calls (the budget
// lives in the Planner, so it carries over).
type switchResolver struct{ provs []Provider }

func (s *switchResolver) Resolve(context.Context) ([]Provider, error) { return s.provs, nil }

func TestPlan_FreeModelCostsZero(t *testing.T) {
	huge := Usage{PromptTokens: 1_000_000, CompletionTokens: 1_000_000}
	llm := &scriptLLM{byBase: map[string]scripted{
		freeA.BaseURL: {resp: ChatResponse{Content: okContent, Usage: huge}},
		paidP.BaseURL: okScript(),
	}}
	// Tiny ceiling: a single PAID call of this size would exhaust it.
	res := &switchResolver{provs: []Provider{freeA}}
	p := New(llm, res, Config{ConsentGranted: true, MonthlyBudgetUSD: 0.001, USDPer1kTokens: 0.005})
	for i := 0; i < 3; i++ {
		if _, err := p.Plan(context.Background(), sampleReq()); err != nil {
			t.Fatalf("chamada %d a modelo gratuito: %v", i+1, err)
		}
	}
	// The three huge FREE calls consumed nothing: a paid call still fits the ceiling.
	res.provs = []Provider{paidP}
	plan, err := p.Plan(context.Background(), sampleReq())
	if err != nil || plan.Provider != paidP.Name {
		t.Fatalf("chamadas gratuitas não podem consumir o orçamento: plan=%+v err=%v", plan, err)
	}
	if len(llm.calls) != 4 {
		t.Fatalf("chamadas = %v", llm.calls)
	}
}

func TestPlan_SpentBudgetStillServesFree(t *testing.T) {
	huge := Usage{PromptTokens: 1_000_000, CompletionTokens: 1_000_000}
	llm := &scriptLLM{byBase: map[string]scripted{
		paidP.BaseURL: {resp: ChatResponse{Content: okContent, Usage: huge}},
		freeA.BaseURL: okScript(),
	}}
	p := New(llm, fakeResolver{provs: []Provider{paidP, freeA}}, Config{ConsentGranted: true, MonthlyBudgetUSD: 0.001, USDPer1kTokens: 0.005})
	plan, err := p.Plan(context.Background(), sampleReq()) // paid call: exhausts the ceiling
	if err != nil || plan.Provider != paidP.Name {
		t.Fatalf("1ª chamada deveria ir ao pago: plan=%+v err=%v", plan, err)
	}
	plan, err = p.Plan(context.Background(), sampleReq()) // paid refused by budget → free
	if err != nil || plan.Provider != freeA.Name {
		t.Fatalf("com o orçamento estourado o gratuito ainda serve: plan=%+v err=%v", plan, err)
	}
	if strings.Join(llm.calls, ",") != paidP.BaseURL+","+freeA.BaseURL {
		t.Fatalf("o pago não pode ser chamado após estourar o teto: %v", llm.calls)
	}
}

// chatBody is an OpenAI-compatible completion whose message content is content.
func chatBody(content string) []byte {
	b, _ := json.Marshal(map[string]any{
		"choices": []any{map[string]any{"message": map[string]any{"content": content}}},
		"usage":   map[string]any{"prompt_tokens": 10, "completion_tokens": 5},
	})
	return b
}

func TestPlan_ProviderFallbackOverHTTP(t *testing.T) {
	var hitsDown, hitsUp int32
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hitsDown, 1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer down.Close()
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hitsUp, 1)
		_, _ = w.Write(chatBody(okContent))
	}))
	defer up.Close()
	gone := httptest.NewServer(http.NotFoundHandler())
	goneURL := gone.URL
	gone.Close() // connection refused

	provs := []Provider{
		{Name: "Fora do ar", Kind: "openrouter", BaseURL: goneURL, APIKey: "k1", Model: "openrouter/free"},
		{Name: "503", Kind: "unorouter", BaseURL: down.URL, APIKey: "k2", Model: "x:free"},
		{Name: "Saudável", Kind: "unorouter", BaseURL: up.URL, APIKey: "k3", Model: "y:free"},
	}
	plan, err := New(NewHTTPLLM(), fakeResolver{provs: provs}, freeCfg()).Plan(context.Background(), sampleReq())
	if err != nil {
		t.Fatalf("deveria chegar ao provedor saudável: %v", err)
	}
	if plan.Provider != "Saudável" {
		t.Fatalf("provedor = %q", plan.Provider)
	}
	if atomic.LoadInt32(&hitsDown) != 1 || atomic.LoadInt32(&hitsUp) != 1 {
		t.Fatalf("chamadas: 503=%d saudável=%d", hitsDown, hitsUp)
	}
}

func TestPlan_FormatFallbackStillRequiresValidDraft(t *testing.T) {
	// json_schema refused with a 400 that cites response_format → json_object attempt.
	srv := func(content string) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			if rfType(body) == "json_schema" {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":{"message":"response_format json_schema is not supported for this model"}}`))
				return
			}
			_, _ = w.Write(chatBody(content))
		}))
	}
	prov := func(base string) fakeResolver {
		return fakeResolver{provs: []Provider{{Name: "OR", Kind: "openrouter", BaseURL: base, APIKey: "k", Model: "openrouter/free"}}}
	}

	// Free text / foreign JSON through the fallback is still REJECTED by parseDraft.
	bad := srv(`{"resposta":"texto livre, sem o schema"}`)
	defer bad.Close()
	if _, err := New(NewHTTPLLM(), prov(bad.URL), freeCfg()).Plan(context.Background(), sampleReq()); err == nil {
		t.Fatal("saída fora do schema não pode virar plano, nem no fallback de formato")
	}
	// A valid draft through the same fallback is accepted.
	good := srv(okContent)
	defer good.Close()
	plan, err := New(NewHTTPLLM(), prov(good.URL), freeCfg()).Plan(context.Background(), sampleReq())
	if err != nil || len(plan.Steps) == 0 {
		t.Fatalf("rascunho válido via fallback deveria passar: plan=%+v err=%v", plan, err)
	}
}
