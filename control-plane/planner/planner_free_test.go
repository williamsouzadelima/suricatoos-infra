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
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/williamsouzadelima/suricatoos-infra/control-plane/aiproviders"
)

// scriptLLM answers per MODEL (the free providers sit on their routers' official
// endpoints, so the model is what tells them apart) and records the call order.
type scriptLLM struct {
	byModel map[string]scripted
	mu      sync.Mutex
	calls   []string
}

type scripted struct {
	resp ChatResponse
	err  error
	fn   func(ctx context.Context) (ChatResponse, error) // when set, answers instead of resp/err
}

func (s *scriptLLM) Chat(ctx context.Context, req ChatRequest) (ChatResponse, error) {
	s.mu.Lock()
	s.calls = append(s.calls, req.Model)
	r, ok := s.byModel[req.Model]
	s.mu.Unlock()
	if !ok {
		return ChatResponse{}, fmt.Errorf("modelo inesperado %q", req.Model)
	}
	if r.fn != nil {
		return r.fn(ctx)
	}
	return r.resp, r.err
}

// called is the comma-joined models in call order.
func (s *scriptLLM) called() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return strings.Join(s.calls, ",")
}

var (
	officialOR  = aiproviders.OfficialBaseURL(aiproviders.KindOpenRouter)
	officialUno = aiproviders.OfficialBaseURL(aiproviders.KindUnoRouter)

	// The free providers carry the operator's data-policy acknowledgment and the
	// paid one is UE + ZDR: each meets the governance bar the planner re-checks.
	freeA = Provider{ID: "openrouter-free", Name: "OpenRouter grátis", Kind: "openrouter", BaseURL: officialOR, APIKey: "ka", Model: "openrouter/free", DataPolicyAck: true}
	freeB = Provider{ID: "unorouter-free", Name: "UnoRouter grátis", Kind: "unorouter", BaseURL: officialUno, APIKey: "kb", Model: "deepseek-v4-flash:free", DataPolicyAck: true}
	paidP = Provider{ID: "pago", Name: "Pago", Kind: "openrouter", BaseURL: officialOR, APIKey: "kp", Model: "openai/gpt-5.5", EURegion: true, ZDR: true}
)

func okScript() scripted { return scripted{resp: ChatResponse{Content: okContent}} }

func freeCfg() Config { return Config{ConsentGranted: true, FreeModelsOnly: true} }

// timeoutErr is a net.Error that reports a timeout (what http.Client returns when
// its Timeout fires, wrapped in *url.Error).
type timeoutErr struct{}

func (timeoutErr) Error() string   { return "Client.Timeout exceeded while awaiting headers" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

func hostOf(raw string) string {
	u, _ := url.Parse(raw)
	return u.Host
}

// hostRouter delivers requests addressed to the given hosts to test servers
// (keeping the Host header). Any other host goes through unchanged and is really
// reached — so zero hits on a foreign test server means it was never contacted.
type hostRouter map[string]*httptest.Server

func (h hostRouter) RoundTrip(r *http.Request) (*http.Response, error) {
	srv, ok := h[r.URL.Host]
	if !ok {
		return http.DefaultTransport.RoundTrip(r)
	}
	u, err := url.Parse(srv.URL)
	if err != nil {
		return nil, err
	}
	r2 := r.Clone(r.Context())
	r2.URL.Scheme, r2.URL.Host = u.Scheme, u.Host
	r2.Host = r.URL.Host
	return http.DefaultTransport.RoundTrip(r2)
}

// routedLLM is the real HTTP client with the routes above.
func routedLLM(routes hostRouter) *HTTPLLM {
	return &HTTPLLM{hc: &http.Client{Timeout: 60 * time.Second, Transport: routes}}
}

// chatBody is an OpenAI-compatible completion whose message content is content.
func chatBody(content string) []byte {
	b, _ := json.Marshal(map[string]any{
		"choices": []any{map[string]any{"message": map[string]any{"content": content}}},
		"usage":   map[string]any{"prompt_tokens": 10, "completion_tokens": 5},
	})
	return b
}

func TestPlan_FreeOnlyRefusesPaidModelBeforeAnyNetwork(t *testing.T) {
	// The real HTTP client against a counting server: proves ZERO network calls.
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		_, _ = w.Write(chatBody(okContent))
	}))
	defer srv.Close()
	llm := routedLLM(hostRouter{hostOf(officialOR): srv})

	_, err := New(llm, fakeResolver{provs: []Provider{paidP}}, freeCfg()).Plan(context.Background(), sampleReq())
	if !errors.Is(err, ErrNonFreeModel) {
		t.Fatalf("modelo pago com a regra ligada deveria dar ErrNonFreeModel, veio %v", err)
	}
	if n := atomic.LoadInt32(&hits); n != 0 {
		t.Fatalf("NENHUMA chamada de rede pode ir a um modelo pago com a regra ligada: %d", n)
	}
}

// With the rule on, the planner only ever calls the routers' official endpoints: a
// provider whose stored base_url points elsewhere (e.g. stored before the rule), or
// a generic gateway, is refused before any network — even with a ":free" model.
func TestPlan_FreeOnlyNeverCallsAForeignEndpoint(t *testing.T) {
	var evilHits, legitHits int32
	var legitHost atomic.Value
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&evilHits, 1)
		_, _ = w.Write(chatBody(okContent))
	}))
	defer evil.Close()
	legit := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&legitHits, 1)
		legitHost.Store(r.Host)
		_, _ = w.Write(chatBody(okContent))
	}))
	defer legit.Close()
	llm := routedLLM(hostRouter{hostOf(officialOR): legit, hostOf(officialUno): legit})

	repointed := Provider{Name: "OpenRouter repontado", Kind: "openrouter", BaseURL: evil.URL, APIKey: "k1", Model: "openrouter/free"}
	gateway := Provider{Name: "Gateway antigo", Kind: "openai_compatible", BaseURL: evil.URL, APIKey: "k2", Model: "x:free"}

	_, err := New(llm, fakeResolver{provs: []Provider{repointed, gateway}}, freeCfg()).Plan(context.Background(), sampleReq())
	if !errors.Is(err, ErrNonFreeModel) {
		t.Fatalf("só endpoints fora do oficial: esperava a recusa da regra, veio %v", err)
	}
	if !strings.Contains(err.Error(), "não é o oficial") || !strings.Contains(err.Error(), "openai_compatible") {
		t.Fatalf("a recusa deveria dizer o motivo de cada provedor: %v", err)
	}

	plan, err := New(llm, fakeResolver{provs: []Provider{repointed, gateway, freeB}}, freeCfg()).Plan(context.Background(), sampleReq())
	if err != nil || plan.Provider != freeB.Name {
		t.Fatalf("o provedor no endpoint oficial deveria atender: plan=%+v err=%v", plan, err)
	}
	if n := atomic.LoadInt32(&evilHits); n != 0 {
		t.Fatalf("o planner contatou um endpoint fora do oficial (%d chamada(s)) — a chave iria junto", n)
	}
	if atomic.LoadInt32(&legitHits) != 1 || legitHost.Load() != hostOf(officialUno) {
		t.Fatalf("esperava 1 chamada ao endpoint oficial do UnoRouter: hits=%d host=%v", legitHits, legitHost.Load())
	}
}

func TestPlan_FreeOnlySkipsPaidAndUsesFree(t *testing.T) {
	llm := &scriptLLM{byModel: map[string]scripted{freeB.Model: okScript()}}
	plan, err := New(llm, fakeResolver{provs: []Provider{paidP, freeB}}, freeCfg()).Plan(context.Background(), sampleReq())
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if llm.called() != freeB.Model {
		t.Fatalf("só o gratuito deveria ser chamado, chamadas = %s", llm.called())
	}
	if plan.Provider != freeB.Name || plan.Model != freeB.Model {
		t.Fatalf("o plano deveria registrar o provedor que redigiu: %s/%s", plan.Provider, plan.Model)
	}
}

func TestPlan_FreeRuleOffAllowsPaid(t *testing.T) {
	llm := &scriptLLM{byModel: map[string]scripted{paidP.Model: okScript()}}
	cfg := Config{ConsentGranted: true} // FreeModelsOnly off: old behavior
	if _, err := New(llm, fakeResolver{provs: []Provider{paidP}}, cfg).Plan(context.Background(), sampleReq()); err != nil {
		t.Fatalf("regra desligada: modelo pago deveria ser chamado: %v", err)
	}
	if llm.called() != paidP.Model {
		t.Fatalf("chamadas = %s", llm.called())
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
		{"timeout", &url.Error{Op: "Post", URL: officialOR + "/chat/completions", Err: timeoutErr{}}},
		{"rede", &url.Error{Op: "Post", URL: officialOR + "/chat/completions", Err: &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connection refused")}}},
	} {
		t.Run(c.name, func(t *testing.T) {
			llm := &scriptLLM{byModel: map[string]scripted{
				freeA.Model: {err: c.err},
				freeB.Model: okScript(),
			}}
			plan, err := New(llm, fakeResolver{provs: []Provider{freeA, freeB}}, freeCfg()).Plan(context.Background(), sampleReq())
			if err != nil {
				t.Fatalf("deveria cair p/ o próximo provedor: %v", err)
			}
			if llm.called() != freeA.Model+","+freeB.Model {
				t.Fatalf("ordem de chamadas = %s", llm.called())
			}
			if plan.Provider != freeB.Name {
				t.Fatalf("o plano deveria vir do 2º provedor: %s", plan.Provider)
			}
		})
	}
}

// M7: ANY non-2xx answer (after the provider's own response-format fallback) moves
// on to the next provider — a 4xx from one router (a model removed from its
// catalog, OpenRouter's "no endpoints found matching your data policy") says
// nothing about the other.
func TestPlan_AnyNon2xxFallsBackToTheNextProvider(t *testing.T) {
	for _, code := range []int{400, 401, 402, 403, 404, 409, 422, 429, 500, 502, 503} {
		llm := &scriptLLM{byModel: map[string]scripted{
			freeA.Model: {err: &StatusError{Code: code, Snippet: "recusado"}},
			freeB.Model: okScript(),
		}}
		plan, err := New(llm, fakeResolver{provs: []Provider{freeA, freeB}}, freeCfg()).Plan(context.Background(), sampleReq())
		if err != nil || plan.Provider != freeB.Name {
			t.Fatalf("%d: deveria cair p/ o próximo provedor: plan=%+v err=%v", code, plan, err)
		}
		if llm.called() != freeA.Model+","+freeB.Model {
			t.Fatalf("%d: ordem de chamadas = %s", code, llm.called())
		}
	}
}

func TestPlan_UnclassifiedErrorStops(t *testing.T) {
	// An error that is neither a non-2xx answer nor a timeout/network failure (a 2xx
	// without usable content) stops: there is no status to judge by.
	llm := &scriptLLM{byModel: map[string]scripted{
		freeA.Model: {err: errors.New("provedor não retornou conteúdo")},
		freeB.Model: okScript(),
	}}
	if _, err := New(llm, fakeResolver{provs: []Provider{freeA, freeB}}, freeCfg()).Plan(context.Background(), sampleReq()); err == nil || llm.called() != freeA.Model {
		t.Fatalf("erro não classificado deveria parar: err=%v chamadas=%s", err, llm.called())
	}
}

func TestPlan_AllProvidersFailReportsEach(t *testing.T) {
	llm := &scriptLLM{byModel: map[string]scripted{
		freeA.Model: {err: &StatusError{Code: http.StatusTooManyRequests}},
		freeB.Model: {err: &StatusError{Code: http.StatusBadGateway}},
	}}
	_, err := New(llm, fakeResolver{provs: []Provider{freeA, freeB}}, freeCfg()).Plan(context.Background(), sampleReq())
	if err == nil || llm.called() != freeA.Model+","+freeB.Model {
		t.Fatalf("todos falhando: err=%v chamadas=%s", err, llm.called())
	}
	if errors.Is(err, ErrBudget) || errors.Is(err, ErrNonFreeModel) || errors.Is(err, ErrConsentOff) || errors.Is(err, ErrTimeout) {
		t.Fatalf("falha de provedor não é recusa de governança nem tempo esgotado: %v", err)
	}
	for _, name := range []string{freeA.Name, freeB.Name} {
		if !strings.Contains(err.Error(), name) {
			t.Fatalf("o erro deveria citar %q: %v", name, err)
		}
	}
}

func TestPlan_CancelledContextStopsFallback(t *testing.T) {
	// The operator's request goes away DURING the first attempt.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	llm := &scriptLLM{byModel: map[string]scripted{
		freeA.Model: {fn: func(context.Context) (ChatResponse, error) {
			cancel()
			return ChatResponse{}, &url.Error{Op: "Post", URL: officialOR + "/chat/completions", Err: context.Canceled}
		}},
		freeB.Model: okScript(),
	}}
	_, err := New(llm, fakeResolver{provs: []Provider{freeA, freeB}}, freeCfg()).Plan(ctx, sampleReq())
	if err == nil || errors.Is(err, ErrTimeout) {
		t.Fatalf("cancelamento deveria dar erro (e não tempo esgotado): %v", err)
	}
	if llm.called() != freeA.Model {
		t.Fatalf("com o pedido cancelado não se tenta o próximo provedor: %s", llm.called())
	}

	// Already cancelled before Plan: no attempt at all, and the error says so.
	gone, stop := context.WithCancel(context.Background())
	stop()
	llm2 := &scriptLLM{byModel: map[string]scripted{freeA.Model: okScript()}}
	_, err = New(llm2, fakeResolver{provs: []Provider{freeA}}, freeCfg()).Plan(gone, sampleReq())
	if err == nil || !errors.Is(err, context.Canceled) || llm2.called() != "" {
		t.Fatalf("pedido já cancelado: nenhuma tentativa e erro de cancelamento; err=%v chamadas=%q", err, llm2.called())
	}
}

// switchResolver lets a test change the candidates between Plan calls (the budget
// lives in the Planner, so it carries over).
type switchResolver struct{ provs []Provider }

func (s *switchResolver) Resolve(context.Context) ([]Provider, error) { return s.provs, nil }

func TestPlan_FreeModelCostsZero(t *testing.T) {
	huge := Usage{PromptTokens: 1_000_000, CompletionTokens: 1_000_000}
	llm := &scriptLLM{byModel: map[string]scripted{
		freeA.Model: {resp: ChatResponse{Content: okContent, Usage: huge}},
		paidP.Model: okScript(),
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
	if n := strings.Count(llm.called(), ",") + 1; n != 4 {
		t.Fatalf("chamadas = %s", llm.called())
	}
}

func TestPlan_SpentBudgetStillServesFree(t *testing.T) {
	huge := Usage{PromptTokens: 1_000_000, CompletionTokens: 1_000_000}
	llm := &scriptLLM{byModel: map[string]scripted{
		paidP.Model: {resp: ChatResponse{Content: okContent, Usage: huge}},
		freeA.Model: okScript(),
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
	if llm.called() != paidP.Model+","+freeA.Model {
		t.Fatalf("o pago não pode ser chamado após estourar o teto: %s", llm.called())
	}
}

// With the rule OFF, custom endpoints keep working (today's behavior), and the
// provider fallback runs over real HTTP: network error → 503 → healthy.
func TestPlan_RuleOffProviderFallbackOverHTTP(t *testing.T) {
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

	// Custom endpoints are the legacy UE + ZDR gateways (":free" means nothing off
	// the routers' official endpoints).
	provs := []Provider{
		{Name: "Fora do ar", Kind: "openrouter", BaseURL: goneURL, APIKey: "k1", Model: "openrouter/free", EURegion: true, ZDR: true},
		{Name: "503", Kind: "unorouter", BaseURL: down.URL, APIKey: "k2", Model: "x:free", EURegion: true, ZDR: true},
		{Name: "Saudável", Kind: "openai_compatible", BaseURL: up.URL, APIKey: "k3", Model: "y:free", EURegion: true, ZDR: true},
	}
	plan, err := New(NewHTTPLLM(), fakeResolver{provs: provs}, Config{ConsentGranted: true}).Plan(context.Background(), sampleReq())
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
	res := fakeResolver{provs: []Provider{freeA}} // official endpoint, free model: the rule lets it through

	// Free text / foreign JSON through the fallback is still REJECTED by parseDraft.
	bad := srv(`{"resposta":"texto livre, sem o schema"}`)
	defer bad.Close()
	_, err := New(routedLLM(hostRouter{hostOf(officialOR): bad}), res, freeCfg()).Plan(context.Background(), sampleReq())
	if err == nil || errors.Is(err, ErrNonFreeModel) {
		t.Fatalf("saída fora do schema não pode virar plano, nem no fallback de formato: %v", err)
	}
	// A valid draft through the same fallback is accepted.
	good := srv(okContent)
	defer good.Close()
	plan, err := New(routedLLM(hostRouter{hostOf(officialOR): good}), res, freeCfg()).Plan(context.Background(), sampleReq())
	if err != nil || len(plan.Steps) == 0 {
		t.Fatalf("rascunho válido via fallback deveria passar: plan=%+v err=%v", plan, err)
	}
}
