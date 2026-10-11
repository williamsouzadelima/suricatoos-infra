package aiproviders

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/williamsouzadelima/suricatoos-infra/control-plane/sessiongate"
)

// upstream is a fake provider catalog. It is TLS because a provider's base_url must
// be https. It counts hits and records the last Authorization header and path.
type upstream struct {
	srv  *httptest.Server
	mu   sync.Mutex
	hits int
	auth string
	path string
}

func newUpstream(t *testing.T, h http.HandlerFunc) *upstream {
	t.Helper()
	u := &upstream{}
	u.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u.mu.Lock()
		u.hits++
		u.auth = r.Header.Get("Authorization")
		u.path = r.URL.Path
		u.mu.Unlock()
		h(w, r)
	}))
	t.Cleanup(u.srv.Close)
	return u
}

func (u *upstream) count() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.hits
}

func (u *upstream) lastAuth() string {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.auth
}

func (u *upstream) lastPath() string {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.path
}

// catalogJSON mixes free and paid ids, with and without supported_parameters.
const catalogJSON = `{"object":"list","data":[
 {"id":"zeta/model:free","context_length":32768,"supported_parameters":["max_tokens","temperature"]},
 {"id":"openai/gpt-5.5","context_length":400000,"supported_parameters":["structured_outputs","response_format"]},
 {"id":"openrouter/free","context_length":200000,"supported_parameters":["structured_outputs","tools"]},
 {"id":"nvidia/nemotron-3-super-120b-a12b:free","context_length":262144,"supported_parameters":["structured_outputs"]},
 {"id":"openrouter/auto","context_length":2000000,"supported_parameters":["structured_outputs"]},
 {"id":"vendor/x:freeze","supported_parameters":["structured_outputs"]},
 {"id":"alpha/no-params:free"},
 {"id":":free"}
]}`

func serveCatalog(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = io.WriteString(w, catalogJSON)
}

// testClock is a settable clock shared with the handlers' goroutines.
type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *testClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// modelsHarness wires a Service whose outbound /models client trusts the fake
// upstream's TLS certificate, with a controllable clock (advance it to expire the
// cache).
func modelsHarness(t *testing.T, freeOnly bool, up *upstream) (*httptest.Server, *Registry, *Service, *testClock) {
	t.Helper()
	kek, _ := randBytes(kekSize)
	reg, err := NewRegistry("", kek, WithFreeModelsOnly(freeOnly))
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	svc := NewService(reg, "s3cret")
	if up != nil {
		svc.modelsHC = newModelsClient(up.srv.Client().Transport)
	}
	clock := &testClock{t: time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)}
	svc.now = clock.Now
	mux := http.NewServeMux()
	svc.Register(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, reg, svc, clock
}

// addProvider stores a DISABLED provider (enabling is not needed to list models:
// the operator lists them to pick one before enabling).
func addProvider(t *testing.T, reg *Registry, kind, base, model, key string) string {
	t.Helper()
	pub, err := reg.Upsert(UpsertInput{Name: "P " + kind, Kind: kind, BaseURL: base, Model: model, APIKey: key}, "op")
	if err != nil {
		t.Fatalf("setup upsert: %v", err)
	}
	return pub.ID
}

type modelsBody struct {
	Models []ModelInfo `json:"models"`
	Error  string      `json:"error"`
}

func decodeModels(t *testing.T, b []byte) modelsBody {
	t.Helper()
	var mb modelsBody
	if err := json.Unmarshal(b, &mb); err != nil {
		t.Fatalf("resposta não é JSON: %v: %s", err, b)
	}
	return mb
}

func TestModels_FiltersFreeAndSortsJSONSchemaFirst(t *testing.T) {
	up := newUpstream(t, serveCatalog)
	srv, reg, _, _ := modelsHarness(t, true, up)
	id := addProvider(t, reg, KindOpenRouter, up.srv.URL+"/api/v1", "openrouter/free", "")

	resp, b := do(t, srv, "GET", "/api/v1/ai/providers/"+id+"/models", "s3cret", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("models = %d: %s", resp.StatusCode, b)
	}
	got := decodeModels(t, b).Models
	want := []ModelInfo{
		{ID: "nvidia/nemotron-3-super-120b-a12b:free", ContextLength: 262144, JSONSchema: true, JSONSchemaKnown: true},
		{ID: "openrouter/free", ContextLength: 200000, JSONSchema: true, JSONSchemaKnown: true},
		{ID: "alpha/no-params:free", JSONSchema: false, JSONSchemaKnown: false},
		{ID: "zeta/model:free", ContextLength: 32768, JSONSchema: false, JSONSchemaKnown: true},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("models =\n %+v\nwant\n %+v", got, want)
	}
	if p := up.lastPath(); p != "/api/v1/models" {
		t.Fatalf("deveria buscar <base_url>/models, buscou %q", p)
	}
	// Wire shape: context_length is omitted when the provider does not inform it.
	if !bytes.Contains(b, []byte(`{"id":"alpha/no-params:free","json_schema":false,"json_schema_known":false}`)) {
		t.Fatalf("formato inesperado: %s", b)
	}
}

func TestModels_OpenRouterWithoutKeyOmitsAuthorization(t *testing.T) {
	up := newUpstream(t, serveCatalog)
	srv, reg, _, _ := modelsHarness(t, true, up)
	id := addProvider(t, reg, KindOpenRouter, up.srv.URL, "openrouter/free", "")
	if resp, b := do(t, srv, "GET", "/api/v1/ai/providers/"+id+"/models", "s3cret", ""); resp.StatusCode != http.StatusOK {
		t.Fatalf("openrouter sem chave = %d, want 200: %s", resp.StatusCode, b)
	}
	if a := up.lastAuth(); a != "" {
		t.Fatalf("sem chave guardada não deveria mandar Authorization, mandou %q", a)
	}
}

func TestModels_UnoRouterUsesStoredKeyAndExcludesTheOpenRouterRouter(t *testing.T) {
	up := newUpstream(t, serveCatalog)
	srv, reg, _, _ := modelsHarness(t, true, up)
	id := addProvider(t, reg, KindUnoRouter, up.srv.URL, "deepseek-v4-flash:free", testKey)

	resp, b := do(t, srv, "GET", "/api/v1/ai/providers/"+id+"/models", "s3cret", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unorouter com chave = %d: %s", resp.StatusCode, b)
	}
	if a := up.lastAuth(); a != "Bearer "+testKey {
		t.Fatalf("deveria mandar a chave guardada, mandou %q", a)
	}
	if bytes.Contains(b, []byte(testKey)) {
		t.Fatalf("a resposta vazou a chave: %s", b)
	}
	var ids []string
	for _, m := range decodeModels(t, b).Models {
		ids = append(ids, m.ID)
	}
	if got := strings.Join(ids, ","); got != "nvidia/nemotron-3-super-120b-a12b:free,alpha/no-params:free,zeta/model:free" {
		t.Fatalf("no unorouter openrouter/free não é gratuito; ids = %s", got)
	}
}

func TestModels_UnoRouterWithoutKeyIs409(t *testing.T) {
	up := newUpstream(t, serveCatalog)
	srv, reg, _, _ := modelsHarness(t, true, up)
	id := addProvider(t, reg, KindUnoRouter, up.srv.URL, "deepseek-v4-flash:free", "")

	resp, b := do(t, srv, "GET", "/api/v1/ai/providers/"+id+"/models", "s3cret", "")
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("unorouter sem chave = %d, want 409: %s", resp.StatusCode, b)
	}
	if e := decodeModels(t, b).Error; e != "cole a chave para listar os modelos" {
		t.Fatalf("mensagem = %q", e)
	}
	if n := up.count(); n != 0 {
		t.Fatalf("sem chave no UnoRouter não deveria ir à rede, foram %d chamada(s)", n)
	}
}

func TestModels_CachedPerProviderForTenMinutes(t *testing.T) {
	up := newUpstream(t, serveCatalog)
	srv, reg, _, clock := modelsHarness(t, true, up)
	id := addProvider(t, reg, KindOpenRouter, up.srv.URL, "openrouter/free", "")
	get := func() {
		t.Helper()
		if resp, b := do(t, srv, "GET", "/api/v1/ai/providers/"+id+"/models", "s3cret", ""); resp.StatusCode != http.StatusOK {
			t.Fatalf("models = %d: %s", resp.StatusCode, b)
		}
	}

	get()
	get()
	if n := up.count(); n != 1 {
		t.Fatalf("a 2ª consulta deveria vir do cache: %d chamada(s) ao provedor", n)
	}
	clock.Advance(9 * time.Minute)
	get()
	if n := up.count(); n != 1 {
		t.Fatalf("aos 9 min ainda vale o cache: %d chamada(s)", n)
	}
	clock.Advance(2 * time.Minute) // 11 min after the fetch
	get()
	if n := up.count(); n != 2 {
		t.Fatalf("após 10 min deveria buscar de novo: %d chamada(s)", n)
	}
	// Pasting a key (or changing the endpoint) invalidates the cached list at once.
	if _, err := reg.Upsert(UpsertInput{ID: id, Name: "P", Kind: KindOpenRouter, BaseURL: up.srv.URL, Model: "openrouter/free", APIKey: testKey}, "op"); err != nil {
		t.Fatalf("colar a chave: %v", err)
	}
	get()
	if n := up.count(); n != 3 {
		t.Fatalf("trocar a chave deveria invalidar o cache: %d chamada(s)", n)
	}
	if a := up.lastAuth(); a != "Bearer "+testKey {
		t.Fatalf("após colar a chave deveria mandá-la, mandou %q", a)
	}
}

func TestModels_ProviderErrorIs502WithoutLeakingKey(t *testing.T) {
	// A live catalog elsewhere: following the redirect WOULD succeed, so only a
	// client that refuses redirects answers 502 (and never reaches it).
	elsewhere := newUpstream(t, serveCatalog)
	echo := func(status int) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(status)
			_, _ = io.WriteString(w, `{"error":"chave recusada: `+r.Header.Get("Authorization")+`"}`)
		}
	}
	for _, c := range []struct {
		name string
		h    http.HandlerFunc
		want string // the short, key-free message the 502 must carry
	}{
		{"500 ecoando a chave", echo(http.StatusInternalServerError), "HTTP 500"},
		{"401 ecoando a chave", echo(http.StatusUnauthorized), "HTTP 401"},
		{"JSON inválido", func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, `não é json `+r.Header.Get("Authorization"))
		}, "resposta do provedor inválida"},
		{"redirect", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, elsewhere.srv.URL+"/models", http.StatusFound)
		}, "HTTP 302"},
		{"corpo acima do limite", func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, `{"data":[{"id":"`+strings.Repeat("a", 4096)+`:free"}]}`)
		}, "grande demais"},
	} {
		t.Run(c.name, func(t *testing.T) {
			up := newUpstream(t, c.h)
			srv, reg, svc, _ := modelsHarness(t, true, up)
			svc.modelsMax = 1024 // small limit so the oversize case needs no 8 MB body
			id := addProvider(t, reg, KindUnoRouter, up.srv.URL, "deepseek-v4-flash:free", testKey)

			resp, b := do(t, srv, "GET", "/api/v1/ai/providers/"+id+"/models", "s3cret", "")
			if resp.StatusCode != http.StatusBadGateway {
				t.Fatalf("erro do provedor = %d, want 502: %s", resp.StatusCode, b)
			}
			if bytes.Contains(b, []byte(testKey)) || bytes.Contains(b, []byte("TESTKEY")) {
				t.Fatalf("o 502 vazou a chave: %s", b)
			}
			e := decodeModels(t, b).Error
			if !strings.Contains(e, c.want) || len(e) > 160 {
				t.Fatalf("o 502 deveria trazer mensagem curta com %q, veio %q", c.want, e)
			}
			if up.count() != 1 {
				t.Fatalf("esperava 1 chamada ao provedor, houve %d", up.count())
			}
		})
	}
	if n := elsewhere.count(); n != 0 {
		t.Fatalf("o redirect não pode ser seguido (a chave iria junto): %d chamada(s) ao outro host", n)
	}
}

func TestModels_ErrorsAreNotCached(t *testing.T) {
	var fail = true
	var mu sync.Mutex
	up := newUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		f := fail
		mu.Unlock()
		if f {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		serveCatalog(w, r)
	})
	srv, reg, _, _ := modelsHarness(t, true, up)
	id := addProvider(t, reg, KindOpenRouter, up.srv.URL, "openrouter/free", "")
	if resp, _ := do(t, srv, "GET", "/api/v1/ai/providers/"+id+"/models", "s3cret", ""); resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("provedor fora = %d, want 502", resp.StatusCode)
	}
	mu.Lock()
	fail = false
	mu.Unlock()
	resp, b := do(t, srv, "GET", "/api/v1/ai/providers/"+id+"/models", "s3cret", "")
	if resp.StatusCode != http.StatusOK || len(decodeModels(t, b).Models) == 0 {
		t.Fatalf("após o provedor voltar = %d, want 200 com modelos (erro não pode ficar em cache): %s", resp.StatusCode, b)
	}
	if n := up.count(); n != 2 {
		t.Fatalf("a falha não pode ser servida do cache: %d chamada(s) ao provedor, want 2", n)
	}
}

func TestModels_NetworkErrorIs502(t *testing.T) {
	up := newUpstream(t, serveCatalog)
	srv, reg, _, _ := modelsHarness(t, true, up)
	id := addProvider(t, reg, KindOpenRouter, up.srv.URL, "openrouter/free", "")
	up.srv.Close() // the provider is gone: connection refused
	resp, b := do(t, srv, "GET", "/api/v1/ai/providers/"+id+"/models", "s3cret", "")
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("erro de rede = %d, want 502: %s", resp.StatusCode, b)
	}
}

func TestModels_UnknownProviderIs404(t *testing.T) {
	srv, _, _, _ := modelsHarness(t, true, nil)
	if resp, _ := do(t, srv, "GET", "/api/v1/ai/providers/nao-existe/models", "s3cret", ""); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("provedor inexistente = %d, want 404", resp.StatusCode)
	}
}

func TestModels_SessionRouteRequiresGateMarker(t *testing.T) {
	up := newUpstream(t, serveCatalog)
	srv, reg, _, _ := modelsHarness(t, true, up)
	id := addProvider(t, reg, KindOpenRouter, up.srv.URL, "openrouter/free", "")

	resp, b := doGate(t, srv, "GET", "/ai/providers/"+id+"/models", "", "")
	if resp.StatusCode != http.StatusForbidden || !bytes.Contains(b, []byte("rota de sessão sem portão")) {
		t.Fatalf("rota de sessão sem a marca = %d, want 403: %s", resp.StatusCode, b)
	}
	if n := up.count(); n != 0 {
		t.Fatalf("pedido sem a marca não pode ir ao provedor: %d chamada(s)", n)
	}
	resp, b = doSession(t, srv, "GET", "/ai/providers/"+id+"/models", "")
	if resp.StatusCode != http.StatusOK || len(decodeModels(t, b).Models) == 0 {
		t.Fatalf("rota de sessão com a marca = %d, want 200 com modelos: %s", resp.StatusCode, b)
	}
}

func TestModels_BearerRouteRequiresBearer(t *testing.T) {
	up := newUpstream(t, serveCatalog)
	srv, reg, _, _ := modelsHarness(t, true, up)
	id := addProvider(t, reg, KindOpenRouter, up.srv.URL, "openrouter/free", "")
	for _, bearer := range []string{"", "errado"} {
		if resp, _ := do(t, srv, "GET", "/api/v1/ai/providers/"+id+"/models", bearer, ""); resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("bearer %q = %d, want 401", bearer, resp.StatusCode)
		}
	}
	if n := up.count(); n != 0 {
		t.Fatalf("pedido sem bearer válido não pode ir ao provedor: %d chamada(s)", n)
	}
}

func TestPolicy_SessionAndBearer(t *testing.T) {
	const wantOn = `{"free_models_only":true,"free_rule":"sufixo :free ou openrouter/free","presets":["openrouter-free","unorouter-free"]}`
	srv, _, _, _ := modelsHarness(t, true, nil)

	resp, b := doSession(t, srv, "GET", "/ai/policy", "")
	if resp.StatusCode != http.StatusOK || strings.TrimSpace(string(b)) != wantOn {
		t.Fatalf("GET /ai/policy = %d %s, want 200 %s", resp.StatusCode, b, wantOn)
	}
	if resp, b := doGate(t, srv, "GET", "/ai/policy", "", ""); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("GET /ai/policy sem a marca = %d, want 403: %s", resp.StatusCode, b)
	}
	for _, bearer := range []string{"", "errado"} {
		if resp, _ := do(t, srv, "GET", "/api/v1/ai/policy", bearer, ""); resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("GET /api/v1/ai/policy bearer %q = %d, want 401", bearer, resp.StatusCode)
		}
	}
	resp, b = do(t, srv, "GET", "/api/v1/ai/policy", "s3cret", "")
	if resp.StatusCode != http.StatusOK || strings.TrimSpace(string(b)) != wantOn {
		t.Fatalf("GET /api/v1/ai/policy = %d %s", resp.StatusCode, b)
	}

	off, _, _, _ := modelsHarness(t, false, nil)
	_, b = doSession(t, off, "GET", "/ai/policy", "")
	if !bytes.Contains(b, []byte(`"free_models_only":false`)) {
		t.Fatalf("regra desligada deveria refletir free_models_only=false: %s", b)
	}
}

// doOperator sends a session request as nginx delivers it, with the operator
// identity nginx sets after the gsad check.
func doOperator(t *testing.T, srv *httptest.Server, method, path, operator, body string) (*http.Response, []byte) {
	t.Helper()
	req, err := http.NewRequest(method, srv.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	req.Header.Set(sessiongate.Header, sessiongate.Value)
	req.Header.Set("X-Operator", operator)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, b
}

func TestService_FreeOnlyUpsertIs422WithClearMessage(t *testing.T) {
	srv, reg, _, _ := modelsHarness(t, true, nil)
	for _, c := range []struct{ name, body, want string }{
		{"openai_compatible",
			`{"name":"GW","kind":"openai_compatible","base_url":"https://gw.example/v1","model":"x:free","eu_region":true,"zdr":true,"enabled":true}`,
			"openai_compatible"},
		{"modelo pago",
			`{"name":"OR","kind":"openrouter","model":"openai/gpt-5.5","eu_region":true,"zdr":true,"enabled":false}`,
			"openai/gpt-5.5"},
		{"gratuito habilitado sem ciência",
			`{"name":"OR","kind":"openrouter","model":"openrouter/free","enabled":true,"api_key":"sk-or-v1-TESTKEY-abcd1234"}`,
			"data_policy_ack"},
	} {
		for _, route := range []string{"bearer", "sessão"} {
			var resp *http.Response
			var b []byte
			if route == "bearer" {
				resp, b = do(t, srv, "POST", "/api/v1/ai/providers", "s3cret", c.body)
			} else {
				resp, b = doSession(t, srv, "POST", "/ai/providers", c.body)
			}
			if resp.StatusCode != http.StatusUnprocessableEntity {
				t.Fatalf("%s (%s) = %d, want 422: %s", c.name, route, resp.StatusCode, b)
			}
			var e struct {
				Error string `json:"error"`
			}
			_ = json.Unmarshal(b, &e)
			if !strings.Contains(e.Error, c.want) {
				t.Fatalf("%s (%s): mensagem %q deveria citar %q", c.name, route, e.Error, c.want)
			}
		}
	}
	if n := len(reg.List()); n != 0 {
		t.Fatalf("nenhum pedido recusado deveria gravar: %d provedor(es)", n)
	}

	// With the acknowledgment the free provider is accepted and the server records
	// WHO acknowledged (from the operator nginx set) — never from the body.
	body := `{"name":"OR","kind":"openrouter","model":"openrouter/free","enabled":true,"data_policy_ack":true,"data_policy_ack_by":"forjado","api_key":"sk-or-v1-TESTKEY-abcd1234"}`
	resp, b := doOperator(t, srv, "POST", "/ai/providers", "alice", body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("gratuito com ciência = %d, want 200: %s", resp.StatusCode, b)
	}
	var got struct {
		Provider PublicProvider `json:"provider"`
	}
	_ = json.Unmarshal(b, &got)
	if !got.Provider.Enabled || !got.Provider.DataPolicyAck || got.Provider.DataPolicyAckBy != "alice" || got.Provider.DataPolicyAckAt.IsZero() {
		t.Fatalf("a ciência deveria ser gravada pelo servidor (alice, com hora): %+v", got.Provider)
	}
	if bytes.Contains(b, []byte("sk-or-v1-TESTKEY-abcd1234")) {
		t.Fatalf("resposta vazou a chave: %s", b)
	}
}
