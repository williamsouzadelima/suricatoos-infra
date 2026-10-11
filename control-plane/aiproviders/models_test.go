package aiproviders

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

// upstream is a fake provider catalog. It is TLS because a provider's base_url must
// be https. It counts hits and records the last Authorization header, path and Host
// (the host the request was ADDRESSED to — see officialRouter), and every Host.
type upstream struct {
	srv   *httptest.Server
	mu    sync.Mutex
	hits  int
	auth  string
	path  string
	host  string
	hosts []string
}

func newUpstream(t *testing.T, h http.HandlerFunc) *upstream {
	t.Helper()
	u := &upstream{}
	u.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u.mu.Lock()
		u.hits++
		u.auth = r.Header.Get("Authorization")
		u.path = r.URL.Path
		u.host = r.Host
		u.hosts = append(u.hosts, r.Host)
		u.mu.Unlock()
		h(w, r)
	}))
	t.Cleanup(u.srv.Close)
	return u
}

func (u *upstream) lastHost() string {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.host
}

// seenHosts is every Host the upstream was addressed as, in order.
func (u *upstream) seenHosts() string {
	u.mu.Lock()
	defer u.mu.Unlock()
	return strings.Join(u.hosts, ",")
}

// officialRouter delivers requests addressed to the routers' OFFICIAL hosts to the
// fake upstream (keeping path and Host header). Any other host goes through
// unchanged and is really reached — so "zero hits" on a foreign test server means
// it was never contacted, not that the request was swallowed here.
type officialRouter struct {
	target *url.URL
	base   http.RoundTripper
}

func (o officialRouter) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Host == hostOf(OfficialBaseURL(KindOpenRouter)) || r.URL.Host == hostOf(OfficialBaseURL(KindUnoRouter)) {
		r2 := r.Clone(r.Context())
		r2.URL.Scheme, r2.URL.Host = o.target.Scheme, o.target.Host
		r2.Host = r.URL.Host
		return o.base.RoundTrip(r2)
	}
	return o.base.RoundTrip(r)
}

func hostOf(raw string) string {
	u, _ := url.Parse(raw)
	return u.Host
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

// modelsHarness wires a Service over a fresh registry; see serveModels.
func modelsHarness(t *testing.T, freeOnly bool, up *upstream) (*httptest.Server, *Registry, *Service, *testClock) {
	t.Helper()
	kek, _ := randBytes(kekSize)
	reg, err := NewRegistry("", kek, WithFreeModelsOnly(freeOnly))
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	srv, svc, clock := serveModels(t, reg, up)
	return srv, reg, svc, clock
}

// serveModels serves reg's API. The outbound /models client delivers requests for
// the routers' official hosts to the fake upstream (TLS trusted) and lets any other
// host through; the clock is controllable (advance it to expire the cache).
func serveModels(t *testing.T, reg *Registry, up *upstream) (*httptest.Server, *Service, *testClock) {
	t.Helper()
	svc := NewService(reg, "s3cret")
	if up != nil {
		target, err := url.Parse(up.srv.URL)
		if err != nil {
			t.Fatalf("url do upstream: %v", err)
		}
		svc.modelsHC = newModelsClient(officialRouter{target: target, base: up.srv.Client().Transport})
	}
	clock := &testClock{t: time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)}
	svc.now = clock.Now
	mux := http.NewServeMux()
	svc.Register(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, svc, clock
}

// addProvider stores a DISABLED provider on the kind's default endpoint (enabling
// is not needed to list models: the operator lists them to pick one first).
func addProvider(t *testing.T, reg *Registry, kind, model, key string) string {
	t.Helper()
	pub, err := reg.Upsert(UpsertInput{Name: "P " + kind, Kind: kind, Model: model, APIKey: key}, "op")
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
	id := addProvider(t, reg, KindOpenRouter, "openrouter/free", "")

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
	if p, h := up.lastPath(), up.lastHost(); p != "/api/v1/models" || h != "openrouter.ai" {
		t.Fatalf("deveria buscar o /models do endpoint oficial, buscou host=%q path=%q", h, p)
	}
	// Wire shape: context_length is omitted when the provider does not inform it.
	if !bytes.Contains(b, []byte(`{"id":"alpha/no-params:free","json_schema":false,"json_schema_known":false}`)) {
		t.Fatalf("formato inesperado: %s", b)
	}
}

func TestModels_OpenRouterWithoutKeyOmitsAuthorization(t *testing.T) {
	up := newUpstream(t, serveCatalog)
	srv, reg, _, _ := modelsHarness(t, true, up)
	id := addProvider(t, reg, KindOpenRouter, "openrouter/free", "")
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
	id := addProvider(t, reg, KindUnoRouter, "deepseek-v4-flash:free", testKey)

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
	id := addProvider(t, reg, KindUnoRouter, "deepseek-v4-flash:free", "")

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
	id := addProvider(t, reg, KindOpenRouter, "openrouter/free", "")
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
	if _, err := reg.Upsert(UpsertInput{ID: id, Name: "P", Kind: KindOpenRouter, Model: "openrouter/free", APIKey: testKey}, "op"); err != nil {
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
			id := addProvider(t, reg, KindUnoRouter, "deepseek-v4-flash:free", testKey)

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
	id := addProvider(t, reg, KindOpenRouter, "openrouter/free", "")
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
	id := addProvider(t, reg, KindOpenRouter, "openrouter/free", "")
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
	id := addProvider(t, reg, KindOpenRouter, "openrouter/free", "")

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
	id := addProvider(t, reg, KindOpenRouter, "openrouter/free", "")
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

	// With the acknowledgment the free provider is accepted and the SERVER records
	// it — never from the body. The request arrives as nginx delivers it: nginx
	// clears X-Operator and sets no identity (propagating the gsad user is pending),
	// so WHEN is recorded and WHO is the "operator" marker the UI does not show.
	body := `{"name":"OR","kind":"openrouter","model":"openrouter/free","enabled":true,"data_policy_ack":true,"data_policy_ack_by":"forjado","api_key":"sk-or-v1-TESTKEY-abcd1234"}`
	resp, b := doSession(t, srv, "POST", "/ai/providers", body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("gratuito com ciência = %d, want 200: %s", resp.StatusCode, b)
	}
	var got struct {
		Provider PublicProvider `json:"provider"`
	}
	_ = json.Unmarshal(b, &got)
	if !got.Provider.Enabled || !got.Provider.DataPolicyAck || got.Provider.DataPolicyAckAt.IsZero() {
		t.Fatalf("a ciência deveria ser gravada pelo servidor, com a hora: %+v", got.Provider)
	}
	if got.Provider.DataPolicyAckBy != "operator" || got.Provider.UpdatedBy != "operator" {
		t.Fatalf("sem identidade do nginx, quem fica o marcador %q (nunca o do corpo): ack_by=%q updated_by=%q",
			"operator", got.Provider.DataPolicyAckBy, got.Provider.UpdatedBy)
	}
	if bytes.Contains(b, []byte("sk-or-v1-TESTKEY-abcd1234")) {
		t.Fatalf("resposta vazou a chave: %s", b)
	}
}

// I3 over the wire: the session that switches the kind of a key-bearing provider
// gets a 422, and the stored key keeps going only to the router it was pasted for
// — the listing never takes it to the other router.
func TestModels_KindSwitchNeverTakesTheKeyToTheOtherRouter(t *testing.T) {
	up := newUpstream(t, serveCatalog) // answers for BOTH official hosts (see officialRouter)
	srv, reg, _, _ := modelsHarness(t, true, up)
	if _, err := reg.EnsurePresets(); err != nil {
		t.Fatalf("EnsurePresets: %v", err)
	}
	paste := `{"id":"openrouter-free","name":"OpenRouter — modelos gratuitos","kind":"openrouter","model":"openrouter/free","enabled":true,"data_policy_ack":true,"api_key":"` + testKey + `"}`
	if resp, b := doSession(t, srv, "POST", "/ai/providers", paste); resp.StatusCode != http.StatusOK {
		t.Fatalf("colar a chave = %d: %s", resp.StatusCode, b)
	}
	switchKind := `{"id":"openrouter-free","name":"OpenRouter — modelos gratuitos","kind":"unorouter","model":"deepseek-v4-flash:free","enabled":true,"data_policy_ack":true}`
	if resp, b := doSession(t, srv, "POST", "/ai/providers", switchKind); resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("trocar o tipo sem chave nova = %d, want 422: %s", resp.StatusCode, b)
	}
	if resp, b := doSession(t, srv, "GET", "/ai/providers/openrouter-free/models", ""); resp.StatusCode != http.StatusOK {
		t.Fatalf("lista de modelos = %d: %s", resp.StatusCode, b)
	}
	if h := up.seenHosts(); h != "openrouter.ai" {
		t.Fatalf("a chave do OpenRouter só pode ir ao OpenRouter; hosts contatados: %q", h)
	}
	if up.lastAuth() != "Bearer "+testKey {
		t.Fatalf("a lista deveria usar a chave guardada no próprio OpenRouter, mandou %q", up.lastAuth())
	}
}

func mustUpsert(t *testing.T, reg *Registry, in UpsertInput) string {
	t.Helper()
	pub, err := reg.Upsert(in, "op")
	if err != nil {
		t.Fatalf("setup upsert %s: %v", in.Name, err)
	}
	return pub.ID
}

// The confused-deputy path: a session user repoints a key-bearing provider at a
// host they control and asks for its models, hoping the server sends the stored
// key there. With the rule on the base_url is pinned, so the key only ever reaches
// the router's official API.
func TestModels_NeverSendsTheKeyToAForeignHost(t *testing.T) {
	up := newUpstream(t, serveCatalog)   // stands in for the official API
	evil := newUpstream(t, serveCatalog) // a host chosen through the API
	srv, _, _, _ := modelsHarness(t, true, up)

	body := `{"name":"OR","kind":"openrouter","base_url":"` + evil.srv.URL + `","model":"openrouter/free","api_key":"` + testKey + `"}`
	resp, b := doSession(t, srv, "POST", "/ai/providers", body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("upsert = %d: %s", resp.StatusCode, b)
	}
	var got struct {
		Provider PublicProvider `json:"provider"`
	}
	_ = json.Unmarshal(b, &got)
	if got.Provider.BaseURL != OfficialBaseURL(KindOpenRouter) {
		t.Fatalf("base_url deveria ser fixada no endpoint oficial, ficou %q", got.Provider.BaseURL)
	}

	resp, b = doSession(t, srv, "GET", "/ai/providers/"+got.Provider.ID+"/models", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("models = %d: %s", resp.StatusCode, b)
	}
	if n := evil.count(); n != 0 {
		t.Fatalf("o servidor contatou um host escolhido pela API (%d chamada(s)) — a chave iria junto", n)
	}
	if up.count() != 1 || up.lastHost() != "openrouter.ai" || up.lastAuth() != "Bearer "+testKey {
		t.Fatalf("a chave deveria ir só ao endpoint oficial: hits=%d host=%q", up.count(), up.lastHost())
	}
}

// Providers stored BEFORE the rule (or with it off) may carry a foreign base_url;
// with the rule on, the listing refuses them (422) without any request, until the
// provider is saved again — which pins the base.
func TestModels_RefusesLegacyForeignEndpoint(t *testing.T) {
	up := newUpstream(t, serveCatalog)
	evil := newUpstream(t, serveCatalog)
	path := filepath.Join(t.TempDir(), "providers.json")
	kek, _ := randBytes(kekSize)
	old, err := NewRegistry(path, kek) // rule off, as before the upgrade
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	orID := mustUpsert(t, old, UpsertInput{Name: "OR antigo", Kind: KindOpenRouter, BaseURL: evil.srv.URL, Model: "openrouter/free", APIKey: testKey})
	gwID := mustUpsert(t, old, UpsertInput{Name: "GW antigo", Kind: KindOpenAICompatible, BaseURL: evil.srv.URL, Model: "x:free", APIKey: testKey})

	reg, err := NewRegistry(path, kek, WithFreeModelsOnly(true)) // same store, rule on
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	srv, _, _ := serveModels(t, reg, up)
	for _, id := range []string{orID, gwID} {
		resp, b := do(t, srv, "GET", "/api/v1/ai/providers/"+id+"/models", "s3cret", "")
		if resp.StatusCode != http.StatusUnprocessableEntity || !strings.Contains(decodeModels(t, b).Error, "endpoint oficial") {
			t.Fatalf("registro antigo fora do endpoint oficial = %d %s, want 422", resp.StatusCode, b)
		}
	}
	if evil.count() != 0 || up.count() != 0 {
		t.Fatalf("recusa não pode ir à rede: evil=%d oficial=%d", evil.count(), up.count())
	}

	// Saving the router again WITHOUT a new key does not move its key: the key was
	// pasted for another host (one chosen through the API), so the save is refused
	// (422) and nothing is contacted. With a new key the save pins the official
	// endpoint, and the listing reaches it with the NEW key only — still never the
	// foreign host.
	resp, b := do(t, srv, "POST", "/api/v1/ai/providers", "s3cret", `{"id":"`+orID+`","name":"OR antigo","kind":"openrouter","model":"openrouter/free"}`)
	if resp.StatusCode != http.StatusUnprocessableEntity || !strings.Contains(decodeModels(t, b).Error, msgKeyRebind) {
		t.Fatalf("salvar de novo sem chave nova = %d %s, want 422 (%s)", resp.StatusCode, b, msgKeyRebind)
	}
	const newKey = "sk-or-v1-CHAVE-NOVA-0042"
	resp, b = do(t, srv, "POST", "/api/v1/ai/providers", "s3cret", `{"id":"`+orID+`","name":"OR antigo","kind":"openrouter","model":"openrouter/free","api_key":"`+newKey+`"}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("salvar com chave nova = %d: %s", resp.StatusCode, b)
	}
	if resp, b := do(t, srv, "GET", "/api/v1/ai/providers/"+orID+"/models", "s3cret", ""); resp.StatusCode != http.StatusOK {
		t.Fatalf("após salvar com chave nova = %d: %s", resp.StatusCode, b)
	}
	if evil.count() != 0 || up.count() != 1 || up.lastAuth() != "Bearer "+newKey {
		t.Fatalf("após salvar: evil=%d oficial=%d auth=%q", evil.count(), up.count(), up.lastAuth())
	}
}

// With the rule OFF a custom endpoint is still accepted and kept (today's
// behavior), but this session-reachable listing still never sends the stored key —
// nor any request — anywhere but the routers' official APIs.
func TestModels_RuleOffAlsoRefusesForeignEndpoint(t *testing.T) {
	up := newUpstream(t, serveCatalog)
	evil := newUpstream(t, serveCatalog)
	srv, reg, _, _ := modelsHarness(t, false, up)

	pub, err := reg.Upsert(UpsertInput{Name: "Proxy", Kind: KindOpenRouter, BaseURL: evil.srv.URL, Model: "openai/gpt-5.5", APIKey: testKey}, "op")
	if err != nil || pub.BaseURL != evil.srv.URL {
		t.Fatalf("regra desligada: base própria deveria ser mantida: %+v err=%v", pub, err)
	}
	resp, b := doSession(t, srv, "GET", "/ai/providers/"+pub.ID+"/models", "")
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("listagem de endpoint próprio = %d %s, want 422", resp.StatusCode, b)
	}
	if n := evil.count(); n != 0 {
		t.Fatalf("a listagem contatou o endpoint próprio (%d chamada(s))", n)
	}
	// The official endpoint keeps working with the rule off.
	id := addProvider(t, reg, KindOpenRouter, "openai/gpt-5.5", testKey)
	if resp, b := doSession(t, srv, "GET", "/ai/providers/"+id+"/models", ""); resp.StatusCode != http.StatusOK {
		t.Fatalf("regra desligada, endpoint oficial = %d: %s", resp.StatusCode, b)
	}
	if up.count() != 1 || up.lastHost() != "openrouter.ai" {
		t.Fatalf("esperava 1 chamada ao endpoint oficial: hits=%d host=%q", up.count(), up.lastHost())
	}
}
