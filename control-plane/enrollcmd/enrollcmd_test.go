package enrollcmd

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/williamsouzadelima/suricatoos-infra/control-plane/installcmd"
	"github.com/williamsouzadelima/suricatoos-infra/control-plane/sessiongate"
	"github.com/williamsouzadelima/suricatoos-infra/control-plane/tokens"
)

// gated marks the request the way nginx delivers it from a session-gated location:
// carrying the sessiongate marker header.
func gated(req *http.Request) *http.Request {
	req.Header.Set(sessiongate.Header, sessiongate.Value)
	return req
}

func newSvc(known TenantKnown) (*Service, *tokens.Manager) {
	tm := tokens.NewManager(tokens.NewMemStore())
	s := New(Config{
		TM:          tm,
		Known:       known,
		Tenants:     func() []string { return []string{"acme", "globex"} },
		CAPin:       "sha256:abc123",
		ServerURL:   "https://scanner.suricatoos.com/agent/v1",
		AdminSecret: "sekret",
	})
	return s, tm
}

func do(s *Service, method, path, bearer string) *httptest.ResponseRecorder {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/tenants/{t}/enroll-command", s.Handler())
	req := httptest.NewRequest(method, path, nil)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	return w
}

func knownAcme(name string) bool { return name == "acme" }

func TestNoBearer401(t *testing.T) {
	s, _ := newSvc(knownAcme)
	if w := do(s, "GET", "/api/v1/tenants/acme/enroll-command", ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("sem bearer deveria 401, got %d", w.Code)
	}
	if w := do(s, "GET", "/api/v1/tenants/acme/enroll-command", "wrong"); w.Code != http.StatusUnauthorized {
		t.Fatalf("bearer errado deveria 401, got %d", w.Code)
	}
}

// Every near miss of "Bearer <secret>" is refused, an empty configured secret never
// matches (fail closed), and nothing is minted on a refusal.
func TestBearerVariantsAreRefused(t *testing.T) {
	s, tm := newSvc(knownAcme)
	call := func(s *Service, auth string) int {
		mux := http.NewServeMux()
		mux.HandleFunc("GET /api/v1/tenants/{t}/enroll-command", s.Handler())
		req := httptest.NewRequest("GET", "/api/v1/tenants/acme/enroll-command", nil)
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		return w.Code
	}
	for name, auth := range map[string]string{
		"no header":             "",
		"wrong secret":          "Bearer wrong",
		"scheme only":           "Bearer",
		"empty token":           "Bearer ",
		"other scheme":          "Basic sekret",
		"secret without scheme": "sekret",
		"lowercase scheme":      "bearer sekret",
		"trailing junk":         "Bearer sekret ",
		"prefix of the secret":  "Bearer sekre",
	} {
		if code := call(s, auth); code != http.StatusUnauthorized {
			t.Errorf("%s: enroll-command = %d, want 401", name, code)
		}
	}
	empty := New(Config{TM: tm, Known: knownAcme, CAPin: "sha256:abc123", ServerURL: "https://x/agent/v1"})
	for _, auth := range []string{"", "Bearer ", "Bearer"} {
		if code := call(empty, auth); code != http.StatusUnauthorized {
			t.Errorf("empty secret, Authorization %q: enroll-command = %d, want 401", auth, code)
		}
	}
	if recs, _ := tm.List(); len(recs) != 0 {
		t.Fatalf("a refused request minted a token: %+v", recs)
	}
	// Positive control: the right bearer still works.
	if code := call(s, "Bearer sekret"); code != http.StatusOK {
		t.Fatalf("right bearer = %d, want 200", code)
	}
}

func TestUnknownTenant404(t *testing.T) {
	s, _ := newSvc(knownAcme)
	// globex is not known → must NOT mint (cross-tenant guard).
	if w := do(s, "GET", "/api/v1/tenants/globex/enroll-command", "sekret"); w.Code != http.StatusNotFound {
		t.Fatalf("tenant desconhecido deveria 404, got %d", w.Code)
	}
}

func TestDockerCommandForTenant(t *testing.T) {
	s, tm := newSvc(knownAcme)
	w := do(s, "GET", "/api/v1/tenants/acme/enroll-command?target=docker", "sekret")
	if w.Code != http.StatusOK {
		t.Fatalf("deveria 200, got %d: %s", w.Code, w.Body.String())
	}
	var r response
	if err := json.Unmarshal(w.Body.Bytes(), &r); err != nil {
		t.Fatal(err)
	}
	if r.Tenant != "acme" || r.Target != "docker" {
		t.Fatalf("tenant/target errados: %+v", r)
	}
	// The command must be a docker run carrying the freshly-minted token, the CA pin
	// and the image; and must NOT still contain the placeholder.
	for _, want := range []string{"docker run", "ENROLL_TOKEN=st_", "CA_PIN=sha256:abc123",
		"suricatoos-agent:stable", "-v /:/host:ro"} {
		if !strings.Contains(r.Command, want) {
			t.Errorf("comando não contém %q:\n%s", want, r.Command)
		}
	}
	if strings.Contains(r.Command, "<TOKEN") {
		t.Error("comando ainda tem placeholder de token")
	}
	// The minted token must be scoped to THIS tenant (server-side, not the request).
	recs, _ := tm.List()
	if len(recs) != 1 || recs[0].Scope.Tenant != "acme" || recs[0].Scope.Policy != "agent-endpoint" {
		t.Fatalf("token mintado com escopo errado: %+v", recs)
	}
}

func TestMaxUsesOneIsSingleHost(t *testing.T) {
	s, tm := newSvc(knownAcme)
	if w := do(s, "GET", "/api/v1/tenants/acme/enroll-command?max_uses=1", "sekret"); w.Code != http.StatusOK {
		t.Fatalf("deveria 200, got %d", w.Code)
	}
	recs, _ := tm.List()
	if recs[0].Type != tokens.SingleHost || recs[0].MaxUses != 1 {
		t.Fatalf("max_uses=1 deveria virar single_host, got type=%s max=%d", recs[0].Type, recs[0].MaxUses)
	}
}

func TestBadTarget400(t *testing.T) {
	s, tm := newSvc(knownAcme)
	// "macos" e "Darwin" tambem sao invalidos: o valor aceito e exatamente "darwin".
	for _, target := range []string{"bogus", "macos", "Darwin"} {
		w := do(s, "GET", "/api/v1/tenants/acme/enroll-command?target="+target, "sekret")
		if w.Code != http.StatusBadRequest {
			t.Fatalf("target %q inválido deveria 400, got %d", target, w.Code)
		}
		// A mensagem lista os alvos validos, incluindo darwin (macOS).
		if want := "target deve ser docker, linux, darwin ou windows"; !strings.Contains(w.Body.String(), want) {
			t.Errorf("target %q: mensagem do 400 deveria conter %q, got %q", target, want, w.Body.String())
		}
	}
	// Recusa ANTES de mintar: alvo invalido nao gasta token.
	if recs, _ := tm.List(); len(recs) != 0 {
		t.Fatalf("alvo inválido mintou token: %+v", recs)
	}
}

// macOS: o install.sh ja detecta o SO ('uname -s' → darwin, instala em /usr/local/bin),
// entao o one-liner e o mesmo do linux. Antes, target=darwin (botao macOS da pagina
// "Ativar Agente") sempre dava 400.
func TestDarwinTargetUsesInstallScript(t *testing.T) {
	s, tm := newSvc(knownAcme)
	w := do(s, "GET", "/api/v1/tenants/acme/enroll-command?target=darwin", "sekret")
	if w.Code != http.StatusOK {
		t.Fatalf("target=darwin deveria 200, got %d: %s", w.Code, w.Body.String())
	}
	var r response
	if err := json.Unmarshal(w.Body.Bytes(), &r); err != nil {
		t.Fatal(err)
	}
	if r.Tenant != "acme" || r.Target != "darwin" {
		t.Fatalf("tenant/target errados: %+v", r)
	}
	for _, want := range []string{
		"curl -fsSL https://scanner.suricatoos.com/install.sh | sudo sh -s --",
		"--server https://scanner.suricatoos.com/agent/v1",
		"--token st_",
		"--ca-pin sha256:abc123",
	} {
		if !strings.Contains(r.Command, want) {
			t.Errorf("comando darwin nao contem %q:\n%s", want, r.Command)
		}
	}
	for _, bad := range []string{"docker", "powershell"} {
		if strings.Contains(r.Command, bad) {
			t.Errorf("comando darwin nao deveria conter %q:\n%s", bad, r.Command)
		}
	}
	if r.Image != "" {
		t.Errorf("darwin nao usa imagem de container, got image=%q", r.Image)
	}
	// Mesmo one-liner do linux (so o token muda).
	gotDarwin, errD := s.command("darwin", "st_x")
	wantLinux, errL := s.command("linux", "st_x")
	if errD != nil || errL != nil {
		t.Fatalf("command: darwin=%v linux=%v", errD, errL)
	}
	if gotDarwin != wantLinux {
		t.Errorf("darwin deveria ter o mesmo one-liner do linux:\n got: %s\nwant: %s", gotDarwin, wantLinux)
	}
	// O token e do tenant e com a mesma politica dos demais alvos.
	recs, _ := tm.List()
	if len(recs) != 1 || recs[0].Scope.Tenant != "acme" || recs[0].Scope.Policy != "agent-endpoint" {
		t.Fatalf("token mintado com escopo errado: %+v", recs)
	}
}

// O botao macOS da UI chama a rota de SESSAO (atras do portao do nginx), nao a de
// bearer: target=darwin precisa dar 200 tambem ali.
func TestSessionHandlerAcceptsDarwin(t *testing.T) {
	s, _ := newSvc(knownAcme)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /provision/enroll-command", s.SessionHandler())
	req := gated(httptest.NewRequest("GET", "/provision/enroll-command?tenant=acme&target=darwin", nil))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("sessao com target=darwin deveria 200, got %d: %s", w.Code, w.Body.String())
	}
	var r response
	if err := json.Unmarshal(w.Body.Bytes(), &r); err != nil {
		t.Fatal(err)
	}
	if r.Target != "darwin" || !strings.Contains(r.Command, "https://scanner.suricatoos.com/install.sh") {
		t.Fatalf("resposta errada: %+v", r)
	}
}

func TestSessionHandlerMintsForQueryTenant(t *testing.T) {
	s, tm := newSvc(knownAcme)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /provision/enroll-command", s.SessionHandler())
	// No bearer (nginx does the session gate); tenant via ?tenant=.
	req := gated(httptest.NewRequest("GET", "/provision/enroll-command?tenant=acme&target=docker", nil))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("session handler deveria 200 (nginx gate), got %d", w.Code)
	}
	var r response
	json.Unmarshal(w.Body.Bytes(), &r)
	if r.Tenant != "acme" || !strings.Contains(r.Command, "docker run") {
		t.Fatalf("resposta errada: %+v", r)
	}
	recs, _ := tm.List()
	if recs[0].Scope.Tenant != "acme" {
		t.Fatalf("token deveria ser do tenant acme, got %s", recs[0].Scope.Tenant)
	}
	// Unknown tenant still refused even session-gated.
	req2 := gated(httptest.NewRequest("GET", "/provision/enroll-command?tenant=evilcorp", nil))
	w2 := httptest.NewRecorder()
	mux.ServeHTTP(w2, req2)
	if w2.Code != http.StatusNotFound {
		t.Fatalf("tenant desconhecido deveria 404 mesmo session-gated, got %d", w2.Code)
	}
}

func TestSessionTenantsHandler(t *testing.T) {
	s, _ := newSvc(knownAcme)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /provision/tenants", s.SessionTenantsHandler())
	req := gated(httptest.NewRequest("GET", "/provision/tenants", nil))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	var r struct {
		Tenants []string `json:"tenants"`
	}
	json.Unmarshal(w.Body.Bytes(), &r)
	if len(r.Tenants) != 2 || r.Tenants[0] != "acme" {
		t.Fatalf("lista de tenants errada: %+v", r.Tenants)
	}
}

// Without the marker nginx sets only on session-gated locations, the session handlers
// refuse (defense in depth): no token is minted, even for a valid tenant, and the
// tenant list does not leak.
func TestSessionHandlersRequireGateMarker(t *testing.T) {
	s, tm := newSvc(knownAcme)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /provision/enroll-command", s.SessionHandler())
	mux.HandleFunc("GET /provision/tenants", s.SessionTenantsHandler())

	for _, path := range []string{
		"/provision/enroll-command?tenant=acme&target=docker",
		"/provision/tenants",
	} {
		for _, gate := range []string{"", "1", "GSAD-SESSION"} {
			req := httptest.NewRequest("GET", path, nil)
			if gate != "" {
				req.Header.Set(sessiongate.Header, gate)
			}
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, req)
			if w.Code != http.StatusForbidden {
				t.Errorf("%s com marca %q deveria 403, got %d", path, gate, w.Code)
			}
			if strings.Contains(w.Body.String(), "acme") {
				t.Errorf("%s com marca %q vazou dado de tenant: %s", path, gate, w.Body.String())
			}
		}
	}
	if recs, _ := tm.List(); len(recs) != 0 {
		t.Fatalf("pedido sem marca mintou token: %+v", recs)
	}
}

func TestLinuxTargetInstallScript(t *testing.T) {
	s, _ := newSvc(knownAcme)
	w := do(s, "GET", "/api/v1/tenants/acme/enroll-command?target=linux", "sekret")
	var r response
	json.Unmarshal(w.Body.Bytes(), &r)
	if !strings.Contains(r.Command, "install.sh") || !strings.Contains(r.Command, "https://scanner.suricatoos.com/install.sh") {
		t.Fatalf("linux deveria usar o install.sh no publicBase: %s", r.Command)
	}
}

func TestWindowsCommandIsRobust(t *testing.T) {
	s, _ := newSvc(knownAcme)
	w := do(s, "GET", "/api/v1/tenants/acme/enroll-command?target=windows", "sekret")
	if w.Code != http.StatusOK {
		t.Fatalf("deveria 200, got %d: %s", w.Code, w.Body.String())
	}
	var r response
	if err := json.Unmarshal(w.Body.Bytes(), &r); err != nil {
		t.Fatal(err)
	}
	if r.Target != "windows" {
		t.Fatalf("target = %q", r.Target)
	}
	for _, want := range []string{
		"install.ps1",
		"-Server 'https://scanner.suricatoos.com/agent/v1'",
		"-Token 'st_",
		"-CaPin 'sha256:abc123'",
		"(Get-Item env:TEMP).Value", // TEMP de quem roda o comando, nao um caminho fixo
		"if (iwr -useb ",            // o download e a condicao: falha nao executa arquivo velho
		" -PassThru ",
		"powershell -NoProfile",
		"throw '", // guarda contra o TEMP do sistema (SYSTEM)
	} {
		if !strings.Contains(r.Command, want) {
			t.Errorf("comando windows nao contem %q:\n%s", want, r.Command)
		}
	}
	// REGRESSAO 1: nenhum '$' no comando. Um '$f'/'$env:TEMP' dentro do -Command e
	// expandido pelo shell de FORA ao colar num prompt do PowerShell, quebrando o
	// one-liner (=Join-Path..., -OutFile vazio). O comando robusto nao usa '$' (nem
	// crase, nem '%' do cmd.exe).
	if strings.ContainsAny(r.Command, "$`%") {
		t.Errorf("comando windows nao pode conter '$', crase ou '%%' (quebra ao colar no PowerShell/cmd):\n%s", r.Command)
	}
	// REGRESSAO 2: nada de caminho fixo em C:\Windows\Temp, onde qualquer usuario local
	// cria arquivos (pre-criar ou trocar o instalador antes da execucao elevada).
	if strings.Contains(r.Command, `:\`) {
		t.Errorf("comando windows nao pode ter caminho fixo (C:\\Windows\\Temp):\n%s", r.Command)
	}
}

// enrollcmd nao monta comando proprio para linux, macOS e Windows: devolve o do
// installcmd, o MESMO que o provision devolve (a forma exata esta travada la).
func TestCommandsComeFromInstallcmd(t *testing.T) {
	s, _ := newSvc(knownAcme)
	const server, token, pin = "https://scanner.suricatoos.com/agent/v1", "st_TESTE", "sha256:abc123"
	unix, err := installcmd.Unix(server, token, pin)
	if err != nil {
		t.Fatal(err)
	}
	windows, err := installcmd.Windows(server, token, pin)
	if err != nil {
		t.Fatal(err)
	}
	for target, want := range map[string]string{"linux": unix, "darwin": unix, "windows": windows} {
		got, err := s.command(target, token)
		if err != nil {
			t.Fatalf("%s: %v", target, err)
		}
		if got != want {
			t.Errorf("%s: o comando nao e o do installcmd:\n got: %s\nwant: %s", target, got, want)
		}
	}
}

// Config que nao cabe com seguranca no comando do Windows (aqui, uma URL com '$('): sem
// comando e SEM token mintado (a config e validada antes de mintar, entao um erro de
// configuracao nao minta e revoga um token a cada pedido); o erro nao vaza nada. Docker,
// linux e macOS citam o valor para o shell e seguem funcionando.
func TestWindowsRefusedWhenServerURLIsUnsafe(t *testing.T) {
	tm := tokens.NewManager(tokens.NewMemStore())
	s := New(Config{
		TM:          tm,
		Known:       knownAcme,
		CAPin:       "sha256:abc123",
		ServerURL:   "https://scanner.suricatoos.com/agent/v1$(evil)",
		AdminSecret: "sekret",
	})

	w := do(s, "GET", "/api/v1/tenants/acme/enroll-command?target=windows", "sekret")
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("windows com URL insegura deveria 500, got %d: %s", w.Code, w.Body.String())
	}
	if body := w.Body.String(); strings.Contains(body, "st_") || strings.Contains(body, "evil") {
		t.Errorf("a resposta de erro vazou dado: %s", body)
	}
	if recs, _ := tm.List(); len(recs) != 0 {
		t.Fatalf("a config recusada nao deveria mintar token: %+v", recs)
	}

	for target, want := range map[string]string{
		"linux":  "--server 'https://scanner.suricatoos.com/agent/v1$(evil)'",
		"darwin": "--server 'https://scanner.suricatoos.com/agent/v1$(evil)'",
		"docker": "CLOUD_BASE_URL='https://scanner.suricatoos.com/agent/v1$(evil)'",
	} {
		w := do(s, "GET", "/api/v1/tenants/acme/enroll-command?target="+target, "sekret")
		if w.Code != http.StatusOK {
			t.Fatalf("%s deveria seguir funcionando, got %d: %s", target, w.Code, w.Body.String())
		}
		var r response
		if err := json.Unmarshal(w.Body.Bytes(), &r); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(r.Command, want) {
			t.Errorf("%s: o valor deveria sair citado para o shell (%s):\n%s", target, want, r.Command)
		}
	}
}

// URL do servidor sem http(s)://host: nao ha de onde baixar o instalador, entao linux,
// macOS e Windows recusam SEM mintar token (antes saia "curl -fsSL /install.sh"). O docker
// nao baixa script nenhum e segue funcionando.
func TestUnusableServerURLRefusesInstallTargetsBeforeMinting(t *testing.T) {
	tm := tokens.NewManager(tokens.NewMemStore())
	s := New(Config{
		TM:          tm,
		Known:       knownAcme,
		CAPin:       "sha256:abc123",
		ServerURL:   "scanner.suricatoos.com/agent/v1",
		AdminSecret: "sekret",
	})
	for _, target := range []string{"linux", "darwin", "windows"} {
		w := do(s, "GET", "/api/v1/tenants/acme/enroll-command?target="+target, "sekret")
		if w.Code != http.StatusInternalServerError {
			t.Errorf("%s com URL sem esquema deveria 500, got %d: %s", target, w.Code, w.Body.String())
		}
	}
	if recs, _ := tm.List(); len(recs) != 0 {
		t.Fatalf("a config recusada nao deveria mintar token: %+v", recs)
	}
	if w := do(s, "GET", "/api/v1/tenants/acme/enroll-command?target=docker", "sekret"); w.Code != http.StatusOK {
		t.Errorf("docker nao depende do host dos scripts, deveria 200, got %d: %s", w.Code, w.Body.String())
	}
}
