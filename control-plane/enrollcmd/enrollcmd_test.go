package enrollcmd

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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
	s, _ := newSvc(knownAcme)
	if w := do(s, "GET", "/api/v1/tenants/acme/enroll-command?target=bogus", "sekret"); w.Code != http.StatusBadRequest {
		t.Fatalf("target inválido deveria 400, got %d", w.Code)
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
		`C:\Windows\Temp\suricatoos-install.ps1`,
	} {
		if !strings.Contains(r.Command, want) {
			t.Errorf("comando windows nao contem %q:\n%s", want, r.Command)
		}
	}
	// REGRESSAO: nenhum '$' no comando. Um '$f'/'$env:TEMP' dentro do -Command e
	// expandido pelo shell de FORA ao colar num prompt do PowerShell, quebrando o
	// one-liner (=Join-Path..., -OutFile vazio). O comando robusto nao usa '$'.
	if strings.Contains(r.Command, "$") {
		t.Errorf("comando windows nao pode conter '$' (quebra ao colar no PowerShell):\n%s", r.Command)
	}
}
