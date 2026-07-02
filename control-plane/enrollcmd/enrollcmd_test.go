package enrollcmd

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/williamsouzadelima/suricatoos-infra/control-plane/tokens"
)

func newSvc(known TenantKnown) (*Service, *tokens.Manager) {
	tm := tokens.NewManager(tokens.NewMemStore())
	s := New(Config{
		TM:          tm,
		Known:       known,
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

func TestLinuxTargetInstallScript(t *testing.T) {
	s, _ := newSvc(knownAcme)
	w := do(s, "GET", "/api/v1/tenants/acme/enroll-command?target=linux", "sekret")
	var r response
	json.Unmarshal(w.Body.Bytes(), &r)
	if !strings.Contains(r.Command, "install.sh") || !strings.Contains(r.Command, "https://scanner.suricatoos.com/install.sh") {
		t.Fatalf("linux deveria usar o install.sh no publicBase: %s", r.Command)
	}
}
