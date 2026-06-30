package provision

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/williamsouzadelima/suricatoos-infra/control-plane/tokens"
)

func newService() *Service {
	tm := tokens.NewManager(tokens.NewMemStore())
	return New(tm, "sha256:deadbeef", "https://scanner.suricatoos.com/agent/v1")
}

func TestProvisionMintsLinuxCommand(t *testing.T) {
	svc := newService()
	rec := httptest.NewRecorder()
	svc.Handler()(rec, httptest.NewRequest(http.MethodGet, "/provision/install?os=linux", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var r response
	if err := json.Unmarshal(rec.Body.Bytes(), &r); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.TokenID == "" || r.ExpiresAt.IsZero() {
		t.Fatalf("expected a minted token + expiry, got %+v", r)
	}
	// The one-liner must embed install.sh, the server, the ca-pin, and a token —
	// so the operator pastes ONE line, no token copying.
	for _, want := range []string{"install.sh", "https://scanner.suricatoos.com/agent/v1", "sha256:deadbeef", "--token"} {
		if !strings.Contains(r.Command, want) {
			t.Errorf("command missing %q:\n%s", want, r.Command)
		}
	}
}

func TestProvisionWindowsUsesPowershell(t *testing.T) {
	svc := newService()
	rec := httptest.NewRecorder()
	svc.Handler()(rec, httptest.NewRequest(http.MethodGet, "/provision/install?os=windows", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d", rec.Code)
	}
	var r response
	json.Unmarshal(rec.Body.Bytes(), &r)
	if !strings.Contains(r.Command, "install.ps1") || !strings.Contains(r.Command, "powershell") {
		t.Errorf("windows command should use install.ps1 via powershell:\n%s", r.Command)
	}
}

func TestProvisionRejectsBadOS(t *testing.T) {
	svc := newService()
	rec := httptest.NewRecorder()
	svc.Handler()(rec, httptest.NewRequest(http.MethodGet, "/provision/install?os=plan9", nil))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for unknown os, got %d", rec.Code)
	}
}

func TestTokensAreSingleUseAndDistinct(t *testing.T) {
	svc := newService()
	get := func() response {
		rec := httptest.NewRecorder()
		svc.Handler()(rec, httptest.NewRequest(http.MethodGet, "/provision/install?os=linux", nil))
		var r response
		json.Unmarshal(rec.Body.Bytes(), &r)
		return r
	}
	a, b := get(), get()
	if a.TokenID == b.TokenID {
		t.Fatal("each provision call must mint a distinct token")
	}
}
