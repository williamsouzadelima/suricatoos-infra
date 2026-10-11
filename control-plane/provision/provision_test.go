package provision

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/williamsouzadelima/suricatoos-infra/control-plane/sessiongate"
	"github.com/williamsouzadelima/suricatoos-infra/control-plane/tokens"
)

func newService() *Service {
	svc, _ := newServiceTM()
	return svc
}

// newServiceTM also returns the token manager, to assert on minting side effects.
func newServiceTM() (*Service, *tokens.Manager) {
	tm := tokens.NewManager(tokens.NewMemStore())
	return New(tm, "sha256:deadbeef", "https://scanner.suricatoos.com/agent/v1"), tm
}

// gatedGet builds a GET the way nginx delivers it from a session-gated location:
// carrying the sessiongate marker header.
func gatedGet(target string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, target, nil)
	r.Header.Set(sessiongate.Header, sessiongate.Value)
	return r
}

func TestProvisionMintsLinuxCommand(t *testing.T) {
	svc := newService()
	rec := httptest.NewRecorder()
	svc.Handler()(rec, gatedGet("/provision/install?os=linux"))
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
	svc.Handler()(rec, gatedGet("/provision/install?os=windows"))
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d", rec.Code)
	}
	var r response
	json.Unmarshal(rec.Body.Bytes(), &r)
	if !strings.Contains(r.Command, "install.ps1") || !strings.Contains(r.Command, "powershell") {
		t.Errorf("windows command should use install.ps1 via powershell:\n%s", r.Command)
	}
}

// installerPath is the fixed path the Windows one-liner downloads install.ps1 to and
// then runs. It is a literal on purpose: no '$f', no '$env:TEMP' (see command).
const installerPath = `C:\Windows\Temp\suricatoos-install.ps1`

// REGRESSAO: o one-liner do Windows nao pode depender do shell de FORA. Colado num
// prompt do PowerShell (ja aberto, sem aninhar), um '$f' / '$env:TEMP' dentro do
// -Command entre aspas duplas e expandido pelo shell externo ANTES de o powershell
// interno rodar: sobra "=Join-Path ..." e "-OutFile" vazio, e a instalacao quebra.
// O comando robusto usa um caminho fixo e nao tem '$' (nem crase, nem '%' do cmd.exe).
func TestProvisionWindowsCommandIsRobust(t *testing.T) {
	svc := newService()
	rec := httptest.NewRecorder()
	svc.Handler()(rec, gatedGet("/provision/install?os=windows"))
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var r response
	if err := json.Unmarshal(rec.Body.Bytes(), &r); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.OS != "windows" {
		t.Fatalf("os = %q", r.OS)
	}
	for _, want := range []string{
		"powershell",
		"iwr -useb https://scanner.suricatoos.com/install.ps1",
		"-Server 'https://scanner.suricatoos.com/agent/v1'",
		"-Token 'st_",
		"-CaPin 'sha256:deadbeef'",
		"-OutFile " + installerPath, // baixa para o caminho fixo...
		"& " + installerPath,        // ...e executa exatamente esse arquivo
	} {
		if !strings.Contains(r.Command, want) {
			t.Errorf("comando windows nao contem %q:\n%s", want, r.Command)
		}
	}
	if strings.ContainsAny(r.Command, "$`%") {
		t.Errorf("comando windows nao pode conter '$', crase ou '%%' (o shell de fora expande ao colar):\n%s", r.Command)
	}
}

// Forma exata de cada one-liner. Linux e macOS compartilham o install.sh (ele escolhe
// o binario por 'uname -s'); travados para o ramo do Windows nao mexer neles. O
// Windows e idem ao do enrollcmd (caminho fixo, sem '$').
func TestProvisionCommandForms(t *testing.T) {
	svc := newService()
	const unix = `curl -fsSL https://scanner.suricatoos.com/install.sh | sudo sh -s -- ` +
		`--server https://scanner.suricatoos.com/agent/v1 --token st_TESTE --ca-pin sha256:deadbeef`
	const windows = `powershell -ExecutionPolicy Bypass -Command "` +
		`iwr -useb https://scanner.suricatoos.com/install.ps1 -OutFile ` + installerPath + `; ` +
		`& ` + installerPath + ` -Server 'https://scanner.suricatoos.com/agent/v1' -Token 'st_TESTE' -CaPin 'sha256:deadbeef'"`
	for goos, want := range map[string]string{"linux": unix, "darwin": unix, "windows": windows} {
		if got := svc.command(goos, "st_TESTE"); got != want {
			t.Errorf("%s: forma do comando mudou:\n got: %s\nwant: %s", goos, got, want)
		}
	}
}

func TestProvisionRejectsBadOS(t *testing.T) {
	svc := newService()
	rec := httptest.NewRecorder()
	svc.Handler()(rec, gatedGet("/provision/install?os=plan9"))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for unknown os, got %d", rec.Code)
	}
}

func TestTokensAreSingleUseAndDistinct(t *testing.T) {
	svc := newService()
	get := func() response {
		rec := httptest.NewRecorder()
		svc.Handler()(rec, gatedGet("/provision/install?os=linux"))
		var r response
		json.Unmarshal(rec.Body.Bytes(), &r)
		return r
	}
	a, b := get(), get()
	if a.TokenID == b.TokenID {
		t.Fatal("each provision call must mint a distinct token")
	}
}

// Without the marker nginx sets only on session-gated locations the handler refuses
// BEFORE minting anything (defense in depth: a location that lacks the gate must not
// be able to obtain enrollment tokens).
func TestProvisionRequiresGateMarker(t *testing.T) {
	svc, tm := newServiceTM()

	for _, gate := range []string{"", "1", "GSAD-SESSION"} {
		r := httptest.NewRequest(http.MethodGet, "/provision/install?os=linux", nil)
		if gate != "" {
			r.Header.Set(sessiongate.Header, gate)
		}
		rec := httptest.NewRecorder()
		svc.Handler()(rec, r)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("marker %q: status=%d, want 403", gate, rec.Code)
		}
		if strings.Contains(rec.Body.String(), "--token") {
			t.Fatalf("marker %q: a refused request leaked an install command: %s", gate, rec.Body.String())
		}
	}
	if recs, _ := tm.List(); len(recs) != 0 {
		t.Fatalf("refused requests minted %d token(s)", len(recs))
	}

	// Positive control: the marker is the only difference.
	rec := httptest.NewRecorder()
	svc.Handler()(rec, gatedGet("/provision/install?os=linux"))
	if rec.Code != http.StatusOK {
		t.Fatalf("with marker: status=%d, want 200", rec.Code)
	}
	if recs, _ := tm.List(); len(recs) != 1 {
		t.Fatalf("with marker: want exactly 1 minted token, got %d", len(recs))
	}
}
