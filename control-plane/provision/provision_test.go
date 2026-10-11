package provision

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

// REGRESSAO: o one-liner do Windows nao pode depender do shell de FORA nem gravar o
// instalador onde outros usuarios escrevem.
//   - Colado num prompt do PowerShell (ja aberto, sem aninhar), um '$f' / '$env:TEMP'
//     dentro do -Command entre aspas duplas e expandido pelo shell externo ANTES de o
//     powershell interno rodar: sobra "=Join-Path ..." e "-OutFile" vazio.
//   - Um caminho fixo em C:\Windows\Temp aceita arquivos de qualquer usuario local, que
//     poderia pre-criar ou trocar o arquivo entre o download e a execucao elevada. O
//     instalador vai para o TEMP do usuario que roda o comando, e a guarda recusa o TEMP
//     do sistema (SYSTEM) antes de baixar.
//   - O download e a condicao de um 'if': download que falha nao executa arquivo velho.
//
// A forma exata e as demais invariantes estao travadas no installcmd.
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
		"powershell -NoProfile",
		"if (iwr -useb https://scanner.suricatoos.com/install.ps1 -PassThru -OutFile ",
		"-Server 'https://scanner.suricatoos.com/agent/v1'",
		"-Token 'st_",
		"-CaPin 'sha256:deadbeef'",
		"(Get-Item env:TEMP).Value", // TEMP de quem roda o comando, nao um caminho fixo
		"throw '",                   // guarda contra o TEMP do sistema
	} {
		if !strings.Contains(r.Command, want) {
			t.Errorf("comando windows nao contem %q:\n%s", want, r.Command)
		}
	}
	if strings.ContainsAny(r.Command, "$`%") {
		t.Errorf("comando windows nao pode conter '$', crase ou '%%' (o shell de fora expande ao colar):\n%s", r.Command)
	}
	if strings.Contains(r.Command, `:\`) {
		t.Errorf("comando windows nao pode ter caminho fixo (C:\\Windows\\Temp: qualquer usuario local escreve la):\n%s", r.Command)
	}
}

// provision nao monta comando proprio: devolve o do installcmd, o MESMO que o enrollcmd
// devolve (a forma exata esta travada la). Linux e macOS saem iguais: o install.sh
// escolhe o binario por 'uname -s'.
func TestProvisionCommandComesFromInstallcmd(t *testing.T) {
	svc := newService()
	const server, token, pin = "https://scanner.suricatoos.com/agent/v1", "st_TESTE", "sha256:deadbeef"
	unix, err := installcmd.Unix(server, token, pin)
	if err != nil {
		t.Fatal(err)
	}
	windows, err := installcmd.Windows(server, token, pin)
	if err != nil {
		t.Fatal(err)
	}
	for goos, want := range map[string]string{"linux": unix, "darwin": unix, "windows": windows} {
		got, err := svc.command(goos, token)
		if err != nil {
			t.Fatalf("%s: %v", goos, err)
		}
		if got != want {
			t.Errorf("%s: o comando nao e o do installcmd:\n got: %s\nwant: %s", goos, got, want)
		}
	}
}

// Config que nao cabe com seguranca no comando do Windows (aqui, uma URL com '$('): sem
// comando e SEM token mintado (a config e validada antes de mintar, entao um erro de
// configuracao nao minta e revoga um token a cada pedido); o erro nao vaza nada. Linux e
// macOS citam o valor para o shell e seguem funcionando.
func TestProvisionWindowsRefusedWhenServerURLIsUnsafe(t *testing.T) {
	tm := tokens.NewManager(tokens.NewMemStore())
	svc := New(tm, "sha256:deadbeef", "https://scanner.suricatoos.com/agent/v1$(evil)")

	rec := httptest.NewRecorder()
	svc.Handler()(rec, gatedGet("/provision/install?os=windows"))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("windows com URL insegura deveria 500, got %d: %s", rec.Code, rec.Body.String())
	}
	if body := rec.Body.String(); strings.Contains(body, "st_") || strings.Contains(body, "evil") {
		t.Errorf("a resposta de erro vazou dado: %s", body)
	}
	if recs, _ := tm.List(); len(recs) != 0 {
		t.Fatalf("a config recusada nao deveria mintar token: %+v", recs)
	}

	rec = httptest.NewRecorder()
	svc.Handler()(rec, gatedGet("/provision/install?os=linux"))
	if rec.Code != http.StatusOK {
		t.Fatalf("linux deveria seguir funcionando, got %d: %s", rec.Code, rec.Body.String())
	}
	var r response
	if err := json.Unmarshal(rec.Body.Bytes(), &r); err != nil {
		t.Fatal(err)
	}
	if want := "--server 'https://scanner.suricatoos.com/agent/v1$(evil)'"; !strings.Contains(r.Command, want) {
		t.Errorf("o valor deveria sair citado para o shell (%s):\n%s", want, r.Command)
	}
}

// URL do servidor sem http(s)://host: nao ha de onde baixar o instalador. Nenhum SO tem
// comando e nenhum token e mintado (antes saia "curl -fsSL /install.sh", que nao funciona
// e nao diz por que).
func TestProvisionUnusableServerURLRefusesEverythingBeforeMinting(t *testing.T) {
	tm := tokens.NewManager(tokens.NewMemStore())
	svc := New(tm, "sha256:deadbeef", "scanner.suricatoos.com/agent/v1")
	for _, goos := range []string{"linux", "darwin", "windows"} {
		rec := httptest.NewRecorder()
		svc.Handler()(rec, gatedGet("/provision/install?os="+goos))
		if rec.Code != http.StatusInternalServerError {
			t.Errorf("%s com URL sem esquema deveria 500, got %d: %s", goos, rec.Code, rec.Body.String())
		}
	}
	if recs, _ := tm.List(); len(recs) != 0 {
		t.Fatalf("a config recusada nao deveria mintar token: %+v", recs)
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
