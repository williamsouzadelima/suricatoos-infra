package fleetops

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/williamsouzadelima/suricatoos-infra/fleet/contract"
)

const (
	testUser     = "fleet-leitor"
	testPassword = "senha-ficticia-do-no"
)

func fakeRunner(t *testing.T, mode string, args ...string) *Runner {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return &Runner{Command: append([]string{exe, fakeArg, mode}, args...), Timeout: 30 * time.Second}
}

func stateRequest() map[string]any {
	return map[string]any{"op": "state.tasks", "command_id": "", "owners": map[string]string{"tenant-acme": "acme"},
		"payload": map[string]any{}}
}

type echoed struct {
	Request json.RawMessage `json:"request"`
	Args    []string        `json:"args"`
	Env     []string        `json:"env"`
}

func runEcho(t *testing.T, r *Runner, req any) echoed {
	t.Helper()
	res, err := r.Run(context.Background(), req, testUser, testPassword)
	if err != nil {
		t.Fatal(err)
	}
	var e echoed
	if err := json.Unmarshal(res.Output, &e); err != nil {
		t.Fatal(err)
	}
	return e
}

func wantCode(t *testing.T, err error, code contract.ErrorCode) *Error {
	t.Helper()
	var fe *Error
	if !errors.As(err, &fe) {
		t.Fatalf("esperava *Error %s, veio %v", code, err)
	}
	if fe.Code != code {
		t.Fatalf("código %s, esperava %s (%v)", fe.Code, code, fe)
	}
	return fe
}

func TestRunMandaOPedidoCompactoNaEntradaEDevolveOOutput(t *testing.T) {
	req := stateRequest()
	got := runEcho(t, fakeRunner(t, "echo"), req)
	want, err := contract.MarshalCompact(req)
	if err != nil {
		t.Fatal(err)
	}
	if string(got.Request) != string(want) {
		t.Fatalf("stdin = %s, esperava %s", got.Request, want)
	}
}

func TestSenhaSoNoAmbienteNuncaNosArgumentos(t *testing.T) {
	got := runEcho(t, fakeRunner(t, "echo"), stateRequest())
	for _, a := range got.Args {
		if strings.Contains(a, testPassword) || strings.Contains(a, testUser) {
			t.Fatalf("credencial no argv: %q", got.Args)
		}
	}
	if len(got.Args) != 2 || got.Args[0] != fakeArg || got.Args[1] != "echo" { // só o Command, nada acrescentado
		t.Fatalf("argv além do Command: %q", got.Args)
	}
	if !containsEnv(got.Env, "GMP_PASSWORD="+testPassword) || !containsEnv(got.Env, "GMP_USERNAME="+testUser) {
		t.Fatalf("usuário e senha têm de ir pelo ambiente: %q", got.Env)
	}
}

// O ambiente do filho é mínimo e explícito: nada do conector vaza (o ingest, por exemplo, exporta
// GMP_USERNAME=admin), só o que o fleet_ops lê.
func TestAmbienteMinimoNuncaHerdado(t *testing.T) {
	t.Setenv("GMP_USERNAME", "admin")
	t.Setenv("FLEET_SEGREDO_DO_CONECTOR", "nao-pode-vazar")
	r := fakeRunner(t, "echo")
	for _, socket := range []string{"", "/run/gvmd/gvmd.sock"} {
		r.Socket = socket
		got := runEcho(t, r, stateRequest())
		want := map[string]string{"GMP_USERNAME": testUser, "GMP_PASSWORD": testPassword}
		if socket != "" {
			want["GVMD_SOCKET"] = socket
		}
		seen := map[string]bool{}
		for _, kv := range got.Env {
			name, value, _ := strings.Cut(kv, "=")
			if runtime.GOOS == "windows" && strings.EqualFold(name, "SYSTEMROOT") {
				continue // o os/exec acrescenta no Windows, que não sobe processo sem ele
			}
			if w, ok := want[name]; !ok || w != value {
				t.Errorf("socket %q: variável inesperada no filho: %q", socket, kv)
			}
			seen[name] = true
		}
		for name := range want {
			if !seen[name] {
				t.Errorf("socket %q: falta %s no filho", socket, name)
			}
		}
	}
}

func TestUmExecPorChamada(t *testing.T) {
	r := fakeRunner(t, "echo")
	for i := range 3 {
		req := map[string]any{"op": "state.reports", "command_id": "", "owners": map[string]string{}, "payload": map[string]any{}, "n": i}
		got := runEcho(t, r, req)
		var back map[string]any
		if err := json.Unmarshal(got.Request, &back); err != nil || back["n"] != float64(i) {
			t.Fatalf("chamada %d recebeu %s", i, got.Request)
		}
	}
}

func TestTimeoutMataOProcessoEDevolveTimeout(t *testing.T) {
	r := fakeRunner(t, "sleep")
	r.Timeout = 300 * time.Millisecond
	start := time.Now()
	_, err := r.Run(context.Background(), stateRequest(), testUser, testPassword)
	wantCode(t, err, contract.ErrorTimeout)
	if d := time.Since(start); d > 15*time.Second {
		t.Fatalf("o timeout de 300 ms levou %s", d)
	}
}

func TestCancelamentoDoChamadorEInterrupted(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(300*time.Millisecond, cancel)
	_, err := fakeRunner(t, "sleep").Run(ctx, stateRequest(), testUser, testPassword)
	wantCode(t, err, contract.ErrorInterrupted)
}

func TestSaidaAcimaDoTetoMataOProcesso(t *testing.T) {
	r := fakeRunner(t, "big", strconv.Itoa(1<<20))
	r.MaxOutput = 64 << 10
	start := time.Now()
	_, err := r.Run(context.Background(), stateRequest(), testUser, testPassword)
	fe := wantCode(t, err, contract.ErrorInternal)
	if !strings.Contains(fe.Message, "teto") {
		t.Fatalf("mensagem %q", fe.Message)
	}
	if d := time.Since(start); d > 15*time.Second { // o falso dorme um minuto depois de escrever
		t.Fatalf("o leitor esperou o processo em vez de matá-lo: %s", d)
	}
}

func TestSaidaNoTetoExatoPassa(t *testing.T) {
	const max = 64 << 10
	r := fakeRunner(t, "padded", strconv.Itoa(max))
	r.MaxOutput = max
	res, err := r.Run(context.Background(), stateRequest(), testUser, testPassword)
	if err != nil || string(res.Output) != "{}" {
		t.Fatalf("Run = %s, %v", res.Output, err)
	}
	r = fakeRunner(t, "padded", strconv.Itoa(max+1))
	r.MaxOutput = max
	_, err = r.Run(context.Background(), stateRequest(), testUser, testPassword)
	wantCode(t, err, contract.ErrorInternal)
}

func TestErroEstruturadoDoFleetOps(t *testing.T) {
	for _, code := range []contract.ErrorCode{contract.ErrorNotFound, contract.ErrorConflict, contract.ErrorGVM,
		contract.ErrorTimeout, contract.ErrorInterrupted, contract.ErrorUnavailable, contract.ErrorArtifactTooLarge,
		contract.ErrorArtifactUploadFailed, contract.ErrorSecretLost, contract.ErrorInternal} {
		_, err := fakeRunner(t, "error", string(code), "gvmd busy or unavailable (get_tasks)").
			Run(context.Background(), stateRequest(), testUser, testPassword)
		fe := wantCode(t, err, code)
		if fe.Message != "gvmd busy or unavailable (get_tasks)" {
			t.Errorf("%s: mensagem %q", code, fe.Message)
		}
	}
}

func TestCodigoDeErroForaDoContratoEInternalError(t *testing.T) {
	_, err := fakeRunner(t, "error", "kaboom", "x").Run(context.Background(), stateRequest(), testUser, testPassword)
	wantCode(t, err, contract.ErrorInternal)
}

func TestSaida1ComRespostaDeErroUsaAResposta(t *testing.T) {
	_, err := fakeRunner(t, "exit1").Run(context.Background(), stateRequest(), testUser, testPassword)
	if fe := wantCode(t, err, contract.ErrorInternal); fe.Message != "unexpected failure (KeyError)" {
		t.Fatalf("mensagem %q", fe.Message)
	}
}

func TestRespostaForaDoProtocoloEInternalError(t *testing.T) {
	cases := map[string]*Runner{
		"não é JSON":               fakeRunner(t, "garbage"),
		"traceback com saída 1":    fakeRunner(t, "traceback"),
		"dois valores":             fakeRunner(t, "two-values"),
		"ok com saída 1":           fakeRunner(t, "ok-exit1"),
		"vazio":                    fakeRunner(t, "raw", ""),
		"ok sem output":            fakeRunner(t, "raw", `{"ok":true}`),
		"erro sem error":           fakeRunner(t, "raw", `{"ok":false}`),
		"ok com error":             fakeRunner(t, "raw", `{"ok":true,"output":{},"error":{"code":"gvm_error","message":"x"}}`),
		"erro com output":          fakeRunner(t, "raw", `{"ok":false,"output":{},"error":{"code":"gvm_error","message":"x"}}`),
		"erro com artifact":        fakeRunner(t, "raw", `{"ok":false,"artifact":{},"error":{"code":"gvm_error","message":"x"}}`),
		"output que não é objeto":  fakeRunner(t, "raw", `{"ok":true,"output":[]}`),
		"membro desconhecido":      fakeRunner(t, "raw", `{"ok":true,"output":{},"comment":"x"}`),
		"chave repetida":           fakeRunner(t, "raw", `{"ok":true,"ok":true,"output":{}}`),
		"caixa diferente":          fakeRunner(t, "raw", `{"OK":true,"output":{}}`),
		"error sem message":        fakeRunner(t, "raw", `{"ok":false,"error":{"code":"gvm_error"}}`),
		"ok null":                  fakeRunner(t, "raw", `{"ok":null,"output":{}}`),
		"BOM":                      fakeRunner(t, "raw", "\xef\xbb\xbf"+`{"ok":true,"output":{}}`),
		"surrogate desemparelhado": fakeRunner(t, "raw", `{"ok":true,"output":{"a":"\ud800"}}`),
	}
	for name, r := range cases {
		_, err := r.Run(context.Background(), stateRequest(), testUser, testPassword)
		var fe *Error
		if !errors.As(err, &fe) || fe.Code != contract.ErrorInternal {
			t.Errorf("%s: esperava internal_error, veio %v", name, err)
		}
	}
}

func TestStderrEDescartado(t *testing.T) {
	res, err := fakeRunner(t, "stderr").Run(context.Background(), stateRequest(), testUser, testPassword)
	if err != nil || string(res.Output) != `{"a":1}` {
		t.Fatalf("Run = %s, %v", res.Output, err)
	}
}

func TestMensagemDeErroSemSenhaSemControleELimitada(t *testing.T) {
	_, err := fakeRunner(t, "leak").Run(context.Background(), stateRequest(), testUser, testPassword)
	fe := wantCode(t, err, contract.ErrorGVM)
	for _, text := range []string{fe.Message, fe.Error()} {
		if strings.Contains(text, testPassword) {
			t.Fatalf("a senha vazou: %q", text)
		}
		if strings.ContainsAny(text, "\x00\x01\n\r\t") {
			t.Fatalf("caractere de controle na mensagem: %q", text)
		}
	}
	if !strings.Contains(fe.Message, "[redacted]") {
		t.Fatalf("mensagem %q", fe.Message)
	}

	long := strings.Repeat("é", 2000)
	_, err = fakeRunner(t, "error", "gvm_error", long).Run(context.Background(), stateRequest(), testUser, testPassword)
	if fe := wantCode(t, err, contract.ErrorGVM); utf8.RuneCountInString(fe.Message) > MaxMessageRunes || !utf8.ValidString(fe.Message) {
		t.Fatalf("mensagem de %d runas", utf8.RuneCountInString(fe.Message))
	}
}

func TestArtifactVemSeparadoDoOutput(t *testing.T) {
	res, err := fakeRunner(t, "artifact").Run(context.Background(), stateRequest(), testUser, testPassword)
	if err != nil || string(res.Output) != `{"report_id":"x"}` || string(res.Artifact) != `{"original_size":3}` {
		t.Fatalf("Run = %+v, %v", res, err)
	}
}

// O que o conector nunca deveria mandar não chega a virar processo: com um Command inexistente, executar daria
// unavailable, e o que volta é internal_error.
func TestPedidoInvalidoNaoExecuta(t *testing.T) {
	r := &Runner{Command: []string{filepath.Join(t.TempDir(), "nao-existe")}}
	big := map[string]any{"op": "state.tasks", "x": strings.Repeat("a", MaxRequestBytes)}
	cases := []struct {
		name           string
		req            any
		user, password string
	}{
		{"pedido acima de 1 MiB", big, testUser, testPassword},
		{"sem usuário", stateRequest(), "", testPassword},
		{"sem senha", stateRequest(), testUser, ""},
		{"senha com NUL", stateRequest(), testUser, "a\x00b"},
		{"usuário com NUL", stateRequest(), "a\x00b", testPassword},
		{"pedido que não serializa", map[string]any{"f": func() {}}, testUser, testPassword},
	}
	for _, c := range cases {
		_, err := r.Run(context.Background(), c.req, c.user, c.password)
		var fe *Error
		if !errors.As(err, &fe) || fe.Code != contract.ErrorInternal {
			t.Errorf("%s: esperava internal_error sem executar, veio %v", c.name, err)
		}
		if err != nil && strings.Contains(err.Error(), testPassword) {
			t.Errorf("%s: o erro vazou a senha", c.name)
		}
	}
	empty := &Runner{}
	_, err := empty.Run(context.Background(), stateRequest(), testUser, testPassword)
	wantCode(t, err, contract.ErrorInternal)
}

func TestExecutavelInexistenteEUnavailable(t *testing.T) {
	r := &Runner{Command: []string{filepath.Join(t.TempDir(), "nao-existe")}}
	_, err := r.Run(context.Background(), stateRequest(), testUser, testPassword)
	if fe := wantCode(t, err, contract.ErrorUnavailable); strings.Contains(fe.Error(), testPassword) {
		t.Fatalf("o erro vazou a senha: %v", fe)
	}
}

func containsEnv(env []string, kv string) bool {
	for _, e := range env {
		if e == kv {
			return true
		}
	}
	return false
}
