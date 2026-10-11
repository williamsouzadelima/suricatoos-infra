package installcmd

import (
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"testing"
)

// Valores no formato real: URL do control-plane (CONTROL_PLANE_URL), token
// "st_<id>.<segredo>" (base64url) e pin da CA.
const (
	testServer = "https://scanner.suricatoos.com/agent/v1"
	testToken  = "st_AbC123.xyz-9_Q"
	testPin    = "sha256:0a1b2c"
)

// between devolve o trecho de s entre a primeira ocorrencia de a e a seguinte de b.
func between(t *testing.T, s, a, b string) string {
	t.Helper()
	i := strings.Index(s, a)
	if i < 0 {
		t.Fatalf("%q nao aparece em %q", a, s)
	}
	i += len(a)
	j := strings.Index(s[i:], b)
	if j < 0 {
		t.Fatalf("%q nao aparece depois de %q em %q", b, a, s)
	}
	return s[i : i+j]
}

// Forma exata do comando do Windows. provision e enrollcmd usam este construtor, entao
// e esta string que o operador cola.
func TestWindowsExactForm(t *testing.T) {
	got, err := Windows(testServer, testToken, testPin)
	if err != nil {
		t.Fatal(err)
	}
	const want = `powershell -ExecutionPolicy Bypass -Command "iwr -useb https://scanner.suricatoos.com/install.ps1 ` +
		`-OutFile (Join-Path (Get-Item env:TEMP).Value 'suricatoos-install.ps1'); ` +
		`& (Join-Path (Get-Item env:TEMP).Value 'suricatoos-install.ps1') ` +
		`-Server 'https://scanner.suricatoos.com/agent/v1' -Token 'st_AbC123.xyz-9_Q' -CaPin 'sha256:0a1b2c'"`
	if got != want {
		t.Errorf("forma do comando Windows mudou:\n got: %s\nwant: %s", got, want)
	}
}

// As invariantes que fazem o comando do Windows funcionar e ser seguro. Cada uma foi
// conferida contra o Windows PowerShell 5.1 real (colado no PowerShell e no cmd.exe).
func TestWindowsCommandInvariants(t *testing.T) {
	cmd, err := Windows(testServer, testToken, testPin)
	if err != nil {
		t.Fatal(err)
	}

	// 1. Nada para o shell de FORA expandir. A linha e colada num prompt qualquer e o
	// -Command vai entre aspas duplas: um PowerShell externo expande '$f' / '$env:TEMP'
	// antes de o powershell interno rodar ("=Join-Path ..." e -OutFile vazio), e o
	// cmd.exe expande '%VAR%'.
	if strings.ContainsAny(cmd, "$`%") {
		t.Errorf("o comando nao pode ter '$', crase nem '%%' (o shell de fora expande ao colar):\n%s", cmd)
	}

	// 2. So as duas aspas duplas do -Command: nenhum valor consegue fechar o literal
	// antes da hora.
	if n := strings.Count(cmd, `"`); n != 2 {
		t.Errorf("o comando deveria ter exatamente 2 aspas duplas (as do -Command), tem %d:\n%s", n, cmd)
	}

	// 3. Nenhum caminho fixo (letra de unidade + barra invertida). O instalador vai para
	// o TEMP de quem roda o comando, nunca para uma pasta que outros usuarios escrevem
	// (C:\Windows\Temp aceita arquivos de qualquer usuario local: pre-criar ou trocar o
	// arquivo entre o download e a execucao elevada).
	if regexp.MustCompile(`(?i)[a-z]:\\`).MatchString(cmd) {
		t.Errorf("o comando nao pode ter caminho fixo:\n%s", cmd)
	}

	// 4. O mesmo caminho para baixar (-OutFile) e para executar (&), resolvido por
	// cmdlets (Get-Item env:TEMP): os metodos estaticos do .NET ([IO.Path]::GetTempPath())
	// sao recusados no Constrained Language Mode, os cmdlets nao.
	dl := between(t, cmd, "-OutFile ", "; & ")
	run := between(t, cmd, "; & ", " -Server ")
	if dl != run {
		t.Errorf("baixa para um caminho e executa outro:\n-OutFile %s\n& %s", dl, run)
	}
	if !strings.Contains(dl, "(Get-Item env:TEMP).Value") {
		t.Errorf("o caminho deveria vir do TEMP do usuario via cmdlet, got %s", dl)
	}
	if strings.Contains(cmd, "::") {
		t.Errorf("sem metodos estaticos do .NET (bloqueados no Constrained Language Mode):\n%s", cmd)
	}

	// 5. A expressao do caminho vai entre parenteses: no modo de argumento do PowerShell
	// um token solto e texto literal, e "-OutFile Join-Path ..." cai em
	// PositionalParameterNotFound.
	if !strings.HasPrefix(dl, "(") || !strings.HasSuffix(dl, ")") {
		t.Errorf("a expressao do caminho precisa estar entre parenteses, got %s", dl)
	}

	// 6. O install.ps1 sai do mesmo host do servidor.
	if !strings.Contains(cmd, "iwr -useb https://scanner.suricatoos.com/install.ps1 ") {
		t.Errorf("deveria baixar o install.ps1 do host do servidor:\n%s", cmd)
	}
}

// Os tres valores entram entre aspas simples, dentro das aspas duplas do -Command: tres
// contextos com regras de escape diferentes (PowerShell externo, cmd.exe, PowerShell
// interno). Em vez de escapar para cada um, so passa o alfabeto que nao precisa de escape
// em nenhum; o resto e recusado, sem devolver comando.
func TestWindowsRefusesValuesTheShellsWouldInterpret(t *testing.T) {
	hostile := []string{
		`a"b`, "a$b", "$(calc)", "a`b", "%TEMP%", "a'b", "a b", "a\tb", "a\nb", "a\rb",
		"a;b", "a&b", "a|b", "a(b", "a)b", "a<b", "a>b", "a^b", "a!b", "a*b", "a?b",
		"a#b", "a@b", "a=b", "a+b", "a,b", "a[b", "a]b", "a{b", "a}b", `a\b`, "a~b",
		"a\u2019b", "a\u201cb", "a\u00e7\u00e3o", "a\x00b",
	}
	fields := map[string]func(v string) (string, error){
		"token":    func(v string) (string, error) { return Windows(testServer, v, testPin) },
		"pin":      func(v string) (string, error) { return Windows(testServer, testToken, v) },
		"servidor": func(v string) (string, error) { return Windows(testServer+v, testToken, testPin) },
	}
	for _, v := range hostile {
		for name, call := range fields {
			got, err := call(v)
			if !errors.Is(err, ErrUnsafeValue) {
				t.Errorf("%s=%q: err=%v, queria ErrUnsafeValue", name, v, err)
			}
			if got != "" {
				t.Errorf("%s=%q: devolveu comando apesar do erro: %s", name, v, got)
			}
		}
	}

	// O erro nunca carrega o valor recusado (o token e segredo).
	_, err := Windows(testServer, "st_SEGREDO$x", testPin)
	if err == nil || strings.Contains(err.Error(), "SEGREDO") {
		t.Errorf("o erro nao pode conter o valor recusado, got %v", err)
	}
}

// Sem URL de servidor utilizavel nao ha comando: antes saia "curl -fsSL /install.sh"
// ou "iwr -useb /install.ps1", que nao funciona e nao diz por que.
func TestRefusesUnusableServerURL(t *testing.T) {
	for _, server := range []string{
		"", "scanner.suricatoos.com/agent/v1", "https://", "https:///agent/v1",
		"//scanner.suricatoos.com/agent/v1", "ftp://scanner.suricatoos.com/agent/v1",
	} {
		if got, err := Windows(server, testToken, testPin); !errors.Is(err, ErrServerURL) || got != "" {
			t.Errorf("Windows(%q) = %q, %v; queria ErrServerURL", server, got, err)
		}
		if got, err := Unix(server, testToken, testPin); !errors.Is(err, ErrServerURL) || got != "" {
			t.Errorf("Unix(%q) = %q, %v; queria ErrServerURL", server, got, err)
		}
	}
	// URL que nem passa no parser tambem.
	if got, err := Unix("https://exa mple.com/agent/v1", testToken, testPin); !errors.Is(err, ErrServerURL) || got != "" {
		t.Errorf("Unix(url invalida) = %q, %v; queria ErrServerURL", got, err)
	}
}

func TestPublicBase(t *testing.T) {
	for in, want := range map[string]string{
		"https://scanner.suricatoos.com/agent/v1":       "https://scanner.suricatoos.com",
		"https://scanner.suricatoos.com":                "https://scanner.suricatoos.com",
		"https://scanner.suricatoos.com/":               "https://scanner.suricatoos.com",
		"http://10.0.0.5:8080/agent/v1":                 "http://10.0.0.5:8080",
		"HTTPS://scanner.suricatoos.com/agent/v1":       "https://scanner.suricatoos.com",
		"https://u:senha@scanner.suricatoos.com/x":      "https://scanner.suricatoos.com", // credencial nunca vai para o comando
		"https://scanner.suricatoos.com/agent/v1?a=1#f": "https://scanner.suricatoos.com",
		"":                                  "",
		"scanner.suricatoos.com/agent/v1":   "",
		"ftp://scanner.suricatoos.com/x":    "",
		"https://":                          "",
		"https:///agent/v1":                 "",
		"//scanner.suricatoos.com/agent/v1": "",
		"http://[::1":                       "",
	} {
		if got := PublicBase(in); got != want {
			t.Errorf("PublicBase(%q) = %q, want %q", in, got, want)
		}
	}
}

// Linux e macOS: o install.sh escolhe o binario por 'uname -s'.
func TestUnixExactForm(t *testing.T) {
	got, err := Unix(testServer, testToken, testPin)
	if err != nil {
		t.Fatal(err)
	}
	const want = `curl -fsSL https://scanner.suricatoos.com/install.sh | sudo sh -s -- ` +
		`--server https://scanner.suricatoos.com/agent/v1 --token st_AbC123.xyz-9_Q --ca-pin sha256:0a1b2c`
	if got != want {
		t.Errorf("forma do comando Unix mudou:\n got: %s\nwant: %s", got, want)
	}
}

// Para valores reais a saida e byte a byte a do codigo anterior (que vivia duplicado em
// provision e enrollcmd): so entrou protecao para o que antes passava cru.
func TestUnixUnchangedForRealValues(t *testing.T) {
	for _, c := range []struct{ server, token, pin string }{
		{testServer, testToken, testPin},
		{"http://10.0.0.5:8080/agent/v1", "st_Zz09-_aa.Zz09-_bb", "sha256:" + strings.Repeat("ab12", 16)},
		{"https://scanner.suricatoos.com", testToken, ""},
	} {
		pin := c.pin
		if pin == "" {
			pin = "''" // o codigo anterior ja citava o pin vazio
		}
		want := fmt.Sprintf("curl -fsSL %s/install.sh | sudo sh -s -- --server %s --token %s --ca-pin %s",
			PublicBase(c.server), c.server, c.token, pin)
		got, err := Unix(c.server, c.token, c.pin)
		if err != nil {
			t.Fatalf("%+v: %v", c, err)
		}
		if got != want {
			t.Errorf("saida mudou para valores reais:\n got: %s\nwant: %s", got, want)
		}
	}
}

// Valores fora do alfabeto seguro vao entre aspas simples: o shell recebe cada um como UMA
// palavra, sem executar nada.
func TestUnixQuotesHostileValues(t *testing.T) {
	got, err := Unix(testServer+"$(evil)", "x;echo pwned", "it's a pin")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`--server 'https://scanner.suricatoos.com/agent/v1$(evil)'`,
		`--token 'x;echo pwned'`,
		`--ca-pin 'it'\''s a pin'`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("comando nao contem %q:\n%s", want, got)
		}
	}
}

func TestShellQuote(t *testing.T) {
	for in, want := range map[string]string{
		"":                   `''`,
		"plain":              "plain",
		"sha256:0a1b2c":      "sha256:0a1b2c",
		"https://h/agent/v1": "https://h/agent/v1",
		"st_a.b-c":           "st_a.b-c",
		"a b":                `'a b'`,
		"it's":               `'it'\''s'`,
		"$(id)":              `'$(id)'`,
		"a;b":                `'a;b'`,
	} {
		if got := ShellQuote(in); got != want {
			t.Errorf("ShellQuote(%q) = %s, want %s", in, got, want)
		}
	}
}

// A prova do "seguro": um shell POSIX de verdade recebe cada valor como UMA palavra,
// identica a original.
func TestShellQuoteRoundTripsThroughRealSh(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("sh indisponivel neste ambiente")
	}
	for i, v := range []string{
		"", "plain", "a b", "it's", `a"b`, "$(id)", "`id`", "a;b", "a&b", "a|b", "a\nb",
		"a\u00e7\u00e3o", "-n", "--flag", "~", "*", `a\b`, "x'; echo pwned; '", "$HOME", "!!",
	} {
		out, err := exec.Command(sh, "-c", "printf %s "+ShellQuote(v)).Output()
		var exit *exec.ExitError
		if err != nil && !errors.As(err, &exit) {
			t.Skipf("sh nao executa neste ambiente: %v", err)
		}
		if err != nil {
			t.Errorf("caso %d (%q): sh falhou: %v", i, v, err)
			continue
		}
		if string(out) != v {
			t.Errorf("caso %d: sh recebeu %q, queria %q (citado: %s)", i, out, v, ShellQuote(v))
		}
	}
}
