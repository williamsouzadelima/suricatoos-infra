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
	const want = `powershell -NoProfile -ExecutionPolicy Bypass -Command "` +
		`if ((Get-Item env:TEMP).Value -like '*\Windows\Temp*') { throw 'Nao rode como SYSTEM: use o install.ps1 com -File a partir de uma pasta protegida' }; ` +
		`if (iwr -useb https://scanner.suricatoos.com/install.ps1 -PassThru -OutFile (Join-Path (Get-Item env:TEMP).Value 'suricatoos-install.ps1')) ` +
		`{ & (Join-Path (Get-Item env:TEMP).Value 'suricatoos-install.ps1') ` +
		`-Server 'https://scanner.suricatoos.com/agent/v1' -Token 'st_AbC123.xyz-9_Q' -CaPin 'sha256:0a1b2c' }"`
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
	dl := between(t, cmd, "-OutFile ", ") { & ")
	run := between(t, cmd, ") { & ", " -Server ")
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

	// 7. Fecha em falha. Com "iwr ...; & caminho" um download que falha (recusado, 404,
	// cortado) seguia para o '&' e executava o arquivo velho ou plantado que estivesse no
	// caminho, entregando o token a ele (reproduzido no PowerShell 5.1 real). Aqui o download
	// e a CONDICAO de um 'if' ('-PassThru' faz o sucesso virar verdadeiro) e a chamada so
	// existe no corpo dele.
	if n := strings.Count(cmd, "&"); n != 1 {
		t.Errorf("deveria haver um unico '&' (a chamada do instalador), ha %d:\n%s", n, cmd)
	}
	cond := between(t, cmd, "if (iwr ", ") { & ")
	if !strings.Contains(cond, " -PassThru ") {
		t.Errorf("sem -PassThru o download nao devolve nada e o 'if' nunca executa o corpo:\n%s", cmd)
	}
	if strings.Contains(cond, ";") {
		t.Errorf("nada pode separar o download do corpo do 'if':\n%s", cmd)
	}
	if body := cmd[strings.Index(cmd, "{ & "):]; !strings.HasSuffix(body, ` }"`) || strings.Contains(body, ";") {
		t.Errorf("o corpo do 'if' deve ser a unica coisa depois do download, e so a chamada:\n%s", cmd)
	}

	// 8. Guarda contra o TEMP do sistema, ANTES de qualquer download. Rodando como SYSTEM
	// (RMM, PsExec -s) o TEMP e C:\Windows\Temp, onde qualquer usuario local cria arquivos:
	// o comando recusa em vez de so documentar. Unica mencao a esse caminho no comando.
	guard := between(t, cmd, `-Command "`, "; if (iwr ")
	for _, want := range []string{"(Get-Item env:TEMP).Value", `-like '*\Windows\Temp*'`, "throw '"} {
		if !strings.Contains(guard, want) {
			t.Errorf("a guarda deveria conter %q, got %s", want, guard)
		}
	}
	if strings.Count(cmd, `Windows\Temp`) != 1 {
		t.Errorf("C:\\Windows\\Temp so pode aparecer na guarda:\n%s", cmd)
	}

	// 9. -NoProfile no powershell interno e elevado: nada do perfil do usuario roda com
	// privilegio.
	if !strings.HasPrefix(cmd, "powershell -NoProfile -ExecutionPolicy Bypass -Command ") {
		t.Errorf("deveria comecar por 'powershell -NoProfile -ExecutionPolicy Bypass -Command':\n%s", cmd)
	}

	// 10. So ASCII (a linha passa por terminais com paginas de codigo diversas) e nenhuma
	// barra invertida antes de aspas duplas (na linha de comando do Windows ela escapa a aspa).
	for i := 0; i < len(cmd); i++ {
		if cmd[i] > 127 {
			t.Errorf("o comando deve ser ASCII, byte %d = 0x%x:\n%s", i, cmd[i], cmd)
			break
		}
	}
	if strings.Contains(cmd, `\"`) {
		t.Errorf("nenhuma barra invertida pode vir antes de aspas duplas:\n%s", cmd)
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

// A validacao previa (antes de mintar token) concorda com os construtores: o que
// CheckWindows/CheckUnix recusam, Windows/Unix recusam, com o mesmo erro, e vice-versa. O
// token vem do gerador e sempre cabe; por isso a checagem previa so olha URL e pin.
func TestCheckAgreesWithBuilders(t *testing.T) {
	for _, c := range []struct{ server, pin string }{
		{testServer, testPin},
		{"https://scanner.suricatoos.com:8443/agent/v1", testPin},
		{"http://10.0.0.5:8080/agent/v1", "sha256:" + strings.Repeat("ab12", 16)},
		{"https://scanner.suricatoos.com", ""},
		{testServer + "$(evil)", testPin},
		{testServer + "?a=1", testPin},
		{testServer, "sha256:0a 1b"},
		{testServer, "sha256:ç"},
		{"", testPin},
		{"scanner.suricatoos.com/agent/v1", testPin},
		{"ftp://scanner.suricatoos.com/agent/v1", testPin},
		{"https://", testPin},
		{"http://[::1]:8080/agent/v1", testPin},
	} {
		_, werr := Windows(c.server, testToken, c.pin)
		if cerr := CheckWindows(c.server, c.pin); cerr != werr {
			t.Errorf("CheckWindows(%q, %q) = %v, mas Windows(...) = %v", c.server, c.pin, cerr, werr)
		}
		_, uerr := Unix(c.server, testToken, c.pin)
		if cerr := CheckUnix(c.server); cerr != uerr {
			t.Errorf("CheckUnix(%q) = %v, mas Unix(...) = %v", c.server, cerr, uerr)
		}
	}
}

// Um aviso so, de uma linha, para o log de inicializacao: diz o que a config nao consegue
// montar e o que segue funcionando, sem repetir os valores configurados.
func TestWarning(t *testing.T) {
	if w := Warning(testServer, testPin); w != "" {
		t.Errorf("config sa nao deveria avisar, got %q", w)
	}
	for name, c := range map[string]struct{ server, pin, mention string }{
		"URL sem host":        {"scanner.suricatoos.com/agent/v1", testPin, "http(s)://host"},
		"URL com caractere":   {testServer + "?a=1", testPin, "[A-Za-z0-9._:/-]"},
		"pin com caractere":   {testServer, "sha256:0a 1b", "[A-Za-z0-9._:/-]"},
		"URL IPv6 (colchete)": {"http://[::1]:8080/agent/v1", testPin, "[A-Za-z0-9._:/-]"},
	} {
		w := Warning(c.server, c.pin)
		if w == "" {
			t.Errorf("%s: deveria avisar", name)
			continue
		}
		if strings.ContainsAny(w, "\r\n") {
			t.Errorf("%s: o aviso deve ser uma linha so, got %q", name, w)
		}
		if !strings.Contains(w, c.mention) {
			t.Errorf("%s: o aviso deveria citar %q, got %q", name, c.mention, w)
		}
		for _, v := range []string{c.server, c.pin} {
			if v != "" && strings.Contains(w, v) {
				t.Errorf("%s: o aviso nao pode repetir o valor configurado %q: %q", name, v, w)
			}
		}
	}
	// So o Windows e afetado por caractere fora do alfabeto: o aviso diz que o resto segue.
	if w := Warning(testServer+"?a=1", testPin); !strings.Contains(w, "Windows") || !strings.Contains(w, "seguem") {
		t.Errorf("o aviso deveria dizer que so o Windows fica sem comando, got %q", w)
	}
	// URL sem host: nenhum comando de instalacao existe.
	if w := Warning("", testPin); !strings.Contains(w, "linux") || !strings.Contains(w, "Windows") {
		t.Errorf("o aviso deveria dizer que nenhum SO tem comando, got %q", w)
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
