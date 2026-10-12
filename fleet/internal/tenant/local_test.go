package tenant

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/williamsouzadelima/suricatoos-infra/fleet/contract"
)

const pwLocal = "senha-local-ficticia"

type localEnv struct {
	passwordFile string
	cfg          Config
}

func newLocalEnv(t *testing.T) *localEnv {
	t.Helper()
	e := &localEnv{passwordFile: filepath.Join(t.TempDir(), "gvm-tenant.pass")}
	e.setPassword(t, pwLocal)
	e.cfg = Config{
		Tenant:          "acme",
		Scope:           "192.0.2.0/24 198.51.100.0/24",
		GVMUser:         "tenant-acme",
		GVMPasswordFile: e.passwordFile,
	}
	return e
}

func (e *localEnv) setPassword(t *testing.T, content string) {
	t.Helper()
	if err := os.WriteFile(e.passwordFile, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func (e *localEnv) open(t *testing.T, kind contract.NodeKind) Source {
	t.Helper()
	src, err := Open(kind, e.cfg)
	if err != nil {
		t.Fatal(err)
	}
	return src
}

func TestLocalCaminhosDaLinha6(t *testing.T) {
	for _, kind := range []contract.NodeKind{contract.NodeStandalone, contract.NodeSensor} {
		t.Run(string(kind), func(t *testing.T) {
			e := newLocalEnv(t)
			src := e.open(t, kind)
			const scope = "192.0.2.0/24 198.51.100.0/24"
			cases := []struct {
				name   string
				tenant string
				typ    contract.CommandType
				ok     bool
				why    Why
				scope  string
				user   string
			}{
				{"o único tenant, leitura", "acme", contract.TypeTaskStart, true, "", scope, "tenant-acme"},
				{"o único tenant, escrita com usuário e senha", "acme", contract.TypeTaskCreate, true, "", scope, "tenant-acme"},
				{"outro tenant, leitura", "globex", contract.TypeTaskStart, false, WhyUnknown, "", ""},
				{"outro tenant, escrita", "globex", contract.TypeTaskCreate, false, WhyUnknown, "", ""},
				{"caixa diferente é outro tenant", "Acme", contract.TypeTaskStart, false, WhyUnknown, "", ""},
				{"prefixo não basta", "acme2", contract.TypeTaskStart, false, WhyUnknown, "", ""},
				{"vazio", "", contract.TypeTaskStart, false, WhyUnknown, "", ""},
			}
			for _, c := range cases {
				st := resolve(t, src, c.tenant, c.typ)
				if st.OK != c.ok || st.Why != c.why || st.Scope != c.scope || st.GVMUser != c.user {
					t.Errorf("%s: Resolve(%q, %s) = %+v, esperava ok=%v why=%q scope=%q gvm_user=%q", c.name, c.tenant, c.typ, st, c.ok, c.why, c.scope, c.user)
				}
			}
		})
	}
}

func TestLocalEscritaExigeUsuarioEArquivoDeSenhaLegivel(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(t *testing.T, e *localEnv)
		why    Why
	}{
		{"sem FLEET_TENANT_GMP_USER", func(t *testing.T, e *localEnv) { e.cfg.GVMUser = "" }, WhyNoGVMUser},
		{"sem FLEET_TENANT_GMP_PASSWORD_FILE", func(t *testing.T, e *localEnv) { e.cfg.GVMPasswordFile = "" }, WhyNoSecret},
		{"arquivo de senha ausente", func(t *testing.T, e *localEnv) { os.Remove(e.passwordFile) }, WhyNoSecret},
		{"arquivo de senha vazio", func(t *testing.T, e *localEnv) { e.setPassword(t, "") }, WhyNoSecret},
		{"arquivo só com quebra de linha", func(t *testing.T, e *localEnv) { e.setPassword(t, "\r\n") }, WhyNoSecret},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newLocalEnv(t)
			c.mutate(t, e)
			src := e.open(t, contract.NodeStandalone)
			if st := resolve(t, src, "acme", contract.TypeTargetCreate); st.OK || st.Why != c.why {
				t.Fatalf("escrita: %+v, esperava why=%q", st, c.why)
			}
			// leitura e tipos sem usuário gvmd seguem passando
			for _, typ := range []contract.CommandType{contract.TypeTaskStart, contract.TypeStateResync, contract.TypeFeedSyncNow} {
				if st := resolve(t, src, "acme", typ); !st.OK {
					t.Errorf("%s: %+v", typ, st)
				}
			}
			// o usuário configurado continua exposto (o executor confere o dono dos objetos "atual"), com ou sem senha
			if want := e.cfg.GVMUser; want != "" {
				if st := resolve(t, src, "acme", contract.TypeTaskStart); st.GVMUser != want {
					t.Errorf("GVMUser = %q, esperava %q", st.GVMUser, want)
				}
			}
			if _, err := src.Credentials("acme"); !errors.Is(err, ErrNoCredentials) {
				t.Errorf("Credentials: esperava ErrNoCredentials, deu %v", err)
			}
		})
	}
}

func TestLocalArquivoDeSenhaIlegivelEErroSoNaEscrita(t *testing.T) {
	e := newLocalEnv(t)
	if err := os.Remove(e.passwordFile); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(e.passwordFile, 0o700); err != nil { // presente e ilegível
		t.Fatal(err)
	}
	src := e.open(t, contract.NodeSensor)
	if st := resolve(t, src, "acme", contract.TypeTaskStart); !st.OK {
		t.Fatalf("a leitura não consulta a senha: %+v", st)
	}
	st, err := src.Resolve("acme", contract.TypeTaskCreate)
	if err == nil || st.OK {
		t.Fatalf("escrita com senha ilegível: %+v, %v", st, err)
	}
	if _, err := src.Credentials("acme"); err == nil || errors.Is(err, ErrNoCredentials) {
		t.Fatalf("Credentials com senha ilegível deveria ser erro de leitura: %v", err)
	}
}

func TestLocalArquivoDeSenhaGrandeDemaisEErro(t *testing.T) {
	e := newLocalEnv(t)
	e.setPassword(t, strings.Repeat("a", maxPasswordFileBytes+1))
	if _, err := e.open(t, contract.NodeStandalone).Resolve("acme", contract.TypeTaskCreate); err == nil {
		t.Fatal("arquivo de senha acima do teto tinha de ser erro")
	}
}

func TestLocalCredentials(t *testing.T) {
	e := newLocalEnv(t)
	src := e.open(t, contract.NodeStandalone)
	creds, err := src.Credentials("acme")
	if err != nil {
		t.Fatal(err)
	}
	if creds.User != "tenant-acme" || creds.Password.Reveal() != pwLocal {
		t.Fatalf("credenciais locais: user %q", creds.User)
	}
	if _, err := src.Credentials("globex"); !errors.Is(err, ErrNoCredentials) {
		t.Fatalf("outro tenant: %v", err)
	}
}

func TestLocalSenhaSemAQuebraDeLinhaFinal(t *testing.T) {
	// `echo senha > arquivo` deixa um \n (ou \r\n) no fim; o gvmd autenticaria com ele e falharia
	for _, content := range []string{pwLocal, pwLocal + "\n", pwLocal + "\r\n", pwLocal + "\n\n"} {
		e := newLocalEnv(t)
		e.setPassword(t, content)
		creds, err := e.open(t, contract.NodeStandalone).Credentials("acme")
		if err != nil || creds.Password.Reveal() != pwLocal {
			t.Errorf("conteúdo %q: %v", content, err)
		}
	}
	// espaços e quebras no meio fazem parte da senha
	e := newLocalEnv(t)
	e.setPassword(t, " a b\tc \n")
	creds, err := e.open(t, contract.NodeStandalone).Credentials("acme")
	if err != nil || creds.Password.Reveal() != " a b\tc " {
		t.Errorf("espaços internos e nas pontas ficam: %q %v", creds.Password.Reveal(), err)
	}
}

func TestLocalReleituraDaSenha(t *testing.T) {
	e := newLocalEnv(t)
	src := e.open(t, contract.NodeStandalone)
	e.setPassword(t, "senha-rotacionada-ficticia")
	creds, err := src.Credentials("acme")
	if err != nil || creds.Password.Reveal() != "senha-rotacionada-ficticia" {
		t.Fatalf("a senha trocada vale já: %v", err)
	}
	if err := os.Remove(e.passwordFile); err != nil {
		t.Fatal(err)
	}
	if st := resolve(t, src, "acme", contract.TypeTaskCreate); st.OK || st.Why != WhyNoSecret {
		t.Fatalf("sem o arquivo: %+v", st)
	}
}

func TestLocalEscopoVoltaComoTexto(t *testing.T) {
	e := newLocalEnv(t)
	e.cfg.Scope = "192.0.2.0/25,  198.51.100.0/25\t203.0.113.7"
	if st := resolve(t, e.open(t, contract.NodeSensor), "acme", contract.TypeTaskStart); st.Scope != e.cfg.Scope {
		t.Fatalf("FLEET_SCAN_SCOPE tem de sair como veio: %q", st.Scope)
	}
}

func TestOpenLocalValidaAConfiguracao(t *testing.T) {
	e := newLocalEnv(t)
	for _, kind := range []contract.NodeKind{contract.NodeStandalone, contract.NodeSensor} {
		if _, err := Open(kind, e.cfg); err != nil {
			t.Errorf("%s: %v", kind, err)
		}
		bad := map[string]Config{
			"sem FLEET_TENANT":                 {Scope: e.cfg.Scope},
			"tenant com espaço":                {Tenant: "acme corp"},
			"tenant com barra":                 {Tenant: "acme/x"},
			"tenant começando por ponto":       {Tenant: ".acme"},
			"tenant longo demais":              {Tenant: strings.Repeat("a", 65)},
			"tenant com caractere de controle": {Tenant: "acme\n"},
		}
		for name, cfg := range bad {
			if _, err := Open(kind, cfg); err == nil {
				t.Errorf("%s, %s: tinha de ser erro", kind, name)
			}
		}
	}
	// no limite do padrão do schema
	if _, err := Open(contract.NodeSensor, Config{Tenant: strings.Repeat("a", 64)}); err != nil {
		t.Errorf("64 caracteres é válido: %v", err)
	}
	if _, err := Open(contract.NodeSensor, Config{Tenant: "a.b_c-d1"}); err != nil {
		t.Errorf("ponto, sublinhado e hífen são válidos: %v", err)
	}
}
