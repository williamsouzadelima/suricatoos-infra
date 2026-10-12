package tenant

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/williamsouzadelima/suricatoos-infra/fleet/contract"
)

const (
	pwAcme    = "senha-acme-ficticia"
	pwInitech = "senha-initech-ficticia"
	pwGlobex  = "senha-globex-ficticia"
)

// centralEnv is a TENANTS_FILE and a SENSOR_TENANT_SECRETS in a temp dir, filled from the shared fixture.
type centralEnv struct {
	dir     string
	tenants string
	secrets string
}

func newCentralEnv(t *testing.T) *centralEnv {
	t.Helper()
	dir := t.TempDir()
	e := &centralEnv{dir: dir, tenants: filepath.Join(dir, "tenants.json"), secrets: filepath.Join(dir, "tenant-gvmd-secrets.json")}
	fixture, err := os.ReadFile(filepath.Join("testdata", "tenants.json"))
	if err != nil {
		t.Fatal(err)
	}
	e.write(t, e.tenants, string(fixture))
	// umbrella tem usuário gvmd no registro e NÃO tem senha; globex tem senha mas não tem usuário
	e.write(t, e.secrets, `{"acme":"`+pwAcme+`","initech":"`+pwInitech+`","globex":"`+pwGlobex+`"}`)
	return e
}

func (e *centralEnv) write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func (e *centralEnv) open(t *testing.T) Source {
	t.Helper()
	src, err := Open(contract.NodeCentral, Config{TenantsFile: e.tenants, SecretsFile: e.secrets})
	if err != nil {
		t.Fatal(err)
	}
	return src
}

func resolve(t *testing.T, src Source, name string, typ contract.CommandType) Standing {
	t.Helper()
	st, err := src.Resolve(name, typ)
	if err != nil {
		t.Fatalf("Resolve(%q, %s): %v", name, typ, err)
	}
	return st
}

func TestCentralCaminhosDaLinha6(t *testing.T) {
	e := newCentralEnv(t)
	src := e.open(t)
	cases := []struct {
		name   string
		tenant string
		typ    contract.CommandType
		ok     bool
		why    Why
		scope  string
		user   string // o usuário gvmd do tenant, sempre que ele é conhecido e habilitado
	}{
		{"conhecido e habilitado, operação de leitura", "acme", contract.TypeTaskStart, true, "", "192.0.2.0/24, 198.51.100.0/24", "tenant-acme"},
		{"conhecido e habilitado, escrita com usuário e segredo", "acme", contract.TypeTaskCreate, true, "", "192.0.2.0/24, 198.51.100.0/24", "tenant-acme"},
		{"desconhecido", "nope", contract.TypeTaskStart, false, WhyUnknown, "", ""},
		{"desconhecido também na escrita", "nope", contract.TypeTargetCreate, false, WhyUnknown, "", ""},
		{"caixa diferente é outro tenant", "ACME", contract.TypeTaskStart, false, WhyUnknown, "", ""},
		{"desabilitado, leitura", "initech", contract.TypeStateResync, false, WhyDisabled, "", ""},
		{"desabilitado, escrita (tem usuário e segredo)", "initech", contract.TypeTaskCreate, false, WhyDisabled, "", ""},
		{"sem usuário gvmd: leitura passa", "globex", contract.TypeTaskStop, true, "", "203.0.113.0/24", ""},
		{"sem usuário gvmd: escrita não", "globex", contract.TypeTargetModify, false, WhyNoGVMUser, "203.0.113.0/24", ""},
		// o executor precisa do nome do dono dos objetos nos tipos "atual", mesmo sem a senha do tenant
		{"com usuário e sem segredo: leitura passa", "umbrella", contract.TypeReportExport, true, "", "", "tenant-umbrella"},
		{"com usuário e sem segredo: escrita não", "umbrella", contract.TypeScheduleCreate, false, WhyNoSecret, "", "tenant-umbrella"},
		{"tipo sem usuário gvmd (API do control-plane) só pede tenant conhecido", "globex", contract.TypeSensorJobEnqueue, true, "", "203.0.113.0/24", ""},
		{"tipo sem usuário gvmd, tenant desconhecido", "nope", contract.TypeAgentScanNow, false, WhyUnknown, "", ""},
		{"tipo fora do catálogo não exige escrita: o veredito é da linha 7", "globex", "task.explode", true, "", "203.0.113.0/24", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			st := resolve(t, src, c.tenant, c.typ)
			if st.OK != c.ok || st.Why != c.why || st.Scope != c.scope || st.GVMUser != c.user {
				t.Fatalf("Resolve(%q, %s) = %+v, esperava ok=%v why=%q scope=%q gvm_user=%q", c.tenant, c.typ, st, c.ok, c.why, c.scope, c.user)
			}
		})
	}
}

// O Standing leva o nome do usuário gvmd e nunca a senha, em nenhum campo nem na impressão.
func TestStandingNaoCarregaASenha(t *testing.T) {
	e := newCentralEnv(t)
	st := resolve(t, e.open(t), "acme", contract.TypeTaskCreate) // tem usuário e senha, e a escrita passa
	if !st.OK || st.GVMUser != "tenant-acme" {
		t.Fatalf("%+v", st)
	}
	for _, verb := range []string{"%v", "%+v", "%#v"} {
		if out := fmt.Sprintf(verb, st); strings.Contains(out, pwAcme) {
			t.Errorf("%s do Standing vazou a senha: %s", verb, out)
		}
	}
}

func TestCentralEscopoVoltaComoTextoSemInterpretar(t *testing.T) {
	// quem interpreta o escopo é o scopegate (F2.4a); aqui ele sai exatamente como o registro o guarda
	e := newCentralEnv(t)
	for _, scope := range []string{
		"192.0.2.0/25 198.51.100.0/25,  203.0.113.0/24\t192.0.2.200",
		"192.0.2.0/24,198.51.100.0/24",
		"isto nem é CIDR",
		"",
	} {
		rec, err := json.Marshal([]map[string]any{{"name": "acme", "scope": scope, "gmp_user": "tenant-acme", "enabled": true}})
		if err != nil {
			t.Fatal(err)
		}
		e.write(t, e.tenants, string(rec))
		if st := resolve(t, e.open(t), "acme", contract.TypeTaskStart); !st.OK || st.Scope != scope {
			t.Errorf("escopo %q voltou como %q (%+v)", scope, st.Scope, st)
		}
	}
}

func TestCentralTodoTipoDeEscritaExigeUsuarioESegredo(t *testing.T) {
	e := newCentralEnv(t)
	src := e.open(t)
	for _, entry := range contract.Catalog() {
		typ := entry.Type
		write := RunsAs(typ) == UserTenant
		if st := resolve(t, src, "umbrella", typ); st.OK == write {
			t.Errorf("%s (escrita=%v): umbrella tem usuário e não tem segredo, Resolve = %+v", typ, write, st)
		}
		if st := resolve(t, src, "globex", typ); st.OK == write {
			t.Errorf("%s (escrita=%v): globex não tem usuário, Resolve = %+v", typ, write, st)
		}
		if st := resolve(t, src, "acme", typ); !st.OK {
			t.Errorf("%s: acme tem tudo, Resolve = %+v", typ, st)
		}
	}
}

func TestCentralSenhaVaziaNoArquivoNaoContaComoPresente(t *testing.T) {
	e := newCentralEnv(t)
	e.write(t, e.secrets, `{"acme":""}`)
	st := resolve(t, e.open(t), "acme", contract.TypeTaskCreate)
	if st.OK || st.Why != WhyNoSecret {
		t.Fatalf("senha vazia: %+v", st)
	}
}

func TestCentralRegistroAusenteNaoConheceNinguem(t *testing.T) {
	e := newCentralEnv(t)
	if err := os.Remove(e.tenants); err != nil {
		t.Fatal(err)
	}
	st := resolve(t, e.open(t), "acme", contract.TypeTaskStart)
	if st.OK || st.Why != WhyUnknown {
		t.Fatalf("sem registro: %+v", st)
	}
}

func TestCentralSegredosAusentesOuNaoConfigurados(t *testing.T) {
	e := newCentralEnv(t)
	if err := os.Remove(e.secrets); err != nil {
		t.Fatal(err)
	}
	src := e.open(t)
	if st := resolve(t, src, "acme", contract.TypeTaskCreate); st.OK || st.Why != WhyNoSecret {
		t.Fatalf("arquivo de segredos ausente: escrita sem segredo: %+v", st)
	}
	if st := resolve(t, src, "acme", contract.TypeTaskStart); !st.OK {
		t.Fatalf("arquivo de segredos ausente não afeta a leitura: %+v", st)
	}
	// SENSOR_TENANT_SECRETS não definido
	none, err := Open(contract.NodeCentral, Config{TenantsFile: e.tenants})
	if err != nil {
		t.Fatal(err)
	}
	if st := resolve(t, none, "acme", contract.TypeTaskCreate); st.OK || st.Why != WhyNoSecret {
		t.Fatalf("sem SENSOR_TENANT_SECRETS: %+v", st)
	}
}

func TestCentralRegistroInutilizavelEErroENaoVeredito(t *testing.T) {
	cases := []struct{ name, content string }{
		{"json quebrado", `[{"name":"acme"`},
		{"vazio", ``},
		{"não é array", `{"name":"acme"}`},
		{"null", `null`},
		{"membro desconhecido (formato mudou)", `[{"name":"acme","scope":"","gmp_user":"","enabled":true,"suspended":true}]`},
		{"membro com caixa diferente", `[{"Name":"acme","enabled":true}]`},
		{"falta enabled", `[{"name":"acme","scope":"192.0.2.0/24"}]`},
		{"enabled em texto", `[{"name":"acme","enabled":"true"}]`},
		{"enabled nulo", `[{"name":"acme","enabled":null}]`},
		{"nome repetido: o control-plane e o ingest discordam de quem vale, a frota não escolhe", `[{"name":"acme","enabled":true},{"name":"acme","enabled":false}]`},
		{"chave repetida no registro", `[{"name":"acme","enabled":true,"enabled":false}]`},
		{"dado depois do array", `[] []`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newCentralEnv(t)
			e.write(t, e.tenants, c.content)
			st, err := e.open(t).Resolve("acme", contract.TypeTaskStart)
			if err == nil {
				t.Fatalf("registro inutilizável tinha de ser erro (o chamador responde unavailable), deu %+v", st)
			}
			if st.OK {
				t.Fatal("em erro nunca vem OK")
			}
		})
	}
}

func TestCentralRegistroIlegivelOuGrandeDemais(t *testing.T) {
	e := newCentralEnv(t)
	if err := os.Remove(e.tenants); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(e.tenants, 0o700); err != nil { // existe e não é arquivo
		t.Fatal(err)
	}
	if _, err := e.open(t).Resolve("acme", contract.TypeTaskStart); err == nil {
		t.Fatal("registro que é um diretório tinha de ser erro")
	}
	if err := os.Remove(e.tenants); err != nil {
		t.Fatal(err)
	}
	e.write(t, e.tenants, `[]`+strings.Repeat(" ", maxRegistryBytes))
	if _, err := e.open(t).Resolve("acme", contract.TypeTaskStart); err == nil {
		t.Fatal("registro acima do teto tinha de ser erro")
	}
}

func TestCentralRegistroAceitaOQueOControlPlaneEscreve(t *testing.T) {
	e := newCentralEnv(t)
	// membros opcionais ausentes: o registro à mão mais enxuto
	e.write(t, e.tenants, `[{"name":"acme","enabled":true}]`)
	st := resolve(t, e.open(t), "acme", contract.TypeTaskStart)
	if !st.OK || st.Scope != "" {
		t.Fatalf("registro mínimo: %+v", st)
	}
	// e nome vazio não derruba o arquivo (nunca casa com um tenant do envelope)
	e.write(t, e.tenants, `[{"name":"","enabled":true},{"name":"","enabled":true},{"name":"acme","enabled":true}]`)
	if st := resolve(t, e.open(t), "acme", contract.TypeTaskStart); !st.OK {
		t.Fatalf("nome vazio no registro: %+v", st)
	}
}

func TestCentralSegredosInutilizaveisSoAfetamAEscrita(t *testing.T) {
	cases := []struct{ name, content string }{
		{"json quebrado", `{"acme":`},
		{"vazio", ``},
		{"não é objeto", `["acme"]`},
		{"senha em número", `{"acme":123}`},
		{"senha nula", `{"acme":null}`},
		{"chave repetida", `{"acme":"` + pwAcme + `","acme":"outra"}`},
		{"dado depois do objeto", `{} {}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newCentralEnv(t)
			e.write(t, e.secrets, c.content)
			src := e.open(t)
			// a leitura não consulta segredos: segue passando
			if st := resolve(t, src, "acme", contract.TypeTaskStart); !st.OK {
				t.Fatalf("leitura com segredos quebrados: %+v", st)
			}
			// a escrita não sabe se há senha: erro (unavailable), nunca "senha presente"
			st, err := src.Resolve("acme", contract.TypeTaskCreate)
			if err == nil || st.OK {
				t.Fatalf("escrita com segredos quebrados: %+v, %v", st, err)
			}
			if _, err := src.Credentials("acme"); err == nil || errors.Is(err, ErrNoCredentials) {
				t.Fatalf("Credentials com segredos quebrados deveria ser erro de leitura, não 'sem credenciais': %v", err)
			}
		})
	}
}

func TestCentralSegredosIlegiveisEGrandesDemais(t *testing.T) {
	e := newCentralEnv(t)
	if err := os.Remove(e.secrets); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(e.secrets, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := e.open(t).Resolve("acme", contract.TypeTaskCreate); err == nil {
		t.Fatal("arquivo de segredos que é um diretório tinha de ser erro")
	}
	if err := os.Remove(e.secrets); err != nil {
		t.Fatal(err)
	}
	e.write(t, e.secrets, `{}`+strings.Repeat(" ", maxSecretsBytes))
	if _, err := e.open(t).Resolve("acme", contract.TypeTaskCreate); err == nil {
		t.Fatal("arquivo de segredos acima do teto tinha de ser erro")
	}
}

func TestCentralErrosNaoCarregamSenha(t *testing.T) {
	// um arquivo de segredos quebrado que ainda traz senhas de verdade: nenhuma pode ir parar no erro
	for _, content := range []string{
		`{"acme":"` + pwAcme + `","acme":"` + pwInitech + `"}`,                 // chave repetida
		`{"acme":"` + pwAcme + `","globex":123,"initech":"` + pwInitech + `"}`, // valor de tipo errado no meio
		`{"acme":"` + pwAcme + `"} "` + pwGlobex + `"`,                         // dado depois do objeto
		`{"acme":"` + pwAcme + `", "x": ["` + pwInitech + `"]}`,                // valor array
	} {
		e := newCentralEnv(t)
		e.write(t, e.secrets, content)
		src := e.open(t)
		_, err1 := src.Resolve("acme", contract.TypeTaskCreate)
		_, err2 := src.Credentials("acme")
		for _, err := range []error{err1, err2} {
			if err == nil {
				t.Fatalf("esperava erro para %s", content)
			}
			msg := err.Error()
			for _, pw := range []string{pwAcme, pwInitech, pwGlobex} {
				if strings.Contains(msg, pw) {
					t.Errorf("o erro carrega uma senha: %s", msg)
				}
			}
		}
	}
}

func TestCentralReleituraAcompanhaOsArquivos(t *testing.T) {
	e := newCentralEnv(t)
	src := e.open(t)
	if st := resolve(t, src, "acme", contract.TypeTaskCreate); !st.OK {
		t.Fatalf("antes: %+v", st)
	}
	// o control-plane desabilita o tenant em execução
	e.write(t, e.tenants, `[{"name":"acme","scope":"192.0.2.0/24","gmp_user":"tenant-acme","enabled":false}]`)
	if st := resolve(t, src, "acme", contract.TypeTaskStart); st.OK || st.Why != WhyDisabled {
		t.Fatalf("depois de desabilitar: %+v", st)
	}
	// reabilita com outro escopo
	e.write(t, e.tenants, `[{"name":"acme","scope":"198.51.100.0/24","gmp_user":"tenant-acme","enabled":true}]`)
	if st := resolve(t, src, "acme", contract.TypeTaskStart); !st.OK || st.Scope != "198.51.100.0/24" {
		t.Fatalf("depois de reabilitar com outro escopo: %+v", st)
	}
	// o operador tira a senha do arquivo de segredos
	e.write(t, e.secrets, `{}`)
	if st := resolve(t, src, "acme", contract.TypeTaskCreate); st.OK || st.Why != WhyNoSecret {
		t.Fatalf("depois de tirar a senha: %+v", st)
	}
	// e a recoloca, trocada
	e.write(t, e.secrets, `{"acme":"outra-senha-ficticia"}`)
	creds, err := src.Credentials("acme")
	if err != nil || creds.Password.Reveal() != "outra-senha-ficticia" {
		t.Fatalf("senha trocada: %v", err)
	}
}

func TestCentralCredentials(t *testing.T) {
	e := newCentralEnv(t)
	src := e.open(t)
	creds, err := src.Credentials("acme")
	if err != nil {
		t.Fatal(err)
	}
	if creds.User != "tenant-acme" || creds.Password.Reveal() != pwAcme {
		t.Fatalf("credenciais de acme: user %q", creds.User)
	}
	for name, tenant := range map[string]string{
		"desconhecido":     "nope",
		"desabilitado":     "initech",
		"sem usuário gvmd": "globex",
		"sem senha":        "umbrella",
	} {
		if _, err := src.Credentials(tenant); !errors.Is(err, ErrNoCredentials) {
			t.Errorf("%s: esperava ErrNoCredentials, deu %v", name, err)
		}
	}
}

func TestOpenValidaAConfiguracao(t *testing.T) {
	e := newCentralEnv(t)
	good := Config{TenantsFile: e.tenants, SecretsFile: e.secrets}
	if _, err := Open(contract.NodeCentral, good); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(contract.NodeCentral, Config{}); err == nil {
		t.Error("central sem TENANTS_FILE tinha de ser erro")
	}
	if _, err := Open("hub", good); err == nil {
		t.Error("node_kind desconhecido tinha de ser erro")
	}
	if _, err := Open("", good); err == nil {
		t.Error("node_kind vazio tinha de ser erro")
	}
}
