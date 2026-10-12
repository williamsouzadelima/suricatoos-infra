package tenant

import (
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/williamsouzadelima/suricatoos-infra/fleet/contract"
)

// O estado da frota (F2.5) lista todo tenant que o nó conhece, na ordem do registro, com os desabilitados e com os
// de nome inválido (quem decide o que eles viram é o chamador: o estado só os conta).
func TestCentralListaTodoORegistroNaOrdem(t *testing.T) {
	e := newCentralEnv(t)
	got, err := e.open(t).List()
	if err != nil {
		t.Fatal(err)
	}
	var want []Listing
	for _, v := range fixtureView {
		want = append(want, Listing{Name: v.Name, Enabled: v.Enabled, Scope: v.Scope, GVMUser: v.GmpUser})
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("List = %+v, esperava %+v", got, want)
	}
}

func TestCentralListaMantemNomeInvalidoParaOChamadorContar(t *testing.T) {
	e := newCentralEnv(t)
	e.write(t, e.tenants, `[{"name":"acme","enabled":true},{"name":"-nome ruim-","gmp_user":"u","enabled":true},{"name":"","enabled":false}]`)
	got, err := e.open(t).List()
	if err != nil {
		t.Fatal(err)
	}
	want := []Listing{{Name: "acme", Enabled: true}, {Name: "-nome ruim-", Enabled: true, GVMUser: "u"}, {Name: ""}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("List = %+v, esperava %+v", got, want)
	}
}

// List não lê senha: um arquivo de segredos quebrado não a impede.
func TestCentralListaNaoLeOArquivoDeSegredos(t *testing.T) {
	e := newCentralEnv(t)
	e.write(t, e.secrets, `{"acme":`)
	got, err := e.open(t).List()
	if err != nil || len(got) != len(fixtureView) {
		t.Fatalf("List = %+v, %v", got, err)
	}
}

func TestCentralListaSemRegistroNaoTemNinguem(t *testing.T) {
	e := newCentralEnv(t)
	if err := os.Remove(e.tenants); err != nil {
		t.Fatal(err)
	}
	got, err := e.open(t).List()
	if err != nil || len(got) != 0 {
		t.Fatalf("sem registro: List = %+v, %v", got, err)
	}
}

func TestCentralListaComRegistroInutilizavelEErro(t *testing.T) {
	for _, content := range []string{`{`, `[{"name":"acme","enabled":true,"extra":1}]`,
		`[{"name":"acme","enabled":true},{"name":"acme","enabled":false}]`} {
		e := newCentralEnv(t)
		e.write(t, e.tenants, content)
		if got, err := e.open(t).List(); err == nil {
			t.Errorf("registro %q: List = %+v sem erro", content, got)
		}
	}
}

func TestCentralWithPasswordSoDizQuemTemSenha(t *testing.T) {
	e := newCentralEnv(t)
	e.write(t, e.secrets, `{"acme":"`+pwAcme+`","initech":"","fora-do-registro":"x"}`)
	got, err := e.open(t).WithPassword()
	if err != nil {
		t.Fatal(err)
	}
	if want := map[string]bool{"acme": true, "fora-do-registro": true}; !reflect.DeepEqual(got, want) {
		t.Fatalf("WithPassword = %v, esperava %v (senha vazia não conta)", got, want)
	}
}

func TestCentralWithPasswordSemArquivoOuSemConfiguracaoEVazio(t *testing.T) {
	e := newCentralEnv(t)
	if err := os.Remove(e.secrets); err != nil {
		t.Fatal(err)
	}
	for name, src := range map[string]Source{
		"arquivo ausente":             e.open(t),
		"SENSOR_TENANT_SECRETS vazio": mustOpen(t, contract.NodeCentral, Config{TenantsFile: e.tenants}),
	} {
		got, err := src.WithPassword()
		if err != nil || len(got) != 0 {
			t.Errorf("%s: WithPassword = %v, %v", name, got, err)
		}
	}
}

func TestCentralWithPasswordComArquivoQuebradoEErroSemVazarConteudo(t *testing.T) {
	e := newCentralEnv(t)
	e.write(t, e.secrets, `{"acme":"`+pwAcme+`","globex":7}`)
	got, err := e.open(t).WithPassword()
	if err == nil {
		t.Fatalf("segredos inválidos: WithPassword = %v sem erro", got)
	}
	if strings.Contains(err.Error(), pwAcme) {
		t.Fatalf("o erro vazou a senha: %v", err)
	}
}

func TestLocalListaOUnicoTenant(t *testing.T) {
	for _, kind := range []contract.NodeKind{contract.NodeStandalone, contract.NodeSensor} {
		e := newLocalEnv(t)
		got, err := e.open(t, kind).List()
		if err != nil {
			t.Fatal(err)
		}
		want := []Listing{{Name: "acme", Enabled: true, Scope: "192.0.2.0/24 198.51.100.0/24", GVMUser: "tenant-acme"}}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s: List = %+v, esperava %+v", kind, got, want)
		}
	}
}

func TestLocalWithPassword(t *testing.T) {
	e := newLocalEnv(t)
	src := e.open(t, contract.NodeStandalone)
	if got, err := src.WithPassword(); err != nil || !reflect.DeepEqual(got, map[string]bool{"acme": true}) {
		t.Fatalf("com senha: WithPassword = %v, %v", got, err)
	}
	e.setPassword(t, "\r\n")
	if got, err := src.WithPassword(); err != nil || len(got) != 0 {
		t.Fatalf("só quebra de linha: WithPassword = %v, %v", got, err)
	}
	if err := os.Remove(e.passwordFile); err != nil {
		t.Fatal(err)
	}
	if got, err := src.WithPassword(); err != nil || len(got) != 0 {
		t.Fatalf("arquivo ausente: WithPassword = %v, %v", got, err)
	}
	if err := os.Mkdir(e.passwordFile, 0o700); err != nil { // existe e não é arquivo regular
		t.Fatal(err)
	}
	if got, err := src.WithPassword(); err == nil {
		t.Fatalf("senha ilegível: WithPassword = %v sem erro", got)
	}
}

func mustOpen(t *testing.T, kind contract.NodeKind, cfg Config) Source {
	t.Helper()
	src, err := Open(kind, cfg)
	if err != nil {
		t.Fatal(err)
	}
	return src
}
