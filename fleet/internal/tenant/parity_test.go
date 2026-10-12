package tenant

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/williamsouzadelima/suricatoos-infra/fleet/contract"
)

// The module fleet does not import control-plane, so the format of TENANTS_FILE is guarded by a shared fixture:
// testdata/tenants.json is read here AND by control-plane/tenants (fleet_parity_test.go), and each side asserts
// the same view of it. It is the file the control-plane Registry writes (the control-plane test checks that
// byte for byte), so a change in the format breaks one of the two suites.
//
// fixtureView is that view: keep it identical to the one in control-plane/tenants/fleet_parity_test.go.
var fixtureView = []struct {
	Name    string
	Enabled bool
	Scope   string
	GmpUser string
}{
	{"acme", true, "192.0.2.0/24, 198.51.100.0/24", "tenant-acme"},
	{"globex", true, "203.0.113.0/24", ""},
	{"initech", false, "192.0.2.0/25 198.51.100.0/25", "tenant-initech"},
	{"umbrella", true, "", "tenant-umbrella"},
}

func TestParidadeComOFixtureDoControlPlane(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "tenants.json"))
	if err != nil {
		t.Fatal(err)
	}
	recs, err := parseRegistry(data)
	if err != nil {
		t.Fatalf("o formato que o control-plane escreve tem de ser lido pela frota: %v", err)
	}
	if len(recs) != len(fixtureView) {
		t.Fatalf("o fixture tem %d registros, a visão espera %d", len(recs), len(fixtureView))
	}
	for i, want := range fixtureView {
		got := recs[i]
		if got.Name != want.Name || got.Enabled != want.Enabled || got.Scope != want.Scope || got.GmpUser != want.GmpUser {
			t.Errorf("registro %d: lido %+v, a visão espera %+v", i, got, want)
		}
	}

	// a mesma visão pela API que o conector usa (central, lendo o fixture direto)
	src, err := Open(contract.NodeCentral, Config{TenantsFile: filepath.Join("testdata", "tenants.json")})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range fixtureView {
		st := resolve(t, src, want.Name, contract.TypeTaskStart) // leitura: não consulta segredos
		if st.OK != want.Enabled {
			t.Errorf("%s: OK=%v, enabled=%v no fixture", want.Name, st.OK, want.Enabled)
		}
		wantScope := want.Scope
		if !want.Enabled {
			wantScope = "" // desabilitado: deny-all, como o ScopeSpec do control-plane
		}
		if st.Scope != wantScope {
			t.Errorf("%s: escopo %q, esperava %q", want.Name, st.Scope, wantScope)
		}
		// o usuário gvmd: com ele (e uma senha) a escrita passa; sem ele, não
		w := resolve(t, src, want.Name, contract.TypeTaskCreate)
		switch {
		case !want.Enabled:
			if w.Why != WhyDisabled {
				t.Errorf("%s: escrita %+v", want.Name, w)
			}
		case want.GmpUser == "":
			if w.OK || w.Why != WhyNoGVMUser {
				t.Errorf("%s: sem gmp_user a escrita não passa: %+v", want.Name, w)
			}
		default:
			if w.OK || w.Why != WhyNoSecret { // há usuário; este teste não monta o arquivo de segredos
				t.Errorf("%s: com gmp_user e sem segredo a escrita para em no_secret: %+v", want.Name, w)
			}
		}
	}
}
