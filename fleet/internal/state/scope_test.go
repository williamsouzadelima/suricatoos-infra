package state

import (
	"bytes"
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/williamsouzadelima/suricatoos-infra/fleet/contract"
	"github.com/williamsouzadelima/suricatoos-infra/fleet/internal/tenant"
)

// O scope de cada tenant conhecido, em ordem de nome: habilitado, CIDRs, se há usuário gvmd de escrita (usuário e
// senha) e a origem — nunca o nome do usuário gvmd nem a senha.
func TestScopeDoCentral(t *testing.T) {
	f := newFakes()
	f.tenants.list = []tenant.Listing{
		{Name: "umbrella", Enabled: true, Scope: "", GVMUser: "tenant-umbrella"},
		{Name: "acme", Enabled: true, Scope: "192.0.2.0/24, 198.51.100.0/24", GVMUser: "tenant-acme"},
		{Name: "initech", Enabled: false, Scope: "192.0.2.0/25 198.51.100.0/25", GVMUser: "tenant-initech"},
		{Name: "globex", Enabled: true, Scope: "203.0.113.0/24"},
		{Name: "-ruim-", Enabled: true, Scope: "192.0.2.0/24"},
	}
	f.tenants.pw = map[string]bool{"acme": true, "initech": true, "globex": true}
	c := collectOnce(t, f, contract.NodeCentral)
	got := current(t, c, contract.KindScope).(*contract.DataScope)
	reg := contract.ScopeTenantsRegistry
	want := &contract.DataScope{Items: []contract.ScopeItem{
		{Tenant: "acme", Enabled: true, Scope: []string{"192.0.2.0/24", "198.51.100.0/24"}, GMPUserConfigured: true, Source: reg},
		{Tenant: "globex", Enabled: true, Scope: []string{"203.0.113.0/24"}, GMPUserConfigured: false, Source: reg}, // senha sem usuário
		{Tenant: "initech", Enabled: false, Scope: []string{"192.0.2.0/25", "198.51.100.0/25"}, GMPUserConfigured: true, Source: reg},
		{Tenant: "umbrella", Enabled: true, Scope: []string{}, GMPUserConfigured: false, Source: reg}, // usuário sem senha
	}, UnattributedCount: 1}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("scope %+v", got)
	}
	s, _ := c.Current(contract.KindScope)
	if bytes.Contains(s.Data, []byte("tenant-")) {
		t.Fatalf("o nome do usuário gvmd saiu no scope: %s", s.Data)
	}
}

func TestScopeDoStandaloneESensor(t *testing.T) {
	for _, kind := range []contract.NodeKind{contract.NodeStandalone, contract.NodeSensor} {
		f := newFakes()
		f.tenants.list = []tenant.Listing{{Name: "acme", Enabled: true, Scope: "192.0.2.0/24", GVMUser: "tenant-acme"}}
		got := current(t, collectOnce(t, f, kind), contract.KindScope).(*contract.DataScope)
		want := []contract.ScopeItem{{Tenant: "acme", Enabled: true, Scope: []string{"192.0.2.0/24"}, GMPUserConfigured: true,
			Source: contract.ScopeLocalEnv}}
		if !reflect.DeepEqual(got.Items, want) {
			t.Errorf("%s: %+v", kind, got.Items)
		}
	}
}

// O escopo sai na forma canônica que o portão de escopo (scopegate) usa: CIDR mascarado, IP isolado como endereço
// (o IPv4 mapeado em IPv6 como IPv4), separado por vírgula, espaço, tab ou quebra de linha.
func TestScopeNaFormaCanonicaDoPortao(t *testing.T) {
	f := newFakes()
	f.tenants.list = []tenant.Listing{{Name: "acme", Enabled: true,
		Scope: "192.0.2.5/24,198.51.100.7\t::ffff:203.0.113.9\n2001:DB8::/32  2001:db8:0:0::1"}}
	got := current(t, collectOnce(t, f, contract.NodeStandalone), contract.KindScope).(*contract.DataScope)
	want := []string{"192.0.2.0/24", "198.51.100.7", "203.0.113.9", "2001:db8::/32", "2001:db8::1"}
	if len(got.Items) != 1 || !reflect.DeepEqual(got.Items[0].Scope, want) {
		t.Fatalf("scope %+v", got.Items)
	}
}

// Uma entrada que não é IP/CIDR literal faz o portão recusar o escopo inteiro (nada passa): o estado diz isso —
// escopo vazio —, nunca só as entradas boas.
func TestScopeComEntradaNaoLiteralSaiVazio(t *testing.T) {
	for _, spec := range []string{"192.0.2.0/24, intranet.acme.example", "192.0.2.0/24 cafe.be", "192.0.2.0/33"} {
		f := newFakes()
		f.tenants.list = []tenant.Listing{{Name: "acme", Enabled: true, Scope: spec}}
		c := collectOnce(t, f, contract.NodeStandalone)
		got := current(t, c, contract.KindScope).(*contract.DataScope)
		if len(got.Items) != 1 || len(got.Items[0].Scope) != 0 {
			t.Errorf("%q: scope %+v", spec, got.Items)
		}
		s, _ := c.Current(contract.KindScope)
		if bytes.Contains(s.Data, []byte("acme.example")) || bytes.Contains(s.Data, []byte("cafe.be")) {
			t.Errorf("%q: a entrada não literal saiu", spec)
		}
	}
}

func TestScopeAcimaDe1024EntradasCortaEMarcaTruncated(t *testing.T) {
	var entries []string
	for i := range 1100 {
		entries = append(entries, fmt.Sprintf("10.%d.%d.0/24", i/256, i%256))
	}
	f := newFakes()
	f.tenants.list = []tenant.Listing{{Name: "acme", Enabled: true, Scope: strings.Join(entries, ",")}}
	got := current(t, collectOnce(t, f, contract.NodeStandalone), contract.KindScope).(*contract.DataScope)
	if len(got.Items) != 1 || len(got.Items[0].Scope) != maxScopeEntries || !got.Truncated ||
		got.Items[0].Scope[maxScopeEntries-1] != entries[maxScopeEntries-1] {
		t.Fatalf("%d entradas, truncated %v", len(got.Items[0].Scope), got.Truncated)
	}
}

// Sem saber quem tem senha, o scope não sai (o kind mantém o último retrato); os outros kinds seguem.
func TestScopeSemLerSenhasFalhaSozinho(t *testing.T) {
	f := newFakes()
	f.gvm.tasks = contract.DataTasks{Items: []contract.TaskItem{fullTask(uuidTask1, "acme")}}
	c := collectOnce(t, f, contract.NodeStandalone)
	before, ok := c.Current(contract.KindScope)
	if !ok {
		t.Fatal("sem o retrato bom de antes")
	}
	f.tenants.pwErr = errFonte
	f.tenants.list = append(f.tenants.list, tenant.Listing{Name: "initech", Enabled: true})
	f.gvm.tasks.Items = append(f.gvm.tasks.Items, fullTask(uuidTask2, "globex"))
	c.Collect(context.Background())
	if after, _ := c.Current(contract.KindScope); !bytes.Equal(after.Data, before.Data) || c.Errors()[contract.KindScope] == nil {
		t.Fatalf("scope devia manter o retrato e expor o erro: %v", c.Errors())
	}
	if got := current(t, c, contract.KindTasks).(*contract.DataTasks); len(got.Items) != 2 {
		t.Fatalf("tasks não avançou: %+v", got)
	}
}

// Sem a listagem de tenants, nenhum kind que atribui por tenant sai; o audit_tail, que não depende dela, segue.
func TestListagemDeTenantsQuebradaSoDerrubaQuemDependeDela(t *testing.T) {
	f := newFakes()
	f.tenants.listErr = errFonte
	c := collectOnce(t, f, contract.NodeCentral)
	errs := c.Errors()
	for _, kind := range []contract.StateKind{contract.KindScope, contract.KindTasks, contract.KindTargets,
		contract.KindSchedules, contract.KindReports, contract.KindAgents, contract.KindTokens, contract.KindSensors,
		contract.KindScanRequests, contract.KindRemediation} {
		if errs[kind] == nil {
			t.Errorf("%s saiu sem a listagem de tenants", kind)
		}
	}
	if errs[contract.KindAuditTail] != nil {
		t.Fatalf("audit_tail não depende de tenant: %v", errs[contract.KindAuditTail])
	}
	current(t, c, contract.KindAuditTail)
}
