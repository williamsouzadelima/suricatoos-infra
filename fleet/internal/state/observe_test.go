package state

import (
	"context"
	"slices"
	"testing"

	"github.com/williamsouzadelima/suricatoos-infra/fleet/contract"
	"github.com/williamsouzadelima/suricatoos-infra/fleet/internal/tenant"
)

// observer guarda as observações que o Collector entrega.
type observer struct{ got []Observation }

func (o *observer) observe(obs Observation) { o.got = append(o.got, obs) }

func observing(t *testing.T, f *fakes, kind contract.NodeKind) (*Collector, *observer) {
	t.Helper()
	o := &observer{}
	cfg := f.config(t, kind)
	cfg.Observe = o.observe
	return openCollector(t, cfg), o
}

// Ao fim de cada ciclo completo, o Collector entrega o retrato novo de cada kind coletado — os mesmos bytes que
// Current devolve — com os tenants a que o kind atribuiu objetos: os donos gvmd para os kinds do gvmd, os habilitados
// para os do control-plane, nenhum para node, scope e audit_tail.
func TestObservacaoDeCadaCicloComOsTenantsAtribuidos(t *testing.T) {
	f := newFakes()
	f.gvm.tasks.Items = []contract.TaskItem{fullTask(uuidTask1, "acme"), fullTask(uuidTask2, "globex")}
	f.cp.agents = []contract.AgentItem{fullAgent("win-01", "acme")}
	c, o := observing(t, f, contract.NodeCentral)
	c.Collect(context.Background())
	if len(o.got) != 1 {
		t.Fatalf("%d observações num ciclo", len(o.got))
	}
	obs := o.got[0]
	if len(obs.Kinds) != len(centralKinds) {
		t.Fatalf("kinds observados %d, esperava %d", len(obs.Kinds), len(centralKinds))
	}
	both := []string{"acme", "globex"}
	for _, kind := range centralKinds {
		ob, ok := obs.Kinds[kind]
		if !ok {
			t.Fatalf("%s fora da observação", kind)
		}
		cur, _ := c.Current(kind)
		if string(ob.Snapshot.Data) != string(cur.Data) || ob.Snapshot.SHA256 != cur.SHA256 || ob.Snapshot.Kind != kind ||
			!ob.Snapshot.CollectedAt.Equal(cur.CollectedAt) {
			t.Errorf("%s: o retrato observado não é o atual", kind)
		}
		if ob.Partial {
			t.Errorf("%s: parcial sem falha", kind)
		}
		switch kind {
		case contract.KindNode, contract.KindScope, contract.KindAuditTail:
			if ob.Tenants != nil {
				t.Errorf("%s: tenants %v", kind, ob.Tenants)
			}
		default:
			if !slices.Equal(ob.Tenants, both) {
				t.Errorf("%s: tenants %v, esperava %v", kind, ob.Tenants, both)
			}
		}
	}
}

// Os tenants de cada kind são o domínio da atribuição dele no ciclo: um tenant desabilitado sai dos dois grupos; um
// sem usuário gvmd, ou que divide o usuário com outro registro, sai só dos kinds do gvmd; um nome fora do padrão não
// entra em nenhum.
func TestTenantsObservadosSaoOsDaAtribuicao(t *testing.T) {
	f := newFakes()
	f.tenants.list = []tenant.Listing{
		{Name: "acme", Enabled: true, GVMUser: "tenant-acme"},
		{Name: "globex", Enabled: false, GVMUser: "tenant-globex"},
		{Name: "initech", Enabled: true},
		{Name: "umbrella", Enabled: true, GVMUser: "compartilhado"},
		{Name: "hooli", Enabled: true, GVMUser: "compartilhado"},
		{Name: "nome inválido", Enabled: true, GVMUser: "tenant-x"},
	}
	c, o := observing(t, f, contract.NodeCentral)
	c.Collect(context.Background())
	obs := o.got[0]
	gvmKinds := []contract.StateKind{contract.KindTasks, contract.KindTargets, contract.KindSchedules, contract.KindReports}
	cpKinds := []contract.StateKind{contract.KindAgents, contract.KindTokens, contract.KindSensors,
		contract.KindScanRequests, contract.KindRemediation}
	for _, kind := range gvmKinds {
		if got := obs.Kinds[kind].Tenants; !slices.Equal(got, []string{"acme"}) {
			t.Errorf("%s: tenants %v", kind, got)
		}
	}
	for _, kind := range cpKinds {
		if got, want := obs.Kinds[kind].Tenants, []string{"acme", "hooli", "initech", "umbrella"}; !slices.Equal(got, want) {
			t.Errorf("%s: tenants %v, esperava %v", kind, got, want)
		}
	}
	// nenhum tenant atribuível: lista vazia, não nil (o kind atribui, só que a ninguém)
	f.tenants.list = nil
	c.Collect(context.Background())
	if got := o.got[1].Kinds[contract.KindTasks].Tenants; got == nil || len(got) != 0 {
		t.Fatalf("tasks sem tenant: %#v", got)
	}
}

// Um kind cuja fonte falhou fica fora da observação (mantém o último retrato, mas nada novo foi visto); o node montado
// sem o gvmd é observado como parcial (feeds desconhecidos, não ausentes).
func TestObservacaoSemOKindQueFalhouENodeParcial(t *testing.T) {
	f := newFakes()
	c, o := observing(t, f, contract.NodeStandalone)
	c.Collect(context.Background())
	f.gvm.errs[contract.KindTasks] = errFonte
	f.gvm.errs[contract.KindNode] = errFonte
	c.Collect(context.Background())
	obs := o.got[1]
	if _, ok := obs.Kinds[contract.KindTasks]; ok {
		t.Fatal("tasks falhou e foi observado")
	}
	node, ok := obs.Kinds[contract.KindNode]
	if !ok || !node.Partial {
		t.Fatalf("node sem gvmd: observado %v, parcial %v", ok, node.Partial)
	}
	if obs.Kinds[contract.KindReports].Partial {
		t.Fatal("reports parcial")
	}
}

// Um ciclo cortado pelo contexto não é observado: o seguinte é.
func TestCicloCortadoPeloContextoNaoEObservado(t *testing.T) {
	f := newFakes()
	c, o := observing(t, f, contract.NodeStandalone)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c.Collect(ctx)
	if len(o.got) != 0 {
		t.Fatal("ciclo com o contexto encerrado foi observado")
	}
	// o contexto acaba no meio do ciclo (durante a leitura do node, o último kind)
	ctx, cancel = context.WithCancel(context.Background())
	f.gvm.node = func(req NodeRequest) (contract.DataNode, error) {
		cancel()
		return echoNode(req)
	}
	c.Collect(ctx)
	if len(o.got) != 0 {
		t.Fatal("ciclo cortado no meio foi observado")
	}
	f.gvm.node = nil
	c.Collect(context.Background())
	if len(o.got) != 1 || len(o.got[0].Kinds) != len(KindsOf(contract.NodeStandalone)) {
		t.Fatalf("o ciclo seguinte não foi observado inteiro: %v", o.got)
	}
}
