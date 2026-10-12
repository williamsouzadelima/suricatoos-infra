package events

import (
	"maps"
	"reflect"
	"testing"

	"github.com/williamsouzadelima/suricatoos-infra/fleet/contract"
)

func sampleBaseline() *baseline {
	b := newBaseline()
	b.kinds[contract.KindTasks] = map[string]map[string]string{
		"acme":   {uuidTask1: "Running", uuidTask2: "Done"},
		"globex": {},
	}
	b.kinds[contract.KindReports] = map[string]map[string]string{"acme": {uuidReport1: valueCompleted, uuidReport2: ""}}
	b.kinds[contract.KindAgents] = map[string]map[string]string{"acme": {"win-01": valueOnline, "win-02": valueOffline}}
	b.kinds[contract.KindRemediation] = map[string]map[string]string{"acme": {"job-1": ""}}
	b.feeds = map[contract.FeedType]feedMark{contract.FeedNVT: {Version: "202610110600", Stale: true}}
	return b
}

// A base inteira vira um delta que, aplicado a uma base vazia, a refaz — sempre com os mesmos bytes.
func TestBaseInteiraIdaEVolta(t *testing.T) {
	b := sampleBaseline()
	full := b.full()
	again := newBaseline()
	if err := again.check(full, trackedKinds); err != nil {
		t.Fatal(err)
	}
	again.apply(full)
	if !reflect.DeepEqual(again, b) {
		t.Fatalf("a base refeita difere:\n%+v\n%+v", again, b)
	}
	one, _ := encodeLine(record{K: kindTx, Delta: full})
	two, _ := encodeLine(record{K: kindTx, Delta: b.full()})
	if string(one) != string(two) {
		t.Fatal("a mesma base deu bytes diferentes")
	}
	empty := newBaseline()
	if d := empty.full(); !d.empty() {
		t.Fatalf("base vazia deu delta %+v", d)
	}
	// um kind sem nada ainda tem base: o delta dele não é vazio
	empty.kinds[contract.KindTasks] = map[string]map[string]string{}
	if d := empty.full(); d.empty() {
		t.Fatal("kind com base e sem objeto sumiu do delta")
	}
}

// O delta aplica na ordem: tira tenants, põe tenants, tira objetos, põe objetos; feeds trocam inteiros.
func TestDeltaAplicaNaOrdem(t *testing.T) {
	b := sampleBaseline()
	d := &delta{Kinds: map[contract.StateKind]*kindDelta{contract.KindTasks: {
		Drop: []string{"globex"}, Add: []string{"initech"},
		Del: []entry{{Tenant: "acme", ID: uuidTask2}},
		Set: []entry{{Tenant: "acme", ID: uuidTask1, Value: "Done"}, {Tenant: "initech", ID: uuidTask3, Value: "New"}},
	}}, Feeds: &feedsDelta{Marks: map[contract.FeedType]feedMark{contract.FeedSCAP: {Version: "1"}}}}
	if err := b.check(d, trackedKinds); err != nil {
		t.Fatal(err)
	}
	b.apply(d)
	want := map[string]map[string]string{"acme": {uuidTask1: "Done"}, "initech": {uuidTask3: "New"}}
	if !reflect.DeepEqual(b.kinds[contract.KindTasks], want) {
		t.Fatalf("tasks %v", b.kinds[contract.KindTasks])
	}
	if !maps.Equal(b.feeds, map[contract.FeedType]feedMark{contract.FeedSCAP: {Version: "1"}}) {
		t.Fatalf("feeds %v", b.feeds)
	}
	// o primeiro delta de um kind cria a base dele, mesmo vazia
	c := newBaseline()
	first := &delta{Kinds: map[contract.StateKind]*kindDelta{contract.KindAgents: {}}}
	if err := c.check(first, trackedKinds); err != nil {
		t.Fatal(err)
	}
	c.apply(first)
	if _, ok := c.kinds[contract.KindAgents]; !ok {
		t.Fatal("o primeiro delta não criou a base do kind")
	}
}

// Um delta que não casa com a base — ou com o schema — é recusado inteiro (no boot, é corrupção).
func TestDeltaInconsistenteRecusado(t *testing.T) {
	tasks := func(kd kindDelta) *delta {
		return &delta{Kinds: map[contract.StateKind]*kindDelta{contract.KindTasks: &kd}}
	}
	cases := map[string]*delta{
		"kind sem transições":    {Kinds: map[contract.StateKind]*kindDelta{contract.KindTargets: {}}},
		"kind nulo":              {Kinds: map[contract.StateKind]*kindDelta{contract.KindTasks: nil}},
		"tira tenant ausente":    tasks(kindDelta{Drop: []string{"initech"}}),
		"tira tenant duas vezes": tasks(kindDelta{Drop: []string{"globex", "globex"}}),
		"põe tenant presente":    tasks(kindDelta{Add: []string{"acme"}}),
		"põe tenant inválido":    tasks(kindDelta{Add: []string{"acme corp"}}),
		"põe tenant duas vezes":  tasks(kindDelta{Add: []string{"initech", "initech"}}),
		"põe tenant tirado":      tasks(kindDelta{Drop: []string{"globex"}, Add: []string{"globex"}}),
		"tira objeto ausente":    tasks(kindDelta{Del: []entry{{Tenant: "acme", ID: uuidTask3}}}),
		"tira objeto com valor":  tasks(kindDelta{Del: []entry{{Tenant: "acme", ID: uuidTask1, Value: "Done"}}}),
		"tira objeto de tenant tirado": tasks(kindDelta{Drop: []string{"acme"},
			Del: []entry{{Tenant: "acme", ID: uuidTask1}}}),
		"tira objeto duas vezes": tasks(kindDelta{Del: []entry{{Tenant: "acme", ID: uuidTask1},
			{Tenant: "acme", ID: uuidTask1}}}),
		"põe objeto em tenant ausente": tasks(kindDelta{Set: []entry{
			{Tenant: "initech", ID: uuidTask3, Value: "New"}}}),
		"põe objeto em tenant tirado": tasks(kindDelta{Drop: []string{"globex"},
			Set: []entry{{Tenant: "globex", ID: uuidTask3, Value: "New"}}}),
		"põe objeto duas vezes": tasks(kindDelta{Set: []entry{{Tenant: "acme", ID: uuidTask3, Value: "New"},
			{Tenant: "acme", ID: uuidTask3, Value: "Done"}}}),
		"põe e tira o mesmo objeto": tasks(kindDelta{Del: []entry{{Tenant: "acme", ID: uuidTask1}},
			Set: []entry{{Tenant: "acme", ID: uuidTask1, Value: "Done"}}}),
		"id de tarefa inválido": tasks(kindDelta{Set: []entry{{Tenant: "acme", ID: "x", Value: "New"}}}),
		"status inválido":       tasks(kindDelta{Set: []entry{{Tenant: "acme", ID: uuidTask3, Value: "New1"}}}),
		"report com valor desconhecido": {Kinds: map[contract.StateKind]*kindDelta{contract.KindReports: {
			Set: []entry{{Tenant: "acme", ID: uuidReport2, Value: "Done"}}}}},
		"agente sem online": {Kinds: map[contract.StateKind]*kindDelta{contract.KindAgents: {
			Set: []entry{{Tenant: "acme", ID: "win-01", Value: ""}}}}},
		"agent_id inválido": {Kinds: map[contract.StateKind]*kindDelta{contract.KindAgents: {
			Set: []entry{{Tenant: "acme", ID: "a,b", Value: valueOnline}}}}},
		"job com valor": {Kinds: map[contract.StateKind]*kindDelta{contract.KindRemediation: {
			Set: []entry{{Tenant: "acme", ID: "job-2", Value: "PENDING_APPROVAL"}}}}},
		"job_id inválido": {Kinds: map[contract.StateKind]*kindDelta{contract.KindRemediation: {
			Set: []entry{{Tenant: "acme", ID: "job.2"}}}}},
		"feeds sem marcas":  {Feeds: &feedsDelta{}},
		"feed desconhecido": {Feeds: &feedsDelta{Marks: map[contract.FeedType]feedMark{"nasl": {Version: "1"}}}},
		"versão de feed ruim": {Feeds: &feedsDelta{Marks: map[contract.FeedType]feedMark{
			contract.FeedNVT: {Version: "v 1"}}}},
	}
	for name, d := range cases {
		b := sampleBaseline()
		if err := b.check(d, trackedKinds); err == nil {
			t.Errorf("%s: aceito", name)
		}
	}
	// agents e remediation não existem fora do nó central
	b := sampleBaseline()
	agents := &delta{Kinds: map[contract.StateKind]*kindDelta{contract.KindAgents: {}}}
	if err := b.check(agents, kindsOf(contract.NodeStandalone)); err == nil {
		t.Fatal("delta de agents aceito num nó standalone")
	}
	sensor := kindsOf(contract.NodeSensor)
	if len(sensor) != 2 || sensor[0] != contract.KindTasks || sensor[1] != contract.KindReports {
		t.Fatalf("kinds do sensor %v", sensor)
	}
	if kindsOf("hub") != nil {
		t.Fatal("node_kind inválido com kinds")
	}
}
