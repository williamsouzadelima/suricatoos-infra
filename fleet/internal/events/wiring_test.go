package events

import (
	"context"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/williamsouzadelima/suricatoos-infra/fleet/contract"
	"github.com/williamsouzadelima/suricatoos-infra/fleet/internal/state"
	"github.com/williamsouzadelima/suricatoos-infra/fleet/internal/tenant"
)

// As fontes do estado num teste: o que o fleet_ops, o registro de tenants e a API admin devolveriam.
type sources struct {
	mu      sync.Mutex
	tasks   []contract.TaskItem
	agents  []contract.AgentItem
	feeds   []contract.FeedStatus
	tenants []tenant.Listing
}

func (s *sources) Node(_ context.Context, req state.NodeRequest) (contract.DataNode, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return contract.DataNode{NodeKind: req.NodeKind, ConnectorVersion: req.ConnectorVersion,
		Versions: contract.NodeVersions{GMPProtocol: strp("22.7")}, Feeds: slices.Clone(s.feeds),
		Health: contract.NodeHealth{Status: contract.HealthOK, GVMDUp: true},
		Capabilities: contract.NodeCapabilities{SupportedTypes: slices.Clone(req.SupportedTypes),
			StateKinds: slices.Clone(req.StateKinds), ReportFormats: []contract.ReportFormatCapability{}},
		Policy: req.Policy, PolicySHA256: req.PolicySHA256, ReplayFloor: req.ReplayFloor}, nil
}

// Tasks faz o que o fleet_ops faz: atribui pelo dono, e só lista o que o mapa de donos cobre.
func (s *sources) Tasks(_ context.Context, owners map[string]string) (contract.DataTasks, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	known := map[string]bool{}
	for _, name := range owners {
		known[name] = true
	}
	d := contract.DataTasks{Items: []contract.TaskItem{}}
	for _, it := range s.tasks {
		if known[it.Tenant] {
			d.Items = append(d.Items, it)
		} else {
			d.UnattributedCount++
		}
	}
	return d, nil
}

func (s *sources) Targets(context.Context, map[string]string) (contract.DataTargets, error) {
	return contract.DataTargets{Items: []contract.TargetItem{}}, nil
}

func (s *sources) Schedules(context.Context, map[string]string) (contract.DataSchedules, error) {
	return contract.DataSchedules{Items: []contract.ScheduleItem{}}, nil
}

func (s *sources) Reports(context.Context, map[string]string) (contract.DataReports, error) {
	return contract.DataReports{Items: []contract.ReportItem{}}, nil
}

func (s *sources) Agents(context.Context) ([]contract.AgentItem, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.agents), nil
}

func (s *sources) Tokens(context.Context) ([]contract.TokenItem, error)             { return nil, nil }
func (s *sources) Sensors(context.Context) ([]contract.SensorItem, error)           { return nil, nil }
func (s *sources) ScanRequests(context.Context) ([]contract.ScanRequestItem, error) { return nil, nil }
func (s *sources) Remediation(context.Context) ([]contract.RemediationItem, error)  { return nil, nil }

func (s *sources) List() ([]tenant.Listing, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.tenants), nil
}

func (s *sources) WithPassword() (map[string]bool, error) { return map[string]bool{}, nil }

func (s *sources) Tail() contract.DataAuditTail {
	return contract.DataAuditTail{Exec: contract.AuditStreamTail{Lines: []string{}},
		Reject: contract.AuditStreamTail{Lines: []string{}}}
}

func (s *sources) ReplayFloor() string { return "2026-10-11T09:00:00Z" }

func (s *sources) edit(fn func(s *sources)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fn(s)
}

// node é um nó central de teste: o Collector do estado entregando cada ciclo à outbox, como a F2.6 os liga.
type node struct {
	t   *testing.T
	dir string
	src *sources
	box *box
	col *state.Collector
	now time.Time
}

func newNode(t *testing.T) *node {
	n := &node{t: t, dir: t.TempDir(), now: testAt, src: &sources{
		tenants: []tenant.Listing{{Name: "acme", Enabled: true, GVMUser: "u-acme"},
			{Name: "globex", Enabled: true, GVMUser: "u-globex"}},
		feeds: []contract.FeedStatus{feed(contract.FeedNVT, "202610110600", 2)},
	}}
	n.start()
	return n
}

// start abre a outbox e o Collector sobre o diretório do nó (um reinício do conector).
func (n *node) start() {
	n.t.Helper()
	n.box = &box{t: n.t, dir: n.dir, kind: contract.NodeCentral, faults: &faults{}, ids: &ids{}}
	n.box.open()
	if r := n.box.Recovery(); r.Corrupt != 0 || r.DiscardedBytes != 0 || (!r.Absent && r.BaselineLost) {
		n.t.Fatalf("o boot achou o arquivo estragado: %+v", r)
	}
	col, err := state.Open(state.Config{NodeKind: contract.NodeCentral, ConnectorVersion: "1.0.0", StateDir: n.dir,
		GVM: n.src, Tenants: n.src, ControlPlane: n.src, Audit: n.src, Floor: n.src,
		Now: func() time.Time { return n.now },
		Observe: func(o state.Observation) {
			if err := n.box.Observe(o); err != nil {
				n.t.Errorf("observação não gravada: %v", err)
			}
		}})
	if err := err; err != nil {
		n.t.Fatal(err)
	}
	n.col = col
}

func (n *node) cycle() {
	n.now = n.now.Add(time.Minute)
	n.col.Collect(context.Background())
	if errs := n.col.Errors(); len(errs) != 0 {
		n.t.Fatalf("coleta com erro: %v", errs)
	}
}

func (n *node) setTenant(name string, enabled bool, user string) {
	n.src.edit(func(s *sources) {
		for i := range s.tenants {
			if s.tenants[i].Name == name {
				s.tenants[i].Enabled, s.tenants[i].GVMUser = enabled, user
			}
		}
	})
}

// Pelo Collector de verdade: ligar e desligar um tenant (enabled) e tirar dele o usuário gvmd próprio (dividido com
// outro registro) fazem os objetos sumirem e voltarem das listas sem evento nenhum; as transições de verdade saem, uma
// vez, também depois de um reinício do conector.
func TestDoColetorAteAOutbox(t *testing.T) {
	n := newNode(t)
	n.src.tasks = []contract.TaskItem{task(uuidTask1, "acme", "Running"), task(uuidTask2, "globex", "Running")}
	n.src.agents = []contract.AgentItem{agent("win-01", "globex", true)}
	n.cycle()
	n.box.expect()

	n.setTenant("globex", false, "u-globex") // desligado
	n.cycle()
	n.box.expect()
	n.src.edit(func(s *sources) { s.tasks[1].Status, s.agents[0].Online = "Done", false })
	n.cycle()
	n.box.expect()
	n.setTenant("globex", true, "u-globex") // religado, com tudo mudado
	n.cycle()
	n.box.expect()

	n.setTenant("globex", true, "u-acme") // usuário gvmd dividido: as tarefas dos dois só contam
	n.cycle()
	n.box.expect()
	n.setTenant("globex", true, "u-globex")
	n.cycle()
	n.box.expect()

	n.src.edit(func(s *sources) {
		s.tasks[0].Status, s.tasks[1].Status, s.agents[0].Online = "Done", "Requested", true
		s.feeds[0] = feed(contract.FeedNVT, "202610120600", 1)
	})
	n.cycle()
	got := n.box.expect(
		`feed.updated - {"feed":"nvt","version":"202610120600","previous_version":"202610110600"}`,
		`task.status_changed acme {"task_id":"`+uuidTask1+`","from":"Running","to":"Done","progress":-1}`,
		`task.status_changed globex {"task_id":"`+uuidTask2+`","from":"Done","to":"Requested","progress":-1}`,
		`agent.online globex {"agent_id":"win-01","last_seen":"2026-10-11T11:58:00Z"}`)
	for _, e := range got {
		if e.OccurredAt != contract.FormatUTCTime(n.now) {
			t.Fatalf("occurred_at %s, a coleta foi em %s", e.OccurredAt, n.now)
		}
	}

	// reinício do conector: o mesmo estado não gera nada; a mudança feita com ele parado sai uma vez
	n.src.edit(func(s *sources) { s.agents[0].Online = false })
	n.start()
	n.cycle()
	n.box.expect(`agent.offline globex {"agent_id":"win-01","last_seen":"2026-10-11T11:58:00Z"}`)
	n.cycle()
	n.box.expect()
}
