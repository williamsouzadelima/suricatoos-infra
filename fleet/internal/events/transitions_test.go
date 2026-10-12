package events

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/williamsouzadelima/suricatoos-infra/fleet/contract"
	"github.com/williamsouzadelima/suricatoos-infra/fleet/internal/state"
)

// world é o estado do nó num instante, como os coletores o veriam: cada kind vira um retrato com os seus tenants
// atribuídos, igual ao que o state entrega no fim de um ciclo.
type world struct {
	t         *testing.T
	at        time.Time
	tenants   []string                        // os tenants atribuídos em todo kind de lista
	tenantsOf map[contract.StateKind][]string // por kind, quando difere
	tasks     []contract.TaskItem
	reports   []contract.ReportItem
	agents    []contract.AgentItem
	jobs      []contract.RemediationItem
	feeds     []contract.FeedStatus
	partial   bool                                  // node montado sem o gvmd
	failed    map[contract.StateKind]bool           // kinds cuja coleta falhou no ciclo
	extra     map[contract.StateKind]state.Observed // retratos postos à mão
}

func newWorld(t *testing.T) *world {
	return &world{t: t, at: testAt, tenants: []string{"acme", "globex"},
		tenantsOf: map[contract.StateKind][]string{}, failed: map[contract.StateKind]bool{},
		extra: map[contract.StateKind]state.Observed{}}
}

func snapOf(t *testing.T, kind contract.StateKind, v any, at time.Time) state.Snapshot {
	t.Helper()
	b, err := contract.MarshalCompact(v)
	if err != nil {
		t.Fatal(err)
	}
	return state.Snapshot{Kind: kind, Data: b, SHA256: sha(b), CollectedAt: at}
}

// obs é a observação do instante atual; cada chamada avança o relógio um minuto, como um ciclo.
func (w *world) obs() state.Observation {
	w.t.Helper()
	at := w.at
	w.at = w.at.Add(time.Minute)
	out := state.Observation{Kinds: map[contract.StateKind]state.Observed{}}
	put := func(kind contract.StateKind, v any) {
		if w.failed[kind] {
			return
		}
		tenants := slices.Clone(w.tenants)
		if ts, ok := w.tenantsOf[kind]; ok {
			tenants = slices.Clone(ts)
		}
		if kind == contract.KindNode {
			tenants = nil
		}
		out.Kinds[kind] = state.Observed{Snapshot: snapOf(w.t, kind, v, at), Tenants: tenants,
			Partial: kind == contract.KindNode && w.partial}
	}
	put(contract.KindTasks, contract.DataTasks{Items: orEmpty(w.tasks)})
	put(contract.KindReports, contract.DataReports{Items: orEmpty(w.reports)})
	put(contract.KindAgents, contract.DataAgents{Items: orEmpty(w.agents)})
	put(contract.KindRemediation, contract.DataRemediation{Items: orEmpty(w.jobs)})
	put(contract.KindNode, nodeData(w.feeds, w.partial))
	for kind, o := range w.extra {
		out.Kinds[kind] = o
	}
	return out
}

func orEmpty[T any](xs []T) []T {
	if xs == nil {
		return []T{}
	}
	return slices.Clone(xs)
}

// nodeData é um data_node válido com os feeds dados (sem o gvmd: saúde down e sem feeds, como o fallback do state).
func nodeData(feeds []contract.FeedStatus, partial bool) contract.DataNode {
	health := contract.NodeHealth{Status: contract.HealthOK, GVMDUp: true}
	if partial {
		feeds, health = nil, contract.NodeHealth{Status: contract.HealthDown}
	}
	return contract.DataNode{NodeKind: contract.NodeCentral, ConnectorVersion: "1.0.0", Feeds: orEmpty(feeds),
		Health: health,
		Capabilities: contract.NodeCapabilities{SupportedTypes: []contract.CommandType{contract.TypeTaskStart},
			StateKinds: []contract.StateKind{contract.KindNode}, ReportFormats: []contract.ReportFormatCapability{}},
		Policy:       contract.Policy{Allow: []contract.CommandType{}, SensitivePerHour: 30, TotalPerHour: 120},
		PolicySHA256: policySHA, ReplayFloor: "2026-10-11T09:00:00Z"}
}

func task(id, tenant, status string) contract.TaskItem {
	return contract.TaskItem{TaskID: id, Tenant: tenant, Name: "Varredura semanal", Status: status, Progress: intp(-1),
		ReportCount: 1}
}

func report(id, taskID, tenant, status string, done bool) contract.ReportItem {
	r := contract.ReportItem{ReportID: id, TaskID: taskID, Tenant: tenant, ScanStatus: status,
		ScanStart:  strp("2026-10-11T02:00:00Z"),
		Counts:     contract.SeverityCounts{Critical: 1, High: 2, Medium: 3, Low: 4, Log: 5, FalsePositive: 6},
		HostsCount: 12}
	if done {
		r.ScanEnd = strp("2026-10-11T03:10:00Z")
	}
	return r
}

func agent(id, tenant string, online bool) contract.AgentItem {
	return contract.AgentItem{AgentID: id, Tenant: tenant, OS: strp("windows"), LastSeen: strp("2026-10-11T11:58:00Z"),
		Online: online}
}

func job(id, tenant string, st contract.RemediationState) contract.RemediationItem {
	return contract.RemediationItem{JobID: id, Tenant: tenant, AgentID: "win-exemplo-01",
		Type: contract.RemediationPackagePatch, State: st, CreatedAt: "2026-10-11T11:50:00Z",
		ExpiresAt: strp("2026-10-12T11:50:00Z")}
}

func feed(f contract.FeedType, version string, age float64) contract.FeedStatus {
	return contract.FeedStatus{Feed: f, Version: version, AgeHours: age}
}

// observe exige que a observação seja gravada.
func (b *box) observe(o state.Observation) {
	b.t.Helper()
	if err := b.Observe(o); err != nil {
		b.t.Fatal(err)
	}
}

// drain entrega tudo o que está na outbox (conferindo cada lote como o hub) e devolve os eventos, na ordem.
func (b *box) drain() []contract.Event {
	b.t.Helper()
	var out []contract.Event
	for {
		bt, ok, err := b.Next(testNode)
		if err != nil {
			b.t.Fatal(err)
		}
		if !ok {
			return out
		}
		out = append(out, checkBatch(b.t, bt)...)
		b.delivered(bt)
	}
}

// describe resume um evento numa linha comparável: tipo, tenant e o data.
func describe(t *testing.T, e contract.Event) string {
	t.Helper()
	tenant := "-"
	if e.Tenant != nil {
		tenant = *e.Tenant
	}
	return fmt.Sprintf("%s %s %s", e.Type, tenant, e.Data)
}

func (b *box) expect(want ...string) []contract.Event {
	b.t.Helper()
	got := b.drain()
	var desc []string
	for _, e := range got {
		desc = append(desc, describe(b.t, e))
	}
	if !slices.Equal(desc, want) {
		b.t.Fatalf("eventos:\n  %s\nesperava:\n  %s", strings.Join(desc, "\n  "), strings.Join(want, "\n  "))
	}
	return got
}

// Sem linha de base (primeiro boot), a primeira coleta só grava a base: nenhum evento, por mais que haja; a seguinte,
// igual, também não gera nada.
func TestPrimeiraColetaSoGravaABase(t *testing.T) {
	b := newBox(t)
	w := newWorld(t)
	w.tasks = []contract.TaskItem{task(uuidTask1, "acme", "Running")}
	w.reports = []contract.ReportItem{report(uuidReport1, uuidTask1, "acme", "Done", true)}
	w.agents = []contract.AgentItem{agent("win-01", "acme", true)}
	w.jobs = []contract.RemediationItem{job("job-1", "acme", contract.RemediationPendingApproval)}
	w.feeds = []contract.FeedStatus{feed(contract.FeedNVT, "202610110600", 100)}
	b.observe(w.obs())
	b.expect()
	b.observe(w.obs())
	b.expect()
}

// task.status_changed sai na transição, com from/to, o último report e o progresso, no escopo do tenant; não se
// repete na coleta seguinte. Uma tarefa nova sai com from "".
func TestTaskStatusChanged(t *testing.T) {
	b := newBox(t)
	w := newWorld(t)
	w.tasks = []contract.TaskItem{task(uuidTask1, "acme", "Running"), task(uuidTask2, "globex", "Done")}
	b.observe(w.obs())
	done := task(uuidTask1, "acme", "Done")
	done.Progress, done.LastReportID = intp(100), strp(uuidReport1)
	w.tasks[0] = done
	at := w.at
	b.observe(w.obs())
	got := b.expect(`task.status_changed acme {"task_id":"` + uuidTask1 +
		`","from":"Running","to":"Done","report_id":"` + uuidReport1 + `","progress":100}`)
	if got[0].OccurredAt != contract.FormatUTCTime(at) {
		t.Fatalf("occurred_at %s, a coleta foi em %s", got[0].OccurredAt, at)
	}
	b.observe(w.obs())
	b.expect()
	// tarefa nova num tenant que já estava na base
	w.tasks = append(w.tasks, task(uuidTask3, "acme", "New"))
	b.observe(w.obs())
	b.expect(`task.status_changed acme {"task_id":"` + uuidTask3 + `","from":"","to":"New","progress":-1}`)
	// só o progresso mudou: nem evento nem gravação
	size := b.fileSize()
	w.tasks[0].Progress = intp(99)
	b.observe(w.obs())
	b.expect()
	if b.fileSize() != size {
		t.Fatal("mudança sem transição gravou")
	}
	// tarefa que some não gera evento; se volta (o mesmo id), é nova: sai com from ""
	gone := w.tasks[0]
	w.tasks = w.tasks[1:]
	b.observe(w.obs())
	b.expect()
	w.tasks = append(w.tasks, gone)
	b.observe(w.obs())
	b.expect(`task.status_changed acme {"task_id":"` + uuidTask1 + `","from":"","to":"Done","report_id":"` +
		uuidReport1 + `","progress":99}`)
}

// report.completed sai quando o report chega a Done (com início e fim), com o resumo de contagens; não se repete. Um
// report novo já Done também sai; um Done ainda sem o fim espera o fim.
func TestReportCompleted(t *testing.T) {
	b := newBox(t)
	w := newWorld(t)
	w.reports = []contract.ReportItem{report(uuidReport1, uuidTask1, "acme", "Running", false)}
	b.observe(w.obs())
	w.reports[0] = report(uuidReport1, uuidTask1, "acme", "Done", true)
	b.observe(w.obs())
	want := `report.completed acme {"report_id":"` + uuidReport1 + `","task_id":"` + uuidTask1 +
		`","scan_start":"2026-10-11T02:00:00Z","scan_end":"2026-10-11T03:10:00Z","counts":{"critical":1,"high":2,` +
		`"medium":3,"low":4,"log":5,"false_positive":6},"hosts_count":12}`
	b.expect(want)
	b.observe(w.obs())
	b.expect()
	// novo e já Done entre duas coletas
	w.reports = append(w.reports, report(uuidReport2, uuidTask2, "globex", "Done", true))
	b.observe(w.obs())
	b.expect(strings.NewReplacer(uuidReport1, uuidReport2, uuidTask1, uuidTask2,
		"report.completed acme", "report.completed globex").Replace(want))
	// Done sem o fim: espera
	w.reports = append(w.reports, report(uuidReport3, uuidTask3, "acme", "Done", false))
	b.observe(w.obs())
	b.expect()
	w.reports[2] = report(uuidReport3, uuidTask3, "acme", "Done", true)
	b.observe(w.obs())
	if got := b.drain(); len(got) != 1 || got[0].Type != contract.EventReportCompleted {
		t.Fatalf("o report com o fim não saiu: %v", got)
	}
	// Running → Stopped não é conclusão
	w.reports = append(w.reports, report(uuidN(4), uuidTask3, "acme", "Running", false))
	b.observe(w.obs())
	w.reports[3].ScanStatus = "Stopped"
	b.observe(w.obs())
	b.expect()
}

// agent.online e agent.offline saem na transição do online do ingest; um agente novo online sai como agent.online, um
// novo offline não sai. Não se repetem.
func TestAgentOnlineOffline(t *testing.T) {
	b := newBox(t)
	w := newWorld(t)
	w.agents = []contract.AgentItem{agent("win-01", "acme", true), agent("win-02", "acme", false)}
	b.observe(w.obs())
	w.agents = []contract.AgentItem{agent("win-01", "acme", false), agent("win-02", "acme", true),
		agent("win-03", "globex", true), agent("win-04", "globex", false)}
	b.observe(w.obs())
	b.expect(
		`agent.offline acme {"agent_id":"win-01","last_seen":"2026-10-11T11:58:00Z"}`,
		`agent.online acme {"agent_id":"win-02","last_seen":"2026-10-11T11:58:00Z"}`,
		`agent.online globex {"agent_id":"win-03","last_seen":"2026-10-11T11:58:00Z"}`,
	)
	b.observe(w.obs())
	b.expect()
	// o mesmo agent_id em dois tenants são dois agentes
	w.agents = append(w.agents, agent("win-01", "globex", true))
	b.observe(w.obs())
	b.expect(`agent.online globex {"agent_id":"win-01","last_seen":"2026-10-11T11:58:00Z"}`)
}

// remediation.pending_approval sai para job NOVO em PENDING_APPROVAL; job novo em outro estado, ou um job que já
// existia, não sai. Não se repete.
func TestRemediationPendingApproval(t *testing.T) {
	b := newBox(t)
	w := newWorld(t)
	w.jobs = []contract.RemediationItem{job("job-1", "acme", contract.RemediationApproved)}
	b.observe(w.obs())
	w.jobs = append(w.jobs, job("job-2", "acme", contract.RemediationPendingApproval),
		job("job-3", "globex", contract.RemediationApproved))
	w.jobs[0].State = contract.RemediationPendingApproval
	b.observe(w.obs())
	b.expect(`remediation.pending_approval acme {"job_id":"job-2","agent_id":"win-exemplo-01","type":"package_patch",` +
		`"created_at":"2026-10-11T11:50:00Z","expires_at":"2026-10-12T11:50:00Z"}`)
	b.observe(w.obs())
	b.expect()
	w.jobs[1].State = contract.RemediationApproved
	b.observe(w.obs())
	b.expect()
}

// feed.updated sai quando a versão muda (com a anterior; sem ela para um feed visto pela primeira vez); feed.stale
// sai uma vez por passagem da idade sobre FLEET_FEED_STALE_HOURS. Os dois são de escopo nó (sem tenant).
func TestFeedUpdatedEStale(t *testing.T) {
	b := newBox(t)
	w := newWorld(t)
	w.feeds = []contract.FeedStatus{feed(contract.FeedNVT, "202610040600", 10)}
	b.observe(w.obs())
	w.feeds[0] = feed(contract.FeedNVT, "202610110600", 1)
	b.observe(w.obs())
	b.expect(`feed.updated - {"feed":"nvt","version":"202610110600","previous_version":"202610040600"}`)
	w.feeds[0].AgeHours = 72 // no limiar ainda não passou
	b.observe(w.obs())
	b.expect()
	w.feeds[0].AgeHours = 72.5
	b.observe(w.obs())
	b.expect(`feed.stale - {"feed":"nvt","version":"202610110600","age_hours":72.5,"stale_after_hours":72}`)
	w.feeds[0].AgeHours = 90 // a mesma passagem
	b.observe(w.obs())
	b.expect()
	w.feeds[0] = feed(contract.FeedNVT, "202610180600", 2) // atualizou: a passagem acaba
	b.observe(w.obs())
	b.expect(`feed.updated - {"feed":"nvt","version":"202610180600","previous_version":"202610110600"}`)
	w.feeds[0].AgeHours = 100 // nova passagem
	b.observe(w.obs())
	b.expect(`feed.stale - {"feed":"nvt","version":"202610180600","age_hours":100,"stale_after_hours":72}`)
	// um feed visto pela primeira vez, já velho: atualizado (sem anterior) e velho
	w.feeds = append(w.feeds, feed(contract.FeedSCAP, "202610010000", 200))
	b.observe(w.obs())
	b.expect(`feed.updated - {"feed":"scap","version":"202610010000"}`,
		`feed.stale - {"feed":"scap","version":"202610010000","age_hours":200,"stale_after_hours":72}`)
	// node sem o gvmd: feeds desconhecidos, nada muda; de volta com as mesmas versões, nada sai
	w.partial = true
	b.observe(w.obs())
	b.expect()
	w.partial = false
	b.observe(w.obs())
	b.expect()
	// feed que some do get_feeds e volta igual: nada; volta com outra versão: atualizado em relação à última vista
	w.feeds = w.feeds[:1]
	b.observe(w.obs())
	b.expect()
	w.feeds = append(w.feeds, feed(contract.FeedSCAP, "202610020000", 1))
	b.observe(w.obs())
	b.expect(`feed.updated - {"feed":"scap","version":"202610020000","previous_version":"202610010000"}`)
}

// O node montado sem o gvmd não serve de base para os feeds: a base deles nasce do primeiro node com o gvmd, sem
// evento — os feeds não "aparecem" quando o gvmd volta.
func TestNodeSemGVMDNaoViraBaseDosFeeds(t *testing.T) {
	b := newBox(t)
	w := newWorld(t)
	w.feeds = []contract.FeedStatus{feed(contract.FeedNVT, "1", 1), feed(contract.FeedSCAP, "1", 100)}
	w.partial = true
	b.observe(w.obs())
	w.partial = false
	b.observe(w.obs())
	b.expect()
	w.feeds[0] = feed(contract.FeedNVT, "2", 1)
	b.observe(w.obs())
	b.expect(`feed.updated - {"feed":"nvt","version":"2","previous_version":"1"}`)
}

// Um registro corrompido derruba a linha de base: depois do reinício, a primeira coleta só refaz a base, sem evento —
// nunca compara com uma base que já não é a que gerou os registros seguintes.
func TestCorrupcaoDerrubaABaseSemEventos(t *testing.T) {
	b := newBox(t)
	w := newWorld(t)
	w.tasks = []contract.TaskItem{task(uuidTask1, "acme", "Running")}
	b.observe(w.obs())
	w.tasks = append(w.tasks, task(uuidTask2, "acme", "New"))
	b.observe(w.obs())
	b.expect(`task.status_changed acme {"task_id":"` + uuidTask2 + `","from":"","to":"New","progress":-1}`)
	path := filepath.Join(b.dir, FileName)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// estraga o registro da segunda coleta (o que pôs a tarefa 2): a base da primeira já estava lida
	data = bytes.Replace(data, []byte(`"value":"New"`), []byte(`"value":"Nex"`), 1)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	b.restartRaw()
	if r := b.Recovery(); r.Corrupt == 0 || !r.BaselineLost {
		t.Fatalf("%+v", r)
	}
	w.tasks[0].Status = "Done"
	b.observe(w.obs())
	b.expect()
	w.tasks[0].Status = "Stopped"
	b.observe(w.obs())
	b.expect(`task.status_changed acme {"task_id":"` + uuidTask1 + `","from":"Done","to":"Stopped","progress":-1}`)
}

// A base de um kind sem nenhum objeto e a dos feeds sem nenhum feed (gvmd recém-instalado) também atravessam um
// reinício: o primeiro objeto e o primeiro feed depois dele são novos de verdade.
func TestBaseVaziaAtravessaOReinicio(t *testing.T) {
	b := newBox(t)
	w := newWorld(t)
	b.observe(w.obs()) // nenhum objeto, nenhum feed
	b.restart()
	if r := b.Recovery(); r.BaselineLost {
		t.Fatalf("%+v", r)
	}
	w.tasks = []contract.TaskItem{task(uuidTask1, "acme", "New")}
	w.feeds = []contract.FeedStatus{feed(contract.FeedNVT, "1", 1)}
	b.observe(w.obs())
	b.expect(`feed.updated - {"feed":"nvt","version":"1"}`,
		`task.status_changed acme {"task_id":"`+uuidTask1+`","from":"","to":"New","progress":-1}`)
}

// O limiar é o FLEET_FEED_STALE_HOURS do nó.
func TestLimiarDoFeedVemDaConfiguracao(t *testing.T) {
	b := newBox(t)
	o, err := open(Config{StateDir: b.dir, NodeKind: contract.NodeSensor, StaleAfterHours: 24}, b.faults.ops(),
		b.ids.next)
	if err != nil {
		t.Fatal(err)
	}
	b.Outbox = o
	w := newWorld(t)
	w.feeds = []contract.FeedStatus{feed(contract.FeedCERT, "20261011", 1)}
	b.observe(w.obs())
	w.feeds[0].AgeHours = 25
	b.observe(w.obs())
	b.expect(`feed.stale - {"feed":"cert","version":"20261011","age_hours":25,"stale_after_hours":24}`)
	for _, bad := range []int{-1, MaxStaleHours + 1} {
		if _, err := open(Config{StateDir: b.dir, NodeKind: contract.NodeSensor, StaleAfterHours: bad}, b.faults.ops(),
			b.ids.next); err == nil {
			t.Errorf("limiar %d aceito", bad)
		}
	}
}

// Desligar um tenant faz os objetos dele sumirem das listas, e religá-lo, voltarem: isso não é transição de tarefa,
// report, agente nem job — nem quando eles mudaram no meio. Os outros tenants seguem normais, e depois de religado o
// tenant volta a ter transições.
func TestLigarDesligarTenantSemEvento(t *testing.T) {
	b := newBox(t)
	w := newWorld(t)
	w.tasks = []contract.TaskItem{task(uuidTask1, "acme", "Running"), task(uuidTask2, "globex", "Running")}
	w.reports = []contract.ReportItem{report(uuidReport2, uuidTask2, "globex", "Running", false)}
	w.agents = []contract.AgentItem{agent("win-01", "globex", true)}
	w.jobs = []contract.RemediationItem{job("job-1", "globex", contract.RemediationApproved)}
	b.observe(w.obs())

	// desliga globex: os objetos dele somem
	w.tenants = []string{"acme"}
	keepAcme := func() {
		w.tasks = slices.DeleteFunc(w.tasks, func(i contract.TaskItem) bool { return i.Tenant == "globex" })
		w.reports, w.agents, w.jobs = nil, nil, nil
	}
	keepAcme()
	b.observe(w.obs())
	b.expect()

	// enquanto desligado, tudo de globex muda — e acme também
	w.tasks[0].Status = "Done"
	b.observe(w.obs())
	b.expect(`task.status_changed acme {"task_id":"` + uuidTask1 + `","from":"Running","to":"Done","progress":-1}`)

	// religa globex: os objetos voltam, mudados, e um novo apareceu — nada sai
	w.tenants = []string{"acme", "globex"}
	w.tasks = append(w.tasks, task(uuidTask2, "globex", "Done"), task(uuidTask3, "globex", "New"))
	w.reports = []contract.ReportItem{report(uuidReport2, uuidTask2, "globex", "Done", true)}
	w.agents = []contract.AgentItem{agent("win-01", "globex", false)}
	w.jobs = []contract.RemediationItem{job("job-1", "globex", contract.RemediationApproved),
		job("job-2", "globex", contract.RemediationPendingApproval)}
	b.observe(w.obs())
	b.expect()

	// religado, globex volta a ter transições
	w.tasks[1].Status = "Requested"
	w.agents[0].Online = true
	b.observe(w.obs())
	b.expect(`task.status_changed globex {"task_id":"`+uuidTask2+`","from":"Done","to":"Requested","progress":-1}`,
		`agent.online globex {"agent_id":"win-01","last_seen":"2026-10-11T11:58:00Z"}`)

	// um tenant que aparece pela primeira vez (cadastrado agora) também só entra na base
	w.tenants = append(w.tenants, "initech")
	w.tasks = append(w.tasks, task(uuidN(5), "initech", "Running"))
	w.agents = append(w.agents, agent("srv-01", "initech", true))
	b.observe(w.obs())
	b.expect()

	// um tenant que entra sem nenhum objeto entra na base mesmo assim: o primeiro objeto dele é novo de verdade
	w.tenants = append(w.tenants, "umbrella")
	b.observe(w.obs())
	b.expect()
	w.tasks = append(w.tasks, task(uuidN(6), "umbrella", "New"))
	b.observe(w.obs())
	b.expect(`task.status_changed umbrella {"task_id":"` + uuidN(6) + `","from":"","to":"New","progress":-1}`)
}

// Os tenants atribuídos são por kind: um tenant que só sai dos kinds do gvmd (perdeu o usuário gvmd próprio) não
// gera evento lá, e os agentes dele seguem com transições.
func TestTenantsSaoPorKind(t *testing.T) {
	b := newBox(t)
	w := newWorld(t)
	w.tasks = []contract.TaskItem{task(uuidTask1, "globex", "Running")}
	w.agents = []contract.AgentItem{agent("win-01", "globex", true)}
	b.observe(w.obs())
	w.tenantsOf[contract.KindTasks] = []string{"acme"}
	w.tenantsOf[contract.KindReports] = []string{"acme"}
	w.tasks = nil
	w.agents[0].Online = false
	b.observe(w.obs())
	b.expect(`agent.offline globex {"agent_id":"win-01","last_seen":"2026-10-11T11:58:00Z"}`)
	delete(w.tenantsOf, contract.KindTasks)
	delete(w.tenantsOf, contract.KindReports)
	w.tasks = []contract.TaskItem{task(uuidTask1, "globex", "Done")}
	b.observe(w.obs())
	b.expect()
}

// Um reinício entre duas coletas não perde nem duplica: o que já saiu não sai de novo, e a transição que aconteceu
// com o conector parado sai depois do reinício.
func TestReinicioEntreColetasSemPerderNemDuplicar(t *testing.T) {
	b := newBox(t)
	w := newWorld(t)
	w.tasks = []contract.TaskItem{task(uuidTask1, "acme", "Running")}
	w.agents = []contract.AgentItem{agent("win-01", "acme", true)}
	w.feeds = []contract.FeedStatus{feed(contract.FeedNVT, "1", 1)}
	b.observe(w.obs())
	w.tasks[0].Status = "Done"
	b.observe(w.obs())
	b.expect(`task.status_changed acme {"task_id":"` + uuidTask1 + `","from":"Running","to":"Done","progress":-1}`)

	b.restart()
	if r := b.Recovery(); r.BaselineLost {
		t.Fatalf("a linha de base se perdeu no reinício: %+v", r)
	}
	b.observe(w.obs()) // o mesmo estado: nada de novo
	b.expect()

	// com o conector parado, o agente caiu e o feed atualizou
	w.agents[0].Online = false
	w.feeds[0] = feed(contract.FeedNVT, "2", 1)
	b.restart()
	b.observe(w.obs())
	b.expect(`feed.updated - {"feed":"nvt","version":"2","previous_version":"1"}`,
		`agent.offline acme {"agent_id":"win-01","last_seen":"2026-10-11T11:58:00Z"}`)

	// uma transição registrada e ainda não entregue volta depois do reinício, uma vez só
	w.tasks[0].Status = "Requested"
	b.observe(w.obs())
	b.restart()
	b.observe(w.obs())
	b.expect(`task.status_changed acme {"task_id":"` + uuidTask1 + `","from":"Done","to":"Requested","progress":-1}`)
}

// Uma observação que não se grava não avança nada: nem eventos nem linha de base; a coleta seguinte — mesmo com o
// mesmo retrato — gera a transição, uma vez só.
func TestObservacaoQueNaoGravaNaoAvanca(t *testing.T) {
	b := newBox(t)
	w := newWorld(t)
	w.tasks = []contract.TaskItem{task(uuidTask1, "acme", "Running")}
	b.observe(w.obs())
	w.tasks[0].Status = "Done"
	o := w.obs()
	b.faults.set(func(f *faults) { f.syncErr = errDisco })
	if err := b.Observe(o); err == nil {
		t.Fatal("a observação não gravou e não deu erro")
	}
	if b.Len() != 0 {
		t.Fatalf("Len %d", b.Len())
	}
	b.faults.set(func(f *faults) { f.syncErr = nil })
	b.observe(o)
	b.expect(`task.status_changed acme {"task_id":"` + uuidTask1 + `","from":"Running","to":"Done","progress":-1}`)
	b.observe(o)
	b.expect()
}

// Uma gravação que falha seguida de queda: se a linha foi cortada de volta, o reinício compara com a base antiga e a
// transição sai uma vez; se a linha ficou inteira no arquivo (o fsync falhou, o corte também), o reinício a lê com a
// base e os eventos juntos, e a transição também sai uma vez — nunca zero, nunca duas.
func TestQuedaDepoisDeGravacaoQueFalhou(t *testing.T) {
	for _, cutFails := range []bool{false, true} {
		b := newBox(t)
		w := newWorld(t)
		w.tasks = []contract.TaskItem{task(uuidTask1, "acme", "Running")}
		b.observe(w.obs())
		w.tasks[0].Status = "Done"
		o := w.obs()
		b.faults.set(func(f *faults) {
			f.syncErr = errDisco
			if cutFails {
				f.truncateErr = errDisco
			}
		})
		if err := b.Observe(o); err == nil {
			t.Fatal("a observação não gravou e não deu erro")
		}
		b.faults.set(func(f *faults) { f.syncErr, f.truncateErr = nil, nil })
		b.restart() // a queda: a memória se perde, o arquivo fica
		b.observe(o)
		b.observe(w.obs())
		b.expect(`task.status_changed acme {"task_id":"` + uuidTask1 + `","from":"Running","to":"Done","progress":-1}`)
	}
}

// Um kind cuja coleta falhou não muda a base: a transição aparece na próxima coleta que der certo, contra a base de
// antes da falha.
func TestKindQueFalhouNaoMudaABase(t *testing.T) {
	b := newBox(t)
	w := newWorld(t)
	w.tasks = []contract.TaskItem{task(uuidTask1, "acme", "Running")}
	b.observe(w.obs())
	w.failed[contract.KindTasks] = true
	w.tasks = nil
	b.observe(w.obs())
	b.expect()
	w.failed[contract.KindTasks] = false
	w.tasks = []contract.TaskItem{task(uuidTask1, "acme", "Done")}
	b.observe(w.obs())
	b.expect(`task.status_changed acme {"task_id":"` + uuidTask1 + `","from":"Running","to":"Done","progress":-1}`)
}

// Um objeto repetido no retrato (mesmo tenant e id) é ambíguo: não gera evento e a base dele fica como estava.
func TestObjetoRepetidoNoRetratoEIgnorado(t *testing.T) {
	b := newBox(t)
	w := newWorld(t)
	w.agents = []contract.AgentItem{agent("win-01", "acme", true)}
	b.observe(w.obs())
	// repetidos: o agente que está na base e uma tarefa nova; a última cópia de cada um faria evento
	w.agents = []contract.AgentItem{agent("win-01", "acme", true), agent("win-01", "acme", false)}
	w.tasks = []contract.TaskItem{task(uuidTask1, "acme", "New"), task(uuidTask1, "acme", "Running")}
	b.observe(w.obs())
	b.expect()
	w.agents = []contract.AgentItem{agent("win-01", "acme", false)}
	w.tasks = []contract.TaskItem{task(uuidTask1, "acme", "Running")}
	b.observe(w.obs())
	b.expect(`task.status_changed acme {"task_id":"`+uuidTask1+`","from":"","to":"Running","progress":-1}`,
		`agent.offline acme {"agent_id":"win-01","last_seen":"2026-10-11T11:58:00Z"}`)
	// feed repetido: idem (o nvt visto pela primeira vez sai como atualizado, sem versão anterior)
	w.feeds = []contract.FeedStatus{feed(contract.FeedNVT, "1", 1)}
	b.observe(w.obs())
	b.expect(`feed.updated - {"feed":"nvt","version":"1"}`)
	w.feeds = []contract.FeedStatus{feed(contract.FeedNVT, "2", 1), feed(contract.FeedNVT, "3", 1)}
	b.observe(w.obs())
	b.expect()
	w.feeds = []contract.FeedStatus{feed(contract.FeedNVT, "3", 1)}
	b.observe(w.obs())
	b.expect(`feed.updated - {"feed":"nvt","version":"3","previous_version":"1"}`)
}

// Fora do nó central não há agents nem remediation: um retrato deles é ignorado, e uma base de outro node_kind no
// mesmo FLEET_STATE_DIR é podada no boot.
func TestKindsDoNoCentralSoNoCentral(t *testing.T) {
	b := newBox(t)
	w := newWorld(t)
	w.agents = []contract.AgentItem{agent("win-01", "acme", true)}
	b.observe(w.obs())
	b.kind = contract.NodeStandalone
	b.restart()
	if _, ok := b.base.kinds[contract.KindAgents]; ok {
		t.Fatal("a base de agents ficou num nó standalone")
	}
	w.agents[0].Online = false
	w.jobs = []contract.RemediationItem{job("job-1", "acme", contract.RemediationPendingApproval)}
	b.observe(w.obs())
	b.expect()
}

// Toda transição de um ciclo vai num registro só, na ordem: feeds, tarefas, reports, agentes, jobs; dentro de cada
// kind, por tenant e id.
func TestOrdemDosEventosDeUmCiclo(t *testing.T) {
	b := newBox(t)
	w := newWorld(t)
	w.tasks = []contract.TaskItem{task(uuidTask2, "globex", "Running"), task(uuidTask1, "acme", "Running")}
	w.reports = []contract.ReportItem{report(uuidReport1, uuidTask1, "acme", "Running", false)}
	w.agents = []contract.AgentItem{agent("win-01", "acme", false)}
	w.jobs = []contract.RemediationItem{}
	w.feeds = []contract.FeedStatus{feed(contract.FeedNVT, "1", 1)}
	b.observe(w.obs())
	w.tasks = []contract.TaskItem{task(uuidTask2, "globex", "Done"), task(uuidTask1, "acme", "Done")}
	w.reports[0] = report(uuidReport1, uuidTask1, "acme", "Done", true)
	w.agents[0].Online = true
	w.jobs = []contract.RemediationItem{job("job-1", "acme", contract.RemediationPendingApproval)}
	w.feeds[0] = feed(contract.FeedNVT, "2", 1)
	before := b.fileSize()
	b.observe(w.obs())
	var types []string
	for _, e := range b.drain() {
		types = append(types, string(e.Type)+" "+*orDash(e.Tenant))
	}
	want := []string{"feed.updated -", "task.status_changed acme", "task.status_changed globex",
		"report.completed acme", "agent.online acme", "remediation.pending_approval acme"}
	if !slices.Equal(types, want) {
		t.Fatalf("ordem %v", types)
	}
	if b.fileSize() <= before {
		t.Fatal("nada gravado")
	}
}

func orDash(s *string) *string {
	if s == nil {
		d := "-"
		return &d
	}
	return s
}
