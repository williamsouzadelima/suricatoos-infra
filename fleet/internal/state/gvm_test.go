package state

import (
	"bytes"
	"context"
	"fmt"
	"math/rand/v2"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/williamsouzadelima/suricatoos-infra/fleet/contract"
	"github.com/williamsouzadelima/suricatoos-infra/fleet/internal/tenant"
)

func fullTask(id, tenantName string) contract.TaskItem {
	return contract.TaskItem{TaskID: id, Tenant: tenantName, Name: "Varredura semanal", Status: "Done",
		Progress: intp(-1), TargetID: strp(uuidTarget1), ScanConfigID: strp(uuidConfig), ScannerID: strp(uuidScanner),
		ScheduleID: strp(uuidSched1), LastReportID: strp(uuidReport1), LastReportAt: strp("2026-10-11T02:00:00Z"),
		ReportCount: 3}
}

func TestTasksConteudoOrdenadoPorID(t *testing.T) {
	f := newFakes()
	second, first := fullTask(uuidTask2, "globex"), fullTask(uuidTask1, "acme")
	second.Status, second.Progress = "Running", intp(42)
	f.gvm.tasks = contract.DataTasks{Items: []contract.TaskItem{second, first}, UnattributedCount: 2}
	c := collectOnce(t, f, contract.NodeStandalone)
	got := current(t, c, contract.KindTasks).(*contract.DataTasks)
	want := &contract.DataTasks{Items: []contract.TaskItem{first, second}, UnattributedCount: 2}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("tasks %+v", got)
	}
}

// O dono gvmd de cada tenant conhecido vai para o fleet_ops; um nome fora do padrão de tenant, um usuário gvmd
// que dois tenants dividem (a frota não adivinha), um usuário que o fleet_ops recusaria e um tenant sem usuário
// ficam de fora — os objetos deles saem só como contagem. Um tenant desabilitado continua conhecido.
func TestOwnersSoDosTenantsConhecidos(t *testing.T) {
	f := newFakes()
	f.tenants.list = []tenant.Listing{
		{Name: "acme", Enabled: true, GVMUser: "tenant-acme"},
		{Name: "initech", Enabled: false, GVMUser: "tenant-initech"},
		{Name: "-ruim-", Enabled: true, GVMUser: "tenant-ruim"},
		{Name: "a", Enabled: true, GVMUser: "compartilhado"},
		{Name: "b", Enabled: true, GVMUser: "compartilhado"},
		{Name: "globex", Enabled: true},
		{Name: "ctrl", Enabled: true, GVMUser: "u\x01"},
		{Name: "longo", Enabled: true, GVMUser: strings.Repeat("u", 257)},
		{Name: "umbrella", Enabled: true, GVMUser: strings.Repeat("u", 256)},
	}
	collectOnce(t, f, contract.NodeStandalone)
	want := map[string]string{"tenant-acme": "acme", "tenant-initech": "initech", strings.Repeat("u", 256): "umbrella"}
	for _, kind := range []contract.StateKind{contract.KindTasks, contract.KindTargets, contract.KindSchedules, contract.KindReports} {
		if got := f.gvm.owners[kind]; len(got) != 1 || !reflect.DeepEqual(got[0], want) {
			t.Errorf("%s: owners %v", kind, got)
		}
	}
}

// Um item com tenant que não veio do mapa de donos (ou de nome inválido) nunca é listado: só contado.
func TestItemDeTenantDesconhecidoSoContado(t *testing.T) {
	f := newFakes()
	f.gvm.tasks = contract.DataTasks{Items: []contract.TaskItem{
		fullTask(uuidTask1, "acme"), fullTask(uuidTask2, "intruso"), fullTask(uuidTask3, "-ruim-"), fullTask(uuidN(9), ""),
	}, UnattributedCount: 1}
	c := collectOnce(t, f, contract.NodeStandalone)
	got := current(t, c, contract.KindTasks).(*contract.DataTasks)
	if len(got.Items) != 1 || got.Items[0].Tenant != "acme" || got.UnattributedCount != 4 {
		t.Fatalf("tasks %+v", got)
	}
}

// Um item que o schema recusaria não sai: é só contado, e o resto da lista segue.
func TestItemForaDoSchemaSoContado(t *testing.T) {
	ctrl := "Nome" + string(rune(0x01))
	bad := []func(*contract.TaskItem){
		func(i *contract.TaskItem) { i.TaskID = "nao-e-uuid" },
		func(i *contract.TaskItem) { i.Name = ctrl },
		func(i *contract.TaskItem) { i.Name = "" },
		func(i *contract.TaskItem) { i.Name = strings.Repeat("n", 129) },
		func(i *contract.TaskItem) { i.Status = "Done2" },
		func(i *contract.TaskItem) { i.Progress = intp(101) },
		func(i *contract.TaskItem) { i.Progress = intp(-2) },
		func(i *contract.TaskItem) { i.TargetID = strp("X") },
		func(i *contract.TaskItem) { i.LastReportAt = strp("2026-02-30T00:00:00Z") },
		func(i *contract.TaskItem) { i.ReportCount = -1 },
	}
	f := newFakes()
	items := []contract.TaskItem{fullTask(uuidTask1, "acme")}
	for n, mutate := range bad {
		it := fullTask(uuidN(100+n), "acme")
		mutate(&it)
		items = append(items, it)
	}
	f.gvm.tasks = contract.DataTasks{Items: items}
	got := current(t, collectOnce(t, f, contract.NodeStandalone), contract.KindTasks).(*contract.DataTasks)
	if len(got.Items) != 1 || got.Items[0].TaskID != uuidTask1 || got.UnattributedCount != int64(len(bad)) {
		t.Fatalf("tasks %+v", got)
	}
}

func fullTarget(id, tenantName string, hosts ...string) contract.TargetItem {
	return contract.TargetItem{TargetID: id, Tenant: tenantName, Name: "Rede LAB", Hosts: hosts,
		LiteralEntries: int64(len(hosts)), NonLiteralEntries: 1, ExcludeEntries: i64p(2), PortListID: strp(uuidPorts),
		AliveTest: strp("ICMP, TCP-SYN Service & ARP Ping"), InUse: true}
}

func TestTargetsSoComHostsLiterais(t *testing.T) {
	f := newFakes()
	good := fullTarget(uuidTarget1, "acme", "192.0.2.0/24", "198.51.100.3", "2001:db8::/32")
	f.gvm.targets = contract.DataTargets{Items: []contract.TargetItem{
		good,
		fullTarget(uuidTarget2, "acme", "192.0.2.10", "cafe.be"),        // hostname só de hex
		fullTarget(uuidN(3), "acme", "srv01.exemplo.com.br"),             // hostname
		fullTarget(uuidN(4), "acme", "192.0.2.1-192.0.2.9"),              // faixa
		fullTarget(uuidN(5), "acme", strings.Repeat("1", 300)),           // longo demais
		fullTarget(uuidN(6), "globex"),                                    // sem hosts literais: lista vazia
	}}
	c := collectOnce(t, f, contract.NodeStandalone)
	s, _ := c.Current(contract.KindTargets)
	for _, leak := range []string{"cafe.be", "srv01", "exemplo"} {
		if bytes.Contains(s.Data, []byte(leak)) {
			t.Fatalf("hostname %q saiu no estado: %s", leak, s.Data)
		}
	}
	got := current(t, c, contract.KindTargets).(*contract.DataTargets)
	empty := fullTarget(uuidN(6), "globex")
	empty.Hosts = []string{}
	if want := []contract.TargetItem{empty, good}; !reflect.DeepEqual(got.Items, want) || got.UnattributedCount != 4 {
		t.Fatalf("targets %+v", got)
	}
}

func TestTargetsCortaHostsEm256SemPerderAContagem(t *testing.T) {
	f := newFakes()
	var hosts []string
	for i := range 300 {
		hosts = append(hosts, fmt.Sprintf("10.0.%d.%d", i/256, i%256))
	}
	it := fullTarget(uuidTarget1, "acme", hosts...)
	f.gvm.targets = contract.DataTargets{Items: []contract.TargetItem{it}}
	got := current(t, collectOnce(t, f, contract.NodeStandalone), contract.KindTargets).(*contract.DataTargets)
	if len(got.Items) != 1 || !slices.Equal(got.Items[0].Hosts, hosts[:256]) || got.Items[0].LiteralEntries != 300 || got.Truncated {
		t.Fatalf("hosts %d, literal_entries %d, truncated %v", len(got.Items[0].Hosts), got.Items[0].LiteralEntries, got.Truncated)
	}
}

func fullSchedule(id, tenantName string, tasks ...string) contract.ScheduleItem {
	return contract.ScheduleItem{ScheduleID: id, Tenant: tenantName, Name: "Semanal", Timezone: "America/Sao_Paulo",
		ICalendar: ical, TaskIDs: tasks}
}

func TestSchedulesTarefasOrdenadasSemRepeticao(t *testing.T) {
	f := newFakes()
	f.gvm.schedules = contract.DataSchedules{Items: []contract.ScheduleItem{
		fullSchedule(uuidSched1, "acme", uuidTask3, uuidTask1, uuidTask3),
		fullSchedule(uuidN(2), "acme", uuidTask1, "nao-e-uuid"),
		fullSchedule(uuidN(3), "acme"),
	}}
	got := current(t, collectOnce(t, f, contract.NodeStandalone), contract.KindSchedules).(*contract.DataSchedules)
	if len(got.Items) != 2 || got.UnattributedCount != 1 {
		t.Fatalf("schedules %+v", got)
	}
	if !slices.Equal(got.Items[1].TaskIDs, []string{uuidTask1, uuidTask3}) || got.Items[0].TaskIDs == nil {
		t.Fatalf("task_ids %v / %v", got.Items[0].TaskIDs, got.Items[1].TaskIDs)
	}
}

func TestSchedulesMaisDe256TarefasCortaEMarcaTruncated(t *testing.T) {
	f := newFakes()
	var tasks []string
	for i := range 300 {
		tasks = append(tasks, uuidN(1000+i))
	}
	f.gvm.schedules = contract.DataSchedules{Items: []contract.ScheduleItem{fullSchedule(uuidSched1, "acme", tasks...)}}
	got := current(t, collectOnce(t, f, contract.NodeStandalone), contract.KindSchedules).(*contract.DataSchedules)
	if len(got.Items) != 1 || len(got.Items[0].TaskIDs) != 256 || !got.Truncated {
		t.Fatalf("task_ids %d truncated %v", len(got.Items[0].TaskIDs), got.Truncated)
	}
}

func fullReport(id, tenantName string) contract.ReportItem {
	return contract.ReportItem{ReportID: id, TaskID: uuidTask1, Tenant: tenantName, ScanStatus: "Done",
		ScanStart: strp("2026-10-10T02:00:05Z"), ScanEnd: strp("2026-10-10T03:10:00Z"),
		Counts:     contract.SeverityCounts{Critical: 1, High: 2, Low: 1, Log: 4, FalsePositive: 1}, HostsCount: 3}
}

// reports sai na ordem da fonte (o mais recente primeiro, como o fleet_ops ordena) e só com contagens.
func TestReportsNaOrdemDaFonte(t *testing.T) {
	f := newFakes()
	newer, older := fullReport(uuidReport2, "acme"), fullReport(uuidReport1, "acme")
	badCount := fullReport(uuidN(5), "acme")
	badCount.Counts.High = -1
	f.gvm.reports = contract.DataReports{Items: []contract.ReportItem{newer, badCount, older}}
	got := current(t, collectOnce(t, f, contract.NodeStandalone), contract.KindReports).(*contract.DataReports)
	if want := []contract.ReportItem{newer, older}; !reflect.DeepEqual(got.Items, want) || got.UnattributedCount != 1 {
		t.Fatalf("reports %+v", got)
	}
}

func TestTetoDeItensMarcaTruncated(t *testing.T) {
	f := newFakes()
	for i := range maxTasks + 1 {
		f.gvm.tasks.Items = append(f.gvm.tasks.Items, contract.TaskItem{TaskID: uuidN(maxTasks - i), Tenant: "acme",
			Name: "t", Status: "New"})
	}
	got := current(t, collectOnce(t, f, contract.NodeStandalone), contract.KindTasks).(*contract.DataTasks)
	if len(got.Items) != maxTasks || !got.Truncated || got.Items[0].TaskID != uuidN(0) || got.Items[maxTasks-1].TaskID != uuidN(maxTasks-1) {
		t.Fatalf("%d itens, truncated %v", len(got.Items), got.Truncated)
	}
}

// A fonte já cortou ou já contou: o estado soma ao que ele mesmo descarta e mantém o truncated.
func TestTruncatedEContagemDaFonteSeguem(t *testing.T) {
	f := newFakes()
	f.gvm.reports = contract.DataReports{Items: []contract.ReportItem{fullReport(uuidReport1, "intruso")},
		Truncated: true, UnattributedCount: 5}
	got := current(t, collectOnce(t, f, contract.NodeStandalone), contract.KindReports).(*contract.DataReports)
	if !got.Truncated || got.UnattributedCount != 6 || len(got.Items) != 0 {
		t.Fatalf("reports %+v", got)
	}
}

// Uma resposta que o schema recusaria no nível do documento (contagem negativa) é erro do kind, nunca um data.
func TestContagemNegativaDaFonteEErroDoKind(t *testing.T) {
	f := newFakes()
	f.gvm.tasks = contract.DataTasks{Items: []contract.TaskItem{fullTask(uuidTask1, "acme")}}
	c := collectOnce(t, f, contract.NodeStandalone)
	before, ok := c.Current(contract.KindTasks)
	if !ok {
		t.Fatal("sem o retrato bom de antes")
	}
	f.gvm.tasks.UnattributedCount = -1
	c.Collect(context.Background())
	if after, _ := c.Current(contract.KindTasks); after.SHA256 != before.SHA256 || c.Errors()[contract.KindTasks] == nil {
		t.Fatalf("o kind devia manter o retrato e expor o erro: %v", c.Errors())
	}
}

// Mesmo estado, mesma ordem de bytes: a fonte pode devolver os itens em qualquer ordem.
func TestBytesDeterministicosComFonteEmQualquerOrdem(t *testing.T) {
	var items []contract.TargetItem
	for i := range 50 {
		items = append(items, fullTarget(uuidN(i), []string{"acme", "globex"}[i%2], fmt.Sprintf("192.0.2.%d", i)))
	}
	var hashes []string
	var data [][]byte
	for round := range 4 {
		f := newFakes()
		shuffled := slices.Clone(items)
		rand.New(rand.NewPCG(uint64(round), 7)).Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
		f.gvm.targets = contract.DataTargets{Items: shuffled}
		s, _ := collectOnce(t, f, contract.NodeStandalone).Current(contract.KindTargets)
		hashes = append(hashes, s.SHA256)
		data = append(data, s.Data)
	}
	for i := range hashes {
		if hashes[i] != hashes[0] || !bytes.Equal(data[i], data[0]) {
			t.Fatalf("rodada %d: bytes diferentes para o mesmo estado", i)
		}
	}
}

// Itens repetidos (mesmo id) também ficam numa ordem só: o desempate é o próprio conteúdo.
func TestDesempateDeIDRepetidoEDeterministico(t *testing.T) {
	a, b := fullTask(uuidTask1, "acme"), fullTask(uuidTask1, "acme")
	b.Name = "Outra"
	var got [][]byte
	for _, order := range [][]contract.TaskItem{{a, b}, {b, a}} {
		f := newFakes()
		f.gvm.tasks = contract.DataTasks{Items: order}
		s, _ := collectOnce(t, f, contract.NodeStandalone).Current(contract.KindTasks)
		got = append(got, s.Data)
	}
	if !bytes.Equal(got[0], got[1]) {
		t.Fatalf("ordens diferentes:\n%s\n%s", got[0], got[1])
	}
}

// O teto de 16 MiB por kind: estourou, corta no fim da lista ordenada e marca truncated — nunca um documento
// inválido nem maior que o teto. Aqui na escala real: 5 000 targets com 256 hosts cada passam de 16 MiB.
func TestTeto16MiBCortaEMarcaTruncated(t *testing.T) {
	if testing.Short() {
		t.Skip("gera ~25 MB")
	}
	f := newFakes()
	hosts := make([]string, maxTargetHosts)
	for i := range hosts {
		hosts[i] = fmt.Sprintf("198.51.100.%d/32", i%256)
	}
	for i := range maxTargets {
		f.gvm.targets.Items = append(f.gvm.targets.Items, fullTarget(uuidN(i), "acme", hosts...))
	}
	c := collectOnce(t, f, contract.NodeStandalone)
	s, ok := c.Current(contract.KindTargets)
	if !ok {
		t.Fatalf("sem retrato: %v", c.Errors())
	}
	if len(s.Data) > maxDataBytes {
		t.Fatalf("data de %d bytes, teto %d", len(s.Data), maxDataBytes)
	}
	got := decodeData(t, contract.KindTargets, s.Data).(*contract.DataTargets)
	n := len(got.Items)
	if !got.Truncated || n == 0 || n >= maxTargets || got.Items[n-1].TargetID != uuidN(n-1) {
		t.Fatalf("%d itens, truncated %v", n, got.Truncated)
	}
	// o próximo item não cabia
	next, err := contract.MarshalCompact(f.gvm.targets.Items[n])
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Data)+len(next)+1 <= maxDataBytes {
		t.Fatalf("cortou cedo demais: %d + %d cabia", len(s.Data), len(next))
	}
	if body, err := s.Body("node-lab-0001"); err != nil || len(body) > contract.MaxStateBytes {
		t.Fatalf("corpo: %d bytes, %v", len(body), err)
	}
}

// A borda exata do teto de bytes, com um teto pequeno: o item que cabe exatamente entra, um byte a mais não.
func TestBordaDoTetoDeBytes(t *testing.T) {
	items := []contract.TaskItem{fullTask(uuidTask1, "acme"), fullTask(uuidTask2, "acme")}
	full, err := contract.MarshalCompact(contract.DataTasks{Items: items})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		limit int
		n     int
	}{{len(full), 2}, {len(full) - 1, 1}} {
		f := newFakes()
		f.gvm.tasks = contract.DataTasks{Items: items}
		col := openCollector(t, f.config(t, contract.NodeStandalone))
		col.dataLimit = c.limit
		col.Collect(context.Background())
		got := current(t, col, contract.KindTasks).(*contract.DataTasks)
		s, _ := col.Current(contract.KindTasks)
		if len(got.Items) != c.n || got.Truncated != (c.n < 2) || len(s.Data) > c.limit {
			t.Errorf("teto %d: %d itens, truncated %v, %d bytes", c.limit, len(got.Items), got.Truncated, len(s.Data))
		}
	}
}
