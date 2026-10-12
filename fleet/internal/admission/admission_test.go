package admission

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/williamsouzadelima/suricatoos-infra/fleet/contract"
	"github.com/williamsouzadelima/suricatoos-infra/fleet/internal/budget"
	"github.com/williamsouzadelima/suricatoos-infra/fleet/internal/policy"
	"github.com/williamsouzadelima/suricatoos-infra/fleet/internal/tenant"
)

var t0 = time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)

// fakeBudgets answers Fits from two switches and remembers what it was asked.
type fakeBudgets struct {
	totalRoom     bool
	sensitiveRoom bool
	calls         []fitsCall
}

type fitsCall struct {
	at        time.Time
	sensitive bool
	lim       budget.Limits
}

func (f *fakeBudgets) Fits(t time.Time, sensitive bool, lim budget.Limits) bool {
	f.calls = append(f.calls, fitsCall{t, sensitive, lim})
	if !f.totalRoom {
		return false
	}
	return !sensitive || f.sensitiveRoom
}

func roomy() *fakeBudgets { return &fakeBudgets{totalRoom: true, sensitiveRoom: true} }

// base passes lines 6 and 7: agent.scan_now is allowed by the default policy, supported only by a central node
// and not sensitive. Each breaker below breaks exactly one line-6/7 check and nothing else.
func base() Request {
	return Request{
		Type:     contract.TypeAgentScanNow,
		NodeKind: contract.NodeCentral,
		Tenant:   tenant.Standing{OK: true, Scope: "192.0.2.0/24"},
		Policy:   contract.DefaultPolicy(contract.NodeCentral),
		Budgets:  roomy(),
		At:       t0,
	}
}

var breakers = []struct {
	reason contract.RejectReason
	apply  func(*Request)
}{
	{contract.ReasonTenantUnknown, func(r *Request) { r.Tenant = tenant.Standing{Why: tenant.WhyUnknown} }},
	{contract.ReasonUnsupported, func(r *Request) { r.NodeKind = contract.NodeSensor }},
	{contract.ReasonTypeNotAllowed, func(r *Request) {
		typ := r.Type
		r.Policy.Allow = slices.DeleteFunc(slices.Clone(r.Policy.Allow), func(t contract.CommandType) bool { return t == typ })
	}},
	{contract.ReasonRateLimited, func(r *Request) { r.Budgets = &fakeBudgets{} }},
}

func reasonOf(t *testing.T, err error) contract.RejectReason {
	t.Helper()
	if err == nil {
		return ""
	}
	var re *contract.RejectError
	if !errors.As(err, &re) {
		t.Fatalf("o veredito da linha 6/7 tem de ser *contract.RejectError, veio %T: %v", err, err)
	}
	if re.Envelope != nil || re.Violation != nil {
		t.Fatalf("o portão não conhece o envelope nem violação de forma: %+v", re)
	}
	if re.Detail == "" {
		t.Fatal("toda recusa traz um detail curto")
	}
	return re.Reason
}

func TestPassaQuandoTudoPassa(t *testing.T) {
	if err := Check(base()); err != nil {
		t.Fatalf("base deveria passar: %v", err)
	}
}

func TestCadaMotivoSozinho(t *testing.T) {
	for _, b := range breakers {
		t.Run(string(b.reason), func(t *testing.T) {
			r := base()
			b.apply(&r)
			if got := reasonOf(t, Check(r)); got != b.reason {
				t.Fatalf("motivo %q, esperava %q", got, b.reason)
			}
		})
	}
}

// TestOrdemDosMotivos: with several failures at once the first in the ADR's order wins:
// tenant_unknown (line 6) -> unsupported -> type_not_allowed -> rate_limited (line 7). All 15 combinations of
// the four checks are run, which includes one case for each of the six pairs.
func TestOrdemDosMotivos(t *testing.T) {
	for mask := 1; mask < 1<<len(breakers); mask++ {
		var names []string
		var want contract.RejectReason
		for i, b := range breakers {
			if mask&(1<<i) != 0 {
				names = append(names, string(b.reason))
				if want == "" {
					want = b.reason // breakers are in the ADR's order
				}
			}
		}
		t.Run(strings.Join(names, "+"), func(t *testing.T) {
			r := base()
			for i, b := range breakers {
				if mask&(1<<i) != 0 {
					b.apply(&r)
				}
			}
			if got := reasonOf(t, Check(r)); got != want {
				t.Fatalf("motivo %q, esperava %q", got, want)
			}
		})
	}
}

func TestTenantRecusadoSempreDaTenantUnknown(t *testing.T) {
	// o motivo é um só; o detail diz qual foi o porquê (para o operador), com texto fixo
	details := map[tenant.Why]string{
		tenant.WhyUnknown:   "desconhecido",
		tenant.WhyDisabled:  "desabilitado",
		tenant.WhyNoGVMUser: "usuário gvmd",
		tenant.WhyNoSecret:  "senha",
		"":                  "desconhecido", // um Standing que ninguém preencheu é recusa, não aceite
	}
	for why, want := range details {
		r := base()
		r.Tenant = tenant.Standing{Why: why}
		err := Check(r)
		if got := reasonOf(t, err); got != contract.ReasonTenantUnknown {
			t.Errorf("why=%q: motivo %q", why, got)
			continue
		}
		if !strings.Contains(err.Error(), want) {
			t.Errorf("why=%q: o detail deveria citar %q: %v", why, want, err)
		}
	}
}

func TestUnsupportedAntesDeTypeNotAllowed(t *testing.T) {
	// o tipo está em allow (o arquivo aceita), mas o node_kind não o suporta: unsupported, não type_not_allowed
	for _, tc := range []struct {
		typ  contract.CommandType
		kind contract.NodeKind
	}{
		{contract.TypeAgentScanNow, contract.NodeSensor},
		{contract.TypeAgentScanNow, contract.NodeStandalone},
		{contract.TypeEnrollTokenCreate, contract.NodeStandalone},
		{contract.TypeSensorJobEnqueue, contract.NodeSensor},
		{contract.TypeFeedSyncNow, contract.NodeSensor},
	} {
		r := base()
		r.Type, r.NodeKind = tc.typ, tc.kind
		r.Policy = contract.Policy{Allow: []contract.CommandType{tc.typ}, SensitivePerHour: 30, TotalPerHour: 120}
		if got := reasonOf(t, Check(r)); got != contract.ReasonUnsupported {
			t.Errorf("%s em %s: %q", tc.typ, tc.kind, got)
		}
		// e fora de allow também: o catálogo e o node_kind vêm antes
		r.Policy.Allow = nil
		if got := reasonOf(t, Check(r)); got != contract.ReasonUnsupported {
			t.Errorf("%s em %s fora de allow: %q", tc.typ, tc.kind, got)
		}
	}
}

func TestTipoForaDoCatalogoEUnsupportedSemEcoDaEntrada(t *testing.T) {
	r := base()
	r.Type = "tenant.scope_set"
	r.Policy.Allow = append(r.Policy.Allow, r.Type) // nem estando em allow
	err := Check(r)
	if reasonOf(t, err) != contract.ReasonUnsupported {
		t.Fatalf("%v", err)
	}
	if strings.Contains(err.Error(), "tenant.scope_set") {
		t.Fatalf("o tipo veio do envelope: não pode ser ecoado no detail: %v", err)
	}
}

func TestScheduleCreateComTaskIDsPedeTaskModify(t *testing.T) {
	allow := func(ts ...contract.CommandType) contract.Policy {
		return contract.Policy{Allow: ts, SensitivePerHour: 30, TotalPerHour: 120}
	}
	cases := []struct {
		name       string
		allow      contract.Policy
		linksTasks bool
		want       contract.RejectReason // "" = passa
		detail     string
	}{
		{"sem task_ids: basta schedule.create", allow(contract.TypeScheduleCreate), false, "", ""},
		{"com task_ids e task.modify permitido", allow(contract.TypeScheduleCreate, contract.TypeTaskModify), true, "", ""},
		{"com task_ids e sem task.modify", allow(contract.TypeScheduleCreate), true, contract.ReasonTypeNotAllowed, "task.modify"},
		{"com task_ids, sem schedule.create", allow(contract.TypeTaskModify), true, contract.ReasonTypeNotAllowed, "schedule.create"},
		{"sem task_ids e sem schedule.create", allow(contract.TypeTaskModify), false, contract.ReasonTypeNotAllowed, "schedule.create"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := base()
			r.Type, r.Policy, r.LinksTasks = contract.TypeScheduleCreate, c.allow, c.linksTasks
			err := Check(r)
			if got := reasonOf(t, err); got != c.want {
				t.Fatalf("motivo %q, esperava %q (%v)", got, c.want, err)
			}
			if c.detail != "" && !strings.Contains(err.Error(), c.detail) {
				t.Fatalf("o detail deveria citar %q: %v", c.detail, err)
			}
		})
	}
}

func TestLinksTasksNaoMudaOutrosTipos(t *testing.T) {
	r := base()
	r.LinksTasks = true // agent.scan_now não é schedule.create
	if err := Check(r); err != nil {
		t.Fatalf("%v", err)
	}
}

func TestOrcamentoPerguntaComOLimiteDaPoliticaEOInstanteDado(t *testing.T) {
	fake := roomy()
	r := base()
	r.Type, r.Policy.Allow = contract.TypeTaskCreate, append(r.Policy.Allow, contract.TypeTaskCreate)
	r.Policy.SensitivePerHour, r.Policy.TotalPerHour = 7, 11
	r.Budgets, r.At = fake, t0.Add(42*time.Second)
	if err := Check(r); err != nil {
		t.Fatal(err)
	}
	// task.create é opt-in, portanto sensível: pergunta o global e depois o conjunto dos dois
	want := []fitsCall{
		{t0.Add(42 * time.Second), false, budget.Limits{Total: 11, Sensitive: 7}},
		{t0.Add(42 * time.Second), true, budget.Limits{Total: 11, Sensitive: 7}},
	}
	if !slices.Equal(fake.calls, want) {
		t.Fatalf("perguntas %+v, esperava %+v", fake.calls, want)
	}

	// não sensível: só o global
	fake2 := roomy()
	r2 := base()
	r2.Budgets = fake2
	if err := Check(r2); err != nil {
		t.Fatal(err)
	}
	if len(fake2.calls) != 1 || fake2.calls[0].sensitive {
		t.Fatalf("tipo não sensível só consulta o global: %+v", fake2.calls)
	}
}

func TestSensivelEsgotadoSoRecusaSensivel(t *testing.T) {
	r := base()
	r.Type, r.Policy.Allow = contract.TypeTaskCreate, append(r.Policy.Allow, contract.TypeTaskCreate)
	r.Budgets = &fakeBudgets{totalRoom: true, sensitiveRoom: false}
	err := Check(r)
	if reasonOf(t, err) != contract.ReasonRateLimited || !strings.Contains(err.Error(), "sensíveis") {
		t.Fatalf("sensível esgotado: %v", err)
	}
	// o não sensível passa com o mesmo orçamento
	r2 := base()
	r2.Budgets = &fakeBudgets{totalRoom: true, sensitiveRoom: false}
	if err := Check(r2); err != nil {
		t.Fatalf("não sensível com o orçamento de sensíveis esgotado: %v", err)
	}
	// global esgotado: o detail diz global
	r3 := base()
	r3.Budgets = &fakeBudgets{}
	if err := Check(r3); !strings.Contains(err.Error(), "global") {
		t.Fatalf("global esgotado: %v", err)
	}
}

func TestOrcamentoSoEConsultadoDepoisDasOutrasLinhas(t *testing.T) {
	for _, b := range breakers[:3] { // tenant, unsupported, type_not_allowed
		fake := roomy()
		r := base()
		b.apply(&r)
		r.Budgets = fake
		if err := Check(r); reasonOf(t, err) != b.reason {
			t.Fatalf("%s: %v", b.reason, err)
		}
		if len(fake.calls) != 0 {
			t.Errorf("%s: os orçamentos não são consultados quando uma linha anterior já recusou: %+v", b.reason, fake.calls)
		}
	}
}

func TestSemOrcamentosNaoDecide(t *testing.T) {
	r := base()
	r.Budgets = nil
	err := Check(r)
	if err == nil {
		t.Fatal("sem orçamentos o portão não pode aceitar")
	}
	var re *contract.RejectError
	if errors.As(err, &re) {
		t.Fatalf("falta de configuração não é veredito da linha 6/7: %v", err)
	}
}

func TestPoliticaVaziaNaoPermiteNada(t *testing.T) {
	r := base()
	r.Policy = contract.Policy{}
	if got := reasonOf(t, Check(r)); got != contract.ReasonTypeNotAllowed {
		t.Fatalf("%q", got)
	}
}

func TestDetailNaoEcoaTipoNemTenant(t *testing.T) {
	for _, b := range breakers {
		r := base()
		b.apply(&r)
		err := Check(r)
		for _, forbidden := range []string{"192.0.2.0/24"} {
			if strings.Contains(err.Error(), forbidden) {
				t.Errorf("%s: o detail não deveria carregar dados do tenant: %v", b.reason, err)
			}
		}
	}
}

func TestLinksTasks(t *testing.T) {
	marshal := func(p contract.PayloadScheduleCreate) string {
		b, err := contract.MarshalCompact(p)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	ids := []string{"2d5b8f0e-1c4a-4e6b-9a3d-7f0c5e1b2a49"}
	plain := contract.PayloadScheduleCreate{Name: "diaria", ICalendar: "BEGIN:VCALENDAR", Timezone: "UTC"}
	withIDs, withEmpty := plain, plain
	withIDs.TaskIDs = ids
	withEmpty.TaskIDs = []string{}

	cases := []struct {
		name    string
		typ     contract.CommandType
		payload string
		want    bool
	}{
		{"schedule.create sem task_ids", contract.TypeScheduleCreate, marshal(plain), false},
		{"schedule.create com task_ids", contract.TypeScheduleCreate, marshal(withIDs), true},
		{"task_ids presente e vazio conta como presente", contract.TypeScheduleCreate, marshal(withEmpty), true},
		{"task_ids nulo conta como presente (a linha 8 recusa)", contract.TypeScheduleCreate, `{"name":"a","icalendar":"x","timezone":"UTC","task_ids":null}`, true},
		{"nome do membro é exato", contract.TypeScheduleCreate, `{"name":"a","icalendar":"x","timezone":"UTC","Task_IDs":["x"]}`, false},
		{"membro parecido não conta", contract.TypeScheduleCreate, `{"name":"a","icalendar":"x","timezone":"UTC","task_ids_x":["x"]}`, false},
		{"task_ids só no nível de cima", contract.TypeScheduleCreate, `{"name":"a","icalendar":"x","timezone":"UTC","comment":{"task_ids":["x"]}}`, false},
		{"objeto vazio", contract.TypeScheduleCreate, `{}`, false},
		{"payload que não é objeto: na dúvida, conta", contract.TypeScheduleCreate, `["task_ids"]`, true},
		{"payload ilegível: na dúvida, conta", contract.TypeScheduleCreate, `{"task_ids":`, true},
		{"payload vazio: na dúvida, conta", contract.TypeScheduleCreate, ``, true},
		{"outro tipo nunca", contract.TypeScheduleModify, marshal(withIDs), false},
		{"task.modify nunca", contract.TypeTaskModify, `{"task_id":"x","task_ids":["y"]}`, false},
		{"tipo fora do catálogo nunca", "tenant.scope_set", marshal(withIDs), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := LinksTasks(c.typ, []byte(c.payload)); got != c.want {
				t.Fatalf("LinksTasks = %v, esperava %v (%s)", got, c.want, c.payload)
			}
		})
	}
}

// TestPortaComOsPacotesReais ties the three building blocks to the gate: a policy.json, a local tenant source and
// a persisted ledger, asked in sequence the way the connector will.
func TestPortaComOsPacotesReais(t *testing.T) {
	dir := t.TempDir()
	pwFile := filepath.Join(dir, "gvm.pass")
	if err := os.WriteFile(pwFile, []byte("senha-ficticia\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	policyPath := filepath.Join(dir, policy.FileName)
	writePolicy := func(allow ...contract.CommandType) {
		b, err := json.Marshal(contract.Policy{Allow: allow, SensitivePerHour: 1, TotalPerHour: 3})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(policyPath, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	writePolicy(contract.TypeTaskStart, contract.TypeTaskCreate)

	src, err := tenant.Open(contract.NodeStandalone, tenant.Config{
		Tenant: "acme", Scope: "192.0.2.0/24", GVMUser: "tenant-acme", GVMPasswordFile: pwFile,
	})
	if err != nil {
		t.Fatal(err)
	}
	ledger, err := budget.Open(dir, t0)
	if err != nil {
		t.Fatal(err)
	}

	// ask runs lines 6 and 7 for one command, the way the connector will: resolve the tenant for the type, load the
	// policy once, then the gate
	ask := func(at time.Time, name string, typ contract.CommandType) (contract.RejectReason, error) {
		t.Helper()
		st, err := src.Resolve(name, typ)
		if err != nil {
			t.Fatal(err)
		}
		snap, err := policy.Load(dir, contract.NodeStandalone)
		if err != nil {
			t.Fatal(err)
		}
		err = Check(Request{Type: typ, NodeKind: contract.NodeStandalone, Tenant: st, Policy: snap.Policy, Budgets: ledger, At: at})
		return reasonOf(t, err), err
	}
	accept := func(at time.Time, typ contract.CommandType) {
		t.Helper()
		e, _ := contract.LookupType(typ)
		snap, _ := policy.Load(dir, contract.NodeStandalone)
		if err := ledger.Consume(at, e.Sensitive, budget.Limits{Total: snap.Policy.TotalPerHour, Sensitive: snap.Policy.SensitivePerHour}); err != nil {
			t.Fatal(err)
		}
	}

	at := t0
	if r, err := ask(at, "acme", contract.TypeTaskCreate); r != "" {
		t.Fatalf("primeiro task.create: %v", err)
	}
	accept(at, contract.TypeTaskCreate)

	at = t0.Add(time.Second)
	if r, _ := ask(at, "acme", contract.TypeTaskCreate); r != contract.ReasonRateLimited {
		t.Fatalf("o orçamento de sensíveis (1/h) acabou: %q", r)
	}
	if r, err := ask(at, "acme", contract.TypeTaskStart); r != "" {
		t.Fatalf("task.start não é sensível: %v", err)
	}
	accept(at, contract.TypeTaskStart)
	accept(at, contract.TypeTaskStart)

	if r, _ := ask(at, "acme", contract.TypeTaskStart); r != contract.ReasonRateLimited {
		t.Fatalf("o global (3/h) acabou: %q", r)
	}
	if r, _ := ask(at, "globex", contract.TypeTaskStart); r != contract.ReasonTenantUnknown {
		t.Fatalf("a linha 6 vem antes do orçamento: %q", r)
	}
	if r, _ := ask(at, "acme", contract.TypeTaskStop); r != contract.ReasonTypeNotAllowed {
		t.Fatalf("task.stop não está em allow, e isso vem antes do orçamento: %q", r)
	}

	// a janela anda: em t0+1h o instante t0 sai, sobram dois dos três
	if r, err := ask(t0.Add(time.Hour), "acme", contract.TypeTaskCreate); r != "" {
		t.Fatalf("depois de 1 h: %v", err)
	}

	// o operador aperta a política com o conector no ar: vale no comando seguinte
	writePolicy(contract.TypeTaskStart)
	if r, _ := ask(t0.Add(time.Hour), "acme", contract.TypeTaskCreate); r != contract.ReasonTypeNotAllowed {
		t.Fatalf("política apertada: %q", r)
	}

	// e a senha do tenant some: a escrita deixa de passar na linha 6 (a leitura segue)
	writePolicy(contract.TypeTaskStart, contract.TypeTaskCreate)
	if err := os.Remove(pwFile); err != nil {
		t.Fatal(err)
	}
	if r, _ := ask(t0.Add(time.Hour), "acme", contract.TypeTaskCreate); r != contract.ReasonTenantUnknown {
		t.Fatalf("sem senha: %q", r)
	}
	if r, err := ask(t0.Add(time.Hour), "acme", contract.TypeTaskStart); r != "" {
		t.Fatalf("leitura sem senha: %v", err)
	}
}
