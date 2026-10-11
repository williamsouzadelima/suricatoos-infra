package sensorjobs

import (
	"bytes"
	"encoding/json"
	"log"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// scopes builds a ScopeLookup from tenant→CIDR-spec.
func scopes(m map[string]string) ScopeLookup {
	return func(tenant string) *Scope {
		spec, ok := m[tenant]
		if !ok {
			return nil
		}
		s, _ := NewScope(spec)
		return s
	}
}

func testReg(t *testing.T) *Registry {
	t.Helper()
	r, err := NewRegistry(Config{
		ScopeOf:  scopes(map[string]string{"acme": "10.20.0.0/16", "globex": "192.168.0.0/16"}),
		Cooldown: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestEnqueueScopeGate(t *testing.T) {
	r := testReg(t)
	job, dropped, err := r.Enqueue(EnqueueRequest{Tenant: "acme", Targets: []string{"10.20.1.1", "8.8.8.8"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(job.Targets) != 1 || job.Targets[0] != "10.20.1.1" {
		t.Fatalf("alvo fora de escopo não foi dropado: %v", job.Targets)
	}
	if len(dropped) != 1 || dropped[0] != "8.8.8.8" {
		t.Fatalf("dropped errado: %v", dropped)
	}
	// Todos fora de escopo → nada é enfileirado.
	if _, _, err := r.Enqueue(EnqueueRequest{Tenant: "acme", Targets: []string{"1.2.3.4"}}); err == nil {
		t.Fatal("alvos totalmente fora de escopo deveriam falhar")
	}
	// Tenant desconhecido → deny-all.
	if _, _, err := r.Enqueue(EnqueueRequest{Tenant: "nobody", Targets: []string{"10.20.1.1"}}); err == nil {
		t.Fatal("tenant desconhecido deveria escanear nada")
	}
}

func TestEnqueueIdempotent(t *testing.T) {
	r := testReg(t)
	j1, _, _ := r.Enqueue(EnqueueRequest{Tenant: "acme", Targets: []string{"10.20.1.1"}, ScanConfig: "full-and-fast"})
	j2, _, _ := r.Enqueue(EnqueueRequest{Tenant: "acme", Targets: []string{"10.20.1.1"}, ScanConfig: "full-and-fast"})
	if j1.JobID != j2.JobID {
		t.Fatal("enqueue idêntico dentro do cooldown deveria colapsar no mesmo job")
	}
}

func TestPollTenantPartition(t *testing.T) {
	r := testReg(t)
	acme, _, _ := r.Enqueue(EnqueueRequest{Tenant: "acme", Targets: []string{"10.20.1.1"}})
	r.Enqueue(EnqueueRequest{Tenant: "globex", Targets: []string{"192.168.1.1"}})

	// O sensor da acme só vê o job da acme.
	got, ok := r.Poll("acme")
	if !ok || got.JobID != acme.JobID {
		t.Fatalf("acme deveria receber seu próprio job, got %+v", got)
	}
	// globex nunca vê o job da acme.
	g, ok := r.Poll("globex")
	if !ok || g.Tenant != "globex" {
		t.Fatalf("globex deveria receber só o seu job, got %+v", g)
	}
	// Um tenant sem jobs → 204.
	if _, ok := r.Poll("acme"); ok {
		t.Fatal("acme não deveria ter mais jobs pendentes (o único já foi entregue)")
	}
}

func TestPollUnguessableAndDelivered(t *testing.T) {
	r := testReg(t)
	r.Enqueue(EnqueueRequest{Tenant: "acme", Targets: []string{"10.20.1.1"}})
	got, _ := r.Poll("acme")
	if len(got.JobID) != 32 || len(got.CorrelationID) != 32 {
		t.Fatalf("ids deveriam ser 32 hex: job=%q corr=%q", got.JobID, got.CorrelationID)
	}
	if got.State != StateDelivered {
		t.Fatalf("poll deveria marcar DELIVERED, got %s", got.State)
	}
}

func TestAckOwnerScope(t *testing.T) {
	r := testReg(t)
	acme, _, _ := r.Enqueue(EnqueueRequest{Tenant: "acme", Targets: []string{"10.20.1.1"}})
	r.Poll("acme") // o sensor só dá ack num job que recebeu (DELIVERED)
	// globex não pode dar ack no job da acme (IDOR) — mesmo ele já entregue.
	if r.Ack(acme.JobID, "globex") {
		t.Fatal("ack cross-tenant deveria falhar")
	}
	if r.Ack(acme.JobID, "acme") != true {
		t.Fatal("ack do próprio tenant deveria funcionar")
	}
	// O sensor só dá ack DEPOIS de rodar o scan e empurrar o relatório, então o ack
	// significa "concluído": DONE (e não mais ACKED).
	got, _ := r.Get(acme.JobID, "acme")
	if got.State != StateDone {
		t.Fatalf("estado deveria ser DONE, got %s", got.State)
	}
	// Get cross-tenant → 404.
	if _, ok := r.Get(acme.JobID, "globex"); ok {
		t.Fatal("Get cross-tenant deveria falhar")
	}
}

func TestRedeliveryAfterCrash(t *testing.T) {
	r := testReg(t)
	r.redeliver = 5 * time.Minute
	now := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	r.now = func() time.Time { return now }
	r.Enqueue(EnqueueRequest{Tenant: "acme", Targets: []string{"10.20.1.1"}})

	first, _ := r.Poll("acme") // DELIVERED, não acked (sensor "crashou")
	// Imediatamente depois: não re-entrega (dentro da janela).
	if _, ok := r.Poll("acme"); ok {
		t.Fatal("não deveria re-entregar dentro da janela de redelivery")
	}
	// Após a janela: re-entrega o mesmo job.
	now = now.Add(6 * time.Minute)
	again, ok := r.Poll("acme")
	if !ok || again.JobID != first.JobID {
		t.Fatal("deveria re-entregar o mesmo job após a janela")
	}
}

func TestExpiry(t *testing.T) {
	r := testReg(t)
	now := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	r.now = func() time.Time { return now }
	r.Enqueue(EnqueueRequest{Tenant: "acme", Targets: []string{"10.20.1.1"}, TTL: time.Hour})
	now = now.Add(2 * time.Hour)
	if _, ok := r.Poll("acme"); ok {
		t.Fatal("job expirado não deveria ser entregue")
	}
}

func TestPersistRoundTrip(t *testing.T) {
	path := t.TempDir() + "/jobs.json"
	r, _ := NewRegistry(Config{Path: path, ScopeOf: scopes(map[string]string{"acme": "10.20.0.0/16"})})
	j, _, _ := r.Enqueue(EnqueueRequest{Tenant: "acme", Targets: []string{"10.20.1.1"}})
	r.Poll("acme") // DELIVERED: só um job entregue pode ser concluído pelo ack
	r.Ack(j.JobID, "acme")

	r2, err := NewRegistry(Config{Path: path, ScopeOf: scopes(map[string]string{"acme": "10.20.0.0/16"})})
	if err != nil {
		t.Fatal(err)
	}
	got, ok := r2.Get(j.JobID, "acme")
	if !ok || got.State != StateDone {
		t.Fatalf("job deveria persistir como DONE, got %+v ok=%v", got, ok)
	}
}

// t0 é o instante-base dos testes de ciclo de vida (relógio injetado via r.now).
var t0 = time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)

// at fixa o relógio do registry em t.
func at(t time.Time) func() time.Time { return func() time.Time { return t } }

func TestAckIsIdempotentAndKeepsFirstTimestamp(t *testing.T) {
	r := testReg(t)
	r.now = at(t0)
	j, _, _ := r.Enqueue(EnqueueRequest{Tenant: "acme", Targets: []string{"10.20.1.1"}})
	r.Poll("acme")

	r.now = at(t0.Add(10 * time.Minute))
	if !r.Ack(j.JobID, "acme") {
		t.Fatal("ack do próprio tenant deveria funcionar")
	}
	r.now = at(t0.Add(20 * time.Minute))
	if !r.Ack(j.JobID, "acme") {
		t.Fatal("ack repetido deveria ser idempotente (true)")
	}
	got, _ := r.Get(j.JobID, "acme")
	if got.State != StateDone || !got.AckedAt.Equal(t0.Add(10*time.Minute)) {
		t.Fatalf("ack repetido não pode mexer no job concluído: %+v", got)
	}
}

// O sensor só conclui o que recebeu: o ack de um job PENDING (nunca entregue) é
// recusado (false) e não muda nada; depois da entrega o ack conclui o job (DONE).
func TestAckOnlyConcludesDeliveredJobs(t *testing.T) {
	r := testReg(t)
	r.now = at(t0)
	j, _, _ := r.Enqueue(EnqueueRequest{Tenant: "acme", Targets: []string{"10.20.1.1"}})

	if r.Ack(j.JobID, "acme") {
		t.Fatal("ack de um job PENDING (nunca entregue) deveria ser recusado")
	}
	got, _ := r.Get(j.JobID, "acme")
	if got.State != StatePending || !got.AckedAt.IsZero() {
		t.Fatalf("o ack recusado não pode mexer no job: %+v", got)
	}

	r.Poll("acme") // → DELIVERED
	r.now = at(t0.Add(time.Minute))
	if !r.Ack(j.JobID, "acme") {
		t.Fatal("ack de um job DELIVERED deveria funcionar")
	}
	got, _ = r.Get(j.JobID, "acme")
	if got.State != StateDone || !got.AckedAt.Equal(t0.Add(time.Minute)) {
		t.Fatalf("deveria estar DONE com AckedAt=+1min: %+v", got)
	}
}

// Um registro legado ACKED (gravado antes do Ack marcar DONE) ainda pode ser
// concluído; o instante do ack original é preservado.
func TestAckConcludesLegacyAckedRecord(t *testing.T) {
	ackedAt := t0.Add(-50 * time.Minute)
	legacy := ScanJob{
		SchemaVersion: SchemaVersion, JobID: "legacy", CorrelationID: "c", Tenant: "acme",
		Targets: []string{"10.20.1.1"}, State: StateAcked,
		CreatedAt: t0.Add(-time.Hour), ExpiresAt: t0.Add(23 * time.Hour), AckedAt: ackedAt,
	}
	r, err := NewRegistry(Config{Path: writeJobs(t, legacy)})
	if err != nil {
		t.Fatal(err)
	}
	r.now = at(t0)
	if !r.Ack("legacy", "acme") {
		t.Fatal("ack de um registro legado ACKED deveria funcionar")
	}
	got, _ := r.Get("legacy", "acme")
	if got.State != StateDone || !got.AckedAt.Equal(ackedAt) {
		t.Fatalf("deveria virar DONE preservando o AckedAt original: %+v", got)
	}
}

func TestAckDoesNotResurrectExpired(t *testing.T) {
	r := testReg(t)
	r.now = at(t0)
	j, _, _ := r.Enqueue(EnqueueRequest{Tenant: "acme", Targets: []string{"10.20.1.1"}, TTL: time.Hour})
	r.now = at(t0.Add(2 * time.Hour))
	r.Poll("acme") // varre o vencido → EXPIRED
	if !r.Ack(j.JobID, "acme") {
		t.Fatal("ack de job do tenant responde true (idempotente) mesmo se terminal")
	}
	if got, _ := r.Get(j.JobID, "acme"); got.State != StateExpired {
		t.Fatalf("job EXPIRED deve continuar EXPIRED após ack, got %s", got.State)
	}
}

// writeJobs grava um arquivo de fila com os jobs dados, para controlar estado e
// idade sem percorrer o ciclo de vida inteiro.
func writeJobs(t *testing.T, jobs ...ScanJob) string {
	t.Helper()
	path := t.TempDir() + "/jobs.json"
	b, err := json.Marshal(jobs)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// Registros gravados por versões anteriores têm state ACKED (o Ack ainda não
// marcava DONE). Precisam continuar legíveis, e nunca são entregues de novo.
func TestLegacyAckedRecordsStillLoad(t *testing.T) {
	legacy := ScanJob{
		SchemaVersion: SchemaVersion, JobID: "legacy", CorrelationID: "c", Tenant: "acme",
		Targets: []string{"10.20.1.1"}, State: StateAcked,
		CreatedAt: t0.Add(-time.Hour), ExpiresAt: t0.Add(23 * time.Hour), AckedAt: t0.Add(-50 * time.Minute),
	}
	r, err := NewRegistry(Config{Path: writeJobs(t, legacy)})
	if err != nil {
		t.Fatal(err)
	}
	r.now = at(t0)
	got, ok := r.Get("legacy", "acme")
	if !ok || got.State != StateAcked {
		t.Fatalf("registro legado ACKED deveria carregar intacto, got %+v ok=%v", got, ok)
	}
	if _, ok := r.Poll("acme"); ok {
		t.Fatal("um job legado ACKED não deve ser entregue de novo")
	}
}

// O colapso de pedidos idênticos (anti-storm) vale para job EM VOO; um job já
// concluído (DONE) não pode engolir um novo pedido de re-scan.
func TestEnqueueAfterDoneIsNotCollapsed(t *testing.T) {
	r := testReg(t)
	req := EnqueueRequest{Tenant: "acme", Targets: []string{"10.20.1.1"}, ScanConfig: "full-and-fast"}
	j1, _, _ := r.Enqueue(req)
	r.Poll("acme") // em voo (DELIVERED)
	if j2, _, _ := r.Enqueue(req); j2.JobID != j1.JobID {
		t.Fatal("job em voo: o enqueue idêntico deveria colapsar no mesmo job")
	}
	r.Ack(j1.JobID, "acme") // concluído
	if j3, _, _ := r.Enqueue(req); j3.JobID == j1.JobID {
		t.Fatal("job DONE não deveria engolir um novo pedido idêntico (re-scan)")
	}
}

func TestReapDropsOldTerminalOnly(t *testing.T) {
	// old passa da retenção padrão (7 dias); recent fica dentro dela.
	old := t0.Add(-8 * 24 * time.Hour)
	recent := t0.Add(-1 * 24 * time.Hour)
	path := writeJobs(t,
		ScanJob{JobID: "done-old", Tenant: "acme", State: StateDone, CreatedAt: old},
		ScanJob{JobID: "expired-old", Tenant: "acme", State: StateExpired, CreatedAt: old},
		ScanJob{JobID: "done-recent", Tenant: "acme", State: StateDone, CreatedAt: recent},
		ScanJob{JobID: "pending-old", Tenant: "acme", State: StatePending, CreatedAt: old},
		ScanJob{JobID: "delivered-old", Tenant: "acme", State: StateDelivered, CreatedAt: old},
	)
	r, err := NewRegistry(Config{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	r.now = at(t0)
	has := func(rr *Registry, id string) bool { _, ok := rr.Get(id, "acme"); return ok }

	if n := r.Reap(0); n != 2 { // 0 = retenção padrão
		t.Fatalf("Reap(0) removeu %d, want 2 (DONE e EXPIRED antigos)", n)
	}
	// Terminais antigos somem; o terminal recente fica; os não-terminais NUNCA
	// saem, por mais velhos que sejam.
	for id, want := range map[string]bool{
		"done-old":      false,
		"expired-old":   false,
		"done-recent":   true,
		"pending-old":   true,
		"delivered-old": true,
	} {
		if has(r, id) != want {
			t.Errorf("job %s presente=%v, want %v", id, has(r, id), want)
		}
	}
	// O expurgo chegou ao disco.
	r2, _ := NewRegistry(Config{Path: path})
	if has(r2, "done-old") || has(r2, "expired-old") || !has(r2, "done-recent") {
		t.Error("o expurgo não foi persistido")
	}
	// Janela explícita menor também vale; ainda só terminais.
	if n := r.Reap(time.Hour); n != 1 || has(r, "done-recent") || !has(r, "pending-old") {
		t.Errorf("Reap(1h) removeu %d; deveria expurgar só done-recent", n)
	}
}

// O expurgo roda no Enqueue (mesmo ponto da fila de remediação): a fila não cresce
// para sempre só porque ninguém chamou Reap.
func TestEnqueueReapsOldTerminal(t *testing.T) {
	path := writeJobs(t,
		ScanJob{JobID: "done-old", Tenant: "acme", State: StateDone, CreatedAt: t0.Add(-8 * 24 * time.Hour)},
		ScanJob{JobID: "pending-old", Tenant: "acme", State: StatePending, CreatedAt: t0.Add(-8 * 24 * time.Hour)},
	)
	r, err := NewRegistry(Config{Path: path, ScopeOf: scopes(map[string]string{"acme": "10.20.0.0/16"})})
	if err != nil {
		t.Fatal(err)
	}
	r.now = at(t0)
	if _, _, err := r.Enqueue(EnqueueRequest{Tenant: "acme", Targets: []string{"10.20.1.1"}}); err != nil {
		t.Fatal(err)
	}
	if _, ok := r.Get("done-old", "acme"); ok {
		t.Fatal("o Enqueue deveria expurgar o terminal antigo")
	}
	if _, ok := r.Get("pending-old", "acme"); !ok {
		t.Fatal("o expurgo não pode tocar job não-terminal")
	}
	r2, _ := NewRegistry(Config{Path: path})
	if _, ok := r2.Get("done-old", "acme"); ok {
		t.Fatal("o expurgo do Enqueue não foi persistido")
	}
}

func TestListIsTenantScopedOrderedAndLimited(t *testing.T) {
	r := testReg(t)
	mk := func(minute int, tenant, target string) *ScanJob {
		r.now = at(t0.Add(time.Duration(minute) * time.Minute))
		j, _, err := r.Enqueue(EnqueueRequest{Tenant: tenant, Targets: []string{target}})
		if err != nil {
			t.Fatal(err)
		}
		return j
	}
	a1 := mk(0, "acme", "10.20.1.1")
	a2 := mk(1, "acme", "10.20.1.2")
	g1 := mk(2, "globex", "192.168.1.1")
	a3 := mk(3, "acme", "10.20.1.3")
	r.Poll("acme") // a1 (o mais antigo elegível) → DELIVERED
	r.Ack(a1.JobID, "acme")

	check := func(what, tenant string, f ListFilter, wantTotal int, want ...*ScanJob) {
		t.Helper()
		got, total := r.List(tenant, f)
		if len(got) != len(want) || total != wantTotal {
			t.Errorf("%s: %d job(s) total=%d, want %d total=%d", what, len(got), total, len(want), wantTotal)
			return
		}
		for i := range want {
			if got[i].JobID != want[i].JobID {
				t.Errorf("%s: posição %d = %s, want %s", what, i, got[i].JobID, want[i].JobID)
			}
		}
	}
	check("acme: created_at desc", "acme", ListFilter{}, 3, a3, a2, a1)
	check("globex só vê o seu", "globex", ListFilter{}, 1, g1)
	check("tenant sem jobs", "nobody", ListFilter{}, 0)
	check("tenant vazio nunca lista tudo", "", ListFilter{}, 0)
	check("state=DONE", "acme", ListFilter{State: StateDone}, 1, a1)
	check("state=PENDING", "acme", ListFilter{State: StatePending}, 2, a3, a2)
	check("limit mantém os mais novos", "acme", ListFilter{Limit: 2}, 3, a3, a2)
	check("limit <= 0 = padrão (nunca ilimitado)", "acme", ListFilter{Limit: -1}, 3, a3, a2, a1)

	// List devolve CLONES.
	got, _ := r.List("acme", ListFilter{})
	got[0].State = StateDone
	got[0].Targets[0] = "6.6.6.6"
	if again, _ := r.List("acme", ListFilter{}); again[0].State == StateDone || again[0].Targets[0] == "6.6.6.6" {
		t.Error("List deve devolver clones")
	}
}

// List("") jamais vira "todos os tenants" — nem para um registro sem tenant (arquivo
// adulterado/corrompido), que um tenant vazio casaria por igualdade.
func TestListEmptyTenantMatchesNothing(t *testing.T) {
	path := writeJobs(t,
		ScanJob{JobID: "orphan", Tenant: "", State: StatePending, CreatedAt: t0},
		ScanJob{JobID: "acme-1", Tenant: "acme", State: StatePending, CreatedAt: t0},
	)
	r, err := NewRegistry(Config{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	if got, total := r.List("", ListFilter{}); len(got) != 0 || total != 0 {
		t.Fatalf("List(\"\") deveria vir vazio, got %d job(s) total=%d", len(got), total)
	}
	if got, _ := r.List("acme", ListFilter{}); len(got) != 1 || got[0].JobID != "acme-1" {
		t.Fatalf("List(acme) deveria trazer só acme-1, got %+v", got)
	}
}

func TestClampLimit(t *testing.T) {
	for in, want := range map[int]int{-5: 200, 0: 200, 1: 1, 7: 7, 1000: 1000, 1001: 1000, 100000: 1000} {
		if got := clampLimit(in); got != want {
			t.Errorf("clampLimit(%d) = %d, want %d", in, got, want)
		}
	}
}

func TestJobStateValid(t *testing.T) {
	for _, s := range []JobState{StatePending, StateDelivered, StateAcked, StateDone, StateExpired} {
		if !s.valid() {
			t.Errorf("%s deveria ser válido", s)
		}
	}
	for _, s := range []JobState{"", "done", "BOGUS", "APPLIED"} {
		if s.valid() {
			t.Errorf("%q não deveria ser válido", s)
		}
	}
}

// lockedBuf é um destino de log seguro entre goroutines.
type lockedBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuf) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// captureLog desvia o logger padrão para um buffer durante o teste.
func captureLog(t *testing.T) *lockedBuf {
	t.Helper()
	buf := &lockedBuf{}
	prev := log.Writer()
	log.SetOutput(buf)
	t.Cleanup(func() { log.SetOutput(prev) })
	return buf
}

// failSaves faz toda gravação futura de r falhar sem tocar no arquivo em disco: o
// temporário que o registry grava antes do rename vira um diretório.
func failSaves(t *testing.T, r *Registry) {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.path == "" {
		t.Fatal("registry sem arquivo nunca falha ao gravar")
	}
	if err := os.Mkdir(r.path+".tmp", 0o700); err != nil {
		t.Fatal(err)
	}
}

// saveLines devolve as linhas do log capturado que reportam falha de gravação.
func saveLines(buf *lockedBuf) []string {
	var out []string
	for _, l := range strings.Split(buf.String(), "\n") {
		if strings.Contains(l, "saveLocked") {
			out = append(out, l)
		}
	}
	return out
}

// O Poll entrega o job e grava a entrega; se a gravação falha, o job continua sendo
// entregue (a janela de redelivery e o scan repetível cobrem o restart), mas a falha
// não pode ser silenciosa: sai no log com o id do job e o erro — e nada dos alvos.
// Uma gravação que dá certo não loga nada.
func TestPollLogsWhenPersistingTheDeliveryFails(t *testing.T) {
	logs := captureLog(t)
	path := t.TempDir() + "/jobs.json"
	r, err := NewRegistry(Config{Path: path, ScopeOf: scopes(map[string]string{"acme": "10.20.0.0/16"})})
	if err != nil {
		t.Fatal(err)
	}
	first, _, _ := r.Enqueue(EnqueueRequest{Tenant: "acme", Targets: []string{"10.20.1.1"}})
	if got, ok := r.Poll("acme"); !ok || got.JobID != first.JobID {
		t.Fatalf("o primeiro poll deveria entregar o job, got %+v ok=%v", got, ok)
	}
	if lines := saveLines(logs); len(lines) != 0 {
		t.Fatalf("uma gravação que deu certo não deve logar: %q", lines)
	}

	second, _, _ := r.Enqueue(EnqueueRequest{Tenant: "acme", Targets: []string{"10.20.2.2"}})
	failSaves(t, r)
	got, ok := r.Poll("acme")
	if !ok || got.JobID != second.JobID {
		t.Fatalf("o segundo job deveria ser entregue mesmo sem conseguir gravar, got %+v ok=%v", got, ok)
	}
	lines := saveLines(logs)
	if len(lines) != 1 {
		t.Fatalf("a falha de gravação da entrega deveria sair no log (1 linha), got %d: %q", len(lines), lines)
	}
	for _, want := range []string{second.JobID, "jobs.json.tmp"} { // o id do job e o erro do SO
		if !strings.Contains(lines[0], want) {
			t.Errorf("a linha de log deveria conter %q: %s", want, lines[0])
		}
	}
	if strings.Contains(logs.String(), "10.20.2.2") {
		t.Errorf("o log não deve trazer os alvos do job: %s", logs.String())
	}
}

// Quando o Poll só varre jobs vencidos (nada elegível), a gravação da varredura
// também não pode falhar em silêncio.
func TestPollLogsWhenPersistingTheExpirySweepFails(t *testing.T) {
	logs := captureLog(t)
	path := t.TempDir() + "/jobs.json"
	r, err := NewRegistry(Config{Path: path, ScopeOf: scopes(map[string]string{"acme": "10.20.0.0/16"})})
	if err != nil {
		t.Fatal(err)
	}
	r.now = at(t0)
	j, _, _ := r.Enqueue(EnqueueRequest{Tenant: "acme", Targets: []string{"10.20.1.1"}, TTL: time.Hour})
	failSaves(t, r)
	r.now = at(t0.Add(2 * time.Hour))
	if got, ok := r.Poll("acme"); ok {
		t.Fatalf("um job vencido não deveria ser entregue, got %+v", got)
	}
	if g, _ := r.Get(j.JobID, "acme"); g.State != StateExpired {
		t.Fatalf("o job vencido deveria estar EXPIRED na memória, got %s", g.State)
	}
	lines := saveLines(logs)
	if len(lines) != 1 || !strings.Contains(lines[0], "jobs.json.tmp") {
		t.Fatalf("a falha de gravação da varredura deveria sair no log (1 linha com o erro do SO), got %q", lines)
	}
}
