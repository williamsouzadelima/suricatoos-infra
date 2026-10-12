package state

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/williamsouzadelima/suricatoos-infra/fleet/contract"
	"github.com/williamsouzadelima/suricatoos-infra/fleet/internal/tenant"
)

func TestParseInterval(t *testing.T) {
	ok := map[string]time.Duration{"": DefaultInterval, "60s": time.Minute, "30s": 30 * time.Second, "1m": time.Minute,
		"1m30s": 90 * time.Second, "1.5m": 90 * time.Second, "10m": 10 * time.Minute, "600s": 10 * time.Minute}
	for in, want := range ok {
		if got, err := ParseInterval(in); err != nil || got != want {
			t.Errorf("ParseInterval(%q) = %v, %v", in, got, err)
		}
	}
	for _, in := range []string{"29s", "29999ms", "30500ms", "0", "-60s", "60", "um minuto", " 60s", "601s", "10m1s",
		"60m", "1h", "2000000h"} {
		if got, err := ParseInterval(in); err == nil || !errors.Is(err, ErrInvalidInterval) {
			t.Errorf("ParseInterval(%q) = %v, %v", in, got, err)
		}
	}
	if DefaultInterval != 60*time.Second || MinInterval != 30*time.Second || MaxInterval != 10*time.Minute {
		t.Fatal("60 s de padrão e 30 s de mínimo (ADR), 10 min de máximo (decisão do controlador)")
	}
}

func TestOpenValidaAConfiguracao(t *testing.T) {
	f := newFakes()
	base := f.config(t, contract.NodeStandalone)
	if c := openCollector(t, base); c.interval != DefaultInterval {
		t.Fatalf("intervalo padrão %v", c.interval)
	}
	for _, d := range []time.Duration{MinInterval, MaxInterval} {
		cfg := base
		cfg.Interval = d
		if c := openCollector(t, cfg); c.interval != d {
			t.Fatalf("intervalo %v virou %v", d, c.interval)
		}
	}
	bad := map[string]func(*Config){
		"node_kind":               func(c *Config) { c.NodeKind = "hub" },
		"connector_version":       func(c *Config) { c.ConnectorVersion = "1.0 beta" },
		"sem FLEET_STATE_DIR":     func(c *Config) { c.StateDir = "" },
		"sem GVM":                 func(c *Config) { c.GVM = nil },
		"sem tenants":             func(c *Config) { c.Tenants = nil },
		"sem auditoria":           func(c *Config) { c.Audit = nil },
		"sem piso":                func(c *Config) { c.Floor = nil },
		"intervalo de 29 s":       func(c *Config) { c.Interval = 29 * time.Second },
		"intervalo com fração":    func(c *Config) { c.Interval = 30*time.Second + time.Millisecond },
		"intervalo de 10 min 1 s": func(c *Config) { c.Interval = 10*time.Minute + time.Second },
	}
	for name, mutate := range bad {
		cfg := base
		mutate(&cfg)
		if _, err := Open(cfg); err == nil {
			t.Errorf("%s: abriu", name)
		}
	}
}

// Uma fonte fora do ar custa só os kinds dela: cada um mantém o último retrato e expõe o erro, os outros avançam e
// o node fica degradado.
func TestFalhaDeUmaFonteIsolada(t *testing.T) {
	sources := map[string]func(f *fakes){
		"tasks":    func(f *fakes) { f.gvm.errs[contract.KindTasks] = errFonte },
		"agents":   func(f *fakes) { f.cp.errs[contract.KindAgents] = errFonte },
		"audit":    func(f *fakes) { f.audit.tail.Exec.FirstSeq = i64p(1) }, // sem linhas: incoerente
		"senhas":   func(f *fakes) { f.tenants.pwErr = errFonte },
		"política": nil, // tratada abaixo
	}
	for name, breakIt := range sources {
		f := newFakes()
		cfg := f.config(t, contract.NodeCentral)
		c := openCollector(t, cfg)
		c.Collect(context.Background())
		before := map[contract.StateKind]string{}
		for kind, h := range c.Hashes() {
			before[kind] = h
		}
		if len(before) != len(centralKinds) {
			t.Fatalf("%s: primeiro ciclo incompleto: %v", name, c.Errors())
		}
		// muda o estado de todo kind de lista do gvmd e quebra uma fonte
		f.gvm.tasks.Items = append(f.gvm.tasks.Items, fullTask(uuidTask1, "acme"))
		f.gvm.targets.Items = append(f.gvm.targets.Items, fullTarget(uuidTarget1, "acme", "192.0.2.1"))
		if breakIt != nil {
			breakIt(f)
		} else if err := os.WriteFile(filepath.Join(cfg.StateDir, "policy.json"), []byte("{"), 0o600); err != nil {
			t.Fatal(err)
		}
		c.Collect(context.Background())
		errs := c.Errors()
		if len(errs) == 0 {
			t.Fatalf("%s: a falha não apareceu", name)
		}
		for kind, err := range errs {
			if err == nil {
				continue
			}
			if c.Hashes()[kind] != before[kind] {
				t.Errorf("%s: %s falhou e perdeu o último retrato", name, kind)
			}
		}
		if errs[contract.KindTargets] == nil && c.Hashes()[contract.KindTargets] == before[contract.KindTargets] {
			t.Errorf("%s: targets não avançou", name)
		}
		if errs[contract.KindNode] == nil {
			if s := nodeOf(t, c).Health.Status; s != contract.HealthDegraded {
				t.Errorf("%s: node %s com uma fonte fora", name, s)
			}
		}
	}
}

// O ciclo completo do "só envia quando muda" pela API que a F2.6 vai usar: tudo pendente no começo, enviado e
// marcado deixa de estar, um ciclo igual não cria pendência, uma mudança cria só a dela.
func TestPendenteEnviadoSemPendenciaPeloCollector(t *testing.T) {
	f := newFakes()
	c := collectOnce(t, f, contract.NodeCentral)
	if p := c.Pending(); !slices.Equal(p, centralKinds) {
		t.Fatalf("pendentes no começo %v", p)
	}
	sendAll(t, c)
	if p := c.Pending(); len(p) != 0 {
		t.Fatalf("depois de enviar %v", p)
	}
	f.now = f.now.Add(time.Minute)
	c.Collect(context.Background())
	if p := c.Pending(); len(p) != 0 {
		t.Fatalf("ciclo igual criou pendência %v", p)
	}
	f.gvm.tasks.Items = append(f.gvm.tasks.Items, fullTask(uuidTask1, "acme"))
	c.Collect(context.Background())
	if p := c.Pending(); !slices.Equal(p, []contract.StateKind{contract.KindTasks}) {
		t.Fatalf("mudança em tasks: %v", p)
	}
	s, _ := c.Current(contract.KindTasks)
	if !s.CollectedAt.Equal(f.now) {
		t.Fatalf("collected_at %v", s.CollectedAt)
	}
}

// sendAll faz o papel da F2.6, na ordem BeginSend → Current → Body → PUT → MarkSent: monta o corpo de cada kind
// pendente, confere-o como o hub conferiria e marca.
func sendAll(t *testing.T, c *Collector) {
	t.Helper()
	for _, kind := range c.Pending() {
		if err := c.BeginSend(kind); err != nil {
			t.Fatal(err)
		}
		s, ok := c.Current(kind)
		if !ok {
			t.Fatalf("%s pendente sem retrato", kind)
		}
		body, err := s.Body("node-lab-0001")
		if err != nil {
			t.Fatal(err)
		}
		var put contract.StateSnapshot
		if err := contract.DecodeStrict(body, &put); err != nil || put.Kind != kind || sha(put.Data) != put.ContentSHA256 {
			t.Fatalf("%s: corpo %v", kind, err)
		}
		decodeData(t, kind, put.Data)
		if err := c.MarkSent(kind, put.ContentSHA256); err != nil {
			t.Fatal(err)
		}
	}
}

// O A→B→A pela API do Collector: o hub aceitou B, o processo caiu antes do MarkSent e o estado voltou para A; com
// o BeginSend antes do PUT, o A de volta é reenviado depois do reinício.
func TestBeginSendPeloCollectorNaoPerdeReenvio(t *testing.T) {
	f := newFakes()
	cfg := f.config(t, contract.NodeStandalone)
	c := openCollector(t, cfg)
	c.Collect(context.Background())
	sendAll(t, c) // o hub tem A de todo kind
	before := c.Hashes()[contract.KindTasks]

	f.gvm.tasks.Items = append(f.gvm.tasks.Items, fullTask(uuidTask1, "acme")) // B
	c.Collect(context.Background())
	if err := c.BeginSend(contract.KindTasks); err != nil {
		t.Fatal(err)
	}
	// PUT de B aceito pelo hub; o processo cai antes do MarkSent

	f.gvm.tasks.Items = nil // de volta a A
	again := openCollector(t, cfg)
	again.Collect(context.Background())
	if again.Hashes()[contract.KindTasks] != before {
		t.Fatal("o estado não voltou para A")
	}
	if p := again.Pending(); !slices.Equal(p, []contract.StateKind{contract.KindTasks}) {
		t.Fatalf("A de volta não ficou pendente: %v", p)
	}
}

// Um reinício (Collector novo no mesmo FLEET_STATE_DIR) não reenvia o que o hub já tem; só o que mudou.
func TestReinicioNaoReenviaSemNecessidadePeloCollector(t *testing.T) {
	f := newFakes()
	cfg := f.config(t, contract.NodeCentral)
	c := openCollector(t, cfg)
	c.Collect(context.Background())
	sendAll(t, c)

	f.gvm.reports.Items = append(f.gvm.reports.Items, fullReport(uuidReport1, "acme")) // mudou durante a parada
	again := openCollector(t, cfg)
	again.Collect(context.Background())
	if p := again.Pending(); !slices.Equal(p, []contract.StateKind{contract.KindReports}) {
		t.Fatalf("pendentes depois do reinício %v", p)
	}
}

func TestResyncPeloCollector(t *testing.T) {
	f := newFakes()
	c := collectOnce(t, f, contract.NodeStandalone)
	sendAll(t, c)
	got, err := c.Resync([]contract.StateKind{contract.KindAgents, contract.KindTasks, contract.KindNode})
	if err != nil {
		t.Fatal(err)
	}
	want := []contract.StateKind{contract.KindNode, contract.KindTasks}
	if !slices.Equal(got, want) || !slices.Equal(c.Pending(), want) {
		t.Fatalf("resync %v, pendentes %v", got, c.Pending())
	}
}

func TestHashesParaOHeartbeat(t *testing.T) {
	c := collectOnce(t, newFakes(), contract.NodeCentral)
	h := c.Hashes()
	if len(h) != len(centralKinds) {
		t.Fatalf("hashes %v", h)
	}
	for _, kind := range centralKinds {
		if s, _ := c.Current(kind); h[kind] != s.SHA256 || !ruleSHA256.ok(h[kind]) {
			t.Errorf("%s: %q", kind, h[kind])
		}
	}
}

func TestRunColetaJaEDepoisACadaIntervalo(t *testing.T) {
	f := newFakes()
	cfg := f.config(t, contract.NodeStandalone)
	cfg.Interval = 45 * time.Second
	c := openCollector(t, cfg)
	tick := make(chan time.Time)
	var gotInterval time.Duration
	stopped := false
	c.newTicker = func(d time.Duration) (<-chan time.Time, func()) {
		gotInterval = d
		return tick, func() { stopped = true }
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error)
	go func() { done <- c.Run(ctx) }()
	waitFor(t, func() bool { return f.gvm.calls(contract.KindTasks) == 1 }) // coletou já, antes de qualquer tick
	tick <- time.Now()
	tick <- time.Now() // o segundo só é aceito depois que o ciclo do primeiro terminou
	waitFor(t, func() bool { return f.gvm.calls(contract.KindTasks) >= 3 })
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("Run = %v", err)
	}
	if gotInterval != 45*time.Second || !stopped {
		t.Fatalf("intervalo %v, ticker parado %v", gotInterval, stopped)
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("tempo esgotado")
		}
		time.Sleep(time.Millisecond)
	}
}

func (f *fakeGVM) calls(kind contract.StateKind) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.owners[kind])
}

func TestCollectComContextoEncerradoNaoColeta(t *testing.T) {
	f := newFakes()
	c := openCollector(t, f.config(t, contract.NodeStandalone))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c.Collect(ctx)
	if len(c.Hashes()) != 0 || f.gvm.calls(contract.KindTasks) != 0 {
		t.Fatal("coletou com o contexto encerrado")
	}
}

// Uma falha é logada quando começa (ou muda) e quando passa, nunca a cada ciclo.
func TestErroLogadoSoNaTransicao(t *testing.T) {
	var buf syncBuffer
	f := newFakes()
	cfg := f.config(t, contract.NodeStandalone)
	cfg.Logger = slog.New(slog.NewTextHandler(&buf, nil))
	c := openCollector(t, cfg)
	f.gvm.errs[contract.KindTasks] = errFonte
	for range 3 {
		c.Collect(context.Background())
	}
	f.gvm.errs[contract.KindTasks] = errors.New("outra falha")
	c.Collect(context.Background())
	delete(f.gvm.errs, contract.KindTasks)
	c.Collect(context.Background())
	c.Collect(context.Background())
	out := buf.String()
	if n := strings.Count(out, "kind=tasks"); n != 3 { // falhou, mudou de erro, voltou
		t.Fatalf("%d linhas de tasks:\n%s", n, out)
	}
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// Com o tenant.Source de verdade (registro e segredos do central em arquivo): o scope diz quem pode escrever e
// nenhum kind leva senha nem nome de usuário gvmd.
func TestNenhumKindLevaSenhaNemUsuarioGVMD(t *testing.T) {
	dir := t.TempDir()
	tenants := filepath.Join(dir, "tenants.json")
	secrets := filepath.Join(dir, "secrets.json")
	write := func(p, s string) {
		if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(tenants, `[{"name":"acme","scope":"192.0.2.0/24","gmp_user":"usuario-gvmd-acme","enabled":true},`+
		`{"name":"globex","scope":"198.51.100.0/24","gmp_user":"usuario-gvmd-globex","enabled":true}]`)
	write(secrets, `{"acme":"senha-acme-ficticia","globex":""}`)
	src, err := tenant.Open(contract.NodeCentral, tenant.Config{TenantsFile: tenants, SecretsFile: secrets})
	if err != nil {
		t.Fatal(err)
	}
	f := newFakes()
	f.gvm.tasks = contract.DataTasks{Items: []contract.TaskItem{fullTask(uuidTask1, "acme")}}
	cfg := f.config(t, contract.NodeCentral)
	cfg.Tenants = src
	c := openCollector(t, cfg)
	c.Collect(context.Background())
	if errs := c.Errors(); len(errs) != 0 {
		t.Fatalf("erros %v", errs)
	}
	scope := current(t, c, contract.KindScope).(*contract.DataScope)
	if len(scope.Items) != 2 || !scope.Items[0].GMPUserConfigured || scope.Items[1].GMPUserConfigured {
		t.Fatalf("scope %+v", scope.Items)
	}
	if got := f.gvm.owners[contract.KindTasks][0]; got["usuario-gvmd-acme"] != "acme" {
		t.Fatalf("owners %v", got)
	}
	for _, kind := range c.Kinds() {
		s, _ := c.Current(kind)
		for _, secret := range []string{"senha-acme-ficticia", "usuario-gvmd"} {
			if bytes.Contains(s.Data, []byte(secret)) {
				t.Errorf("%s levou %q", kind, secret)
			}
		}
	}
}

// Todo data que o Collector gera, de todo kind, passa no DecodeStrict do tipo do contrato e vira um corpo de PUT
// que o hub aceitaria (content_sha256 dos bytes crus).
func TestTodoDataGeradoPassaNoDecodeStrict(t *testing.T) {
	f := newFakes()
	f.tenants.list = append(f.tenants.list, tenant.Listing{Name: "initech", Enabled: false, Scope: "203.0.113.0/24 2001:db8::/48"})
	f.gvm.tasks = contract.DataTasks{Items: []contract.TaskItem{fullTask(uuidTask1, "acme"), fullTask(uuidTask2, "globex")}, UnattributedCount: 3}
	f.gvm.targets = contract.DataTargets{Items: []contract.TargetItem{fullTarget(uuidTarget1, "acme", "192.0.2.0/24", "2001:db8::1")}}
	f.gvm.schedules = contract.DataSchedules{Items: []contract.ScheduleItem{fullSchedule(uuidSched1, "acme", uuidTask1)}}
	f.gvm.reports = contract.DataReports{Items: []contract.ReportItem{fullReport(uuidReport1, "globex")}, Truncated: true}
	f.cp.agents = []contract.AgentItem{fullAgent("DESKTOP-01", "acme")}
	f.cp.tokens = []contract.TokenItem{{TokenID: "tok_ABCdef12", Tenant: "acme", TokenType: contract.TokenDeployment,
		Policy: strp("agent-endpoint"), MaxUses: 10, Remaining: 9, ExpiresAt: "2026-10-18T12:00:00Z", Revoked: true}}
	f.cp.sensors = []contract.SensorItem{{SensorID: "sensor-01", Tenant: "globex", Online: true, GVMDUp: boolp(false)}}
	f.cp.scanRequests = []contract.ScanRequestItem{{JobID: "job-1", Tenant: "acme", State: contract.ScanRequestAcked,
		TargetsCount: 4, CreatedAt: "2026-10-11T11:00:00Z"}}
	f.cp.remediation = []contract.RemediationItem{{JobID: "rem-1", Tenant: "acme", AgentID: "DESKTOP-01",
		Type: contract.RemediationConfigHardening, State: contract.RemediationApproved, CreatedAt: "2026-10-11T10:00:00Z",
		ApprovedAt: strp("2026-10-11T10:05:00Z")}}
	line := `{"stream":"exec","seq":1,"at":"2026-10-11T12:00:00Z","event":"connector_started","prev_sha256":"` + strings.Repeat("0", 64) + `"}`
	f.audit.tail.Exec = contract.AuditStreamTail{Lines: []string{line}, FirstSeq: i64p(1), LastSeq: i64p(1), HeadSHA256: strp(sha([]byte(line)))}
	c := collectOnce(t, f, contract.NodeCentral)
	if errs := c.Errors(); len(errs) != 0 {
		t.Fatalf("erros %v", errs)
	}
	sendAll(t, c) // decodifica cada data e confere cada corpo
	if p := c.Pending(); len(p) != 0 {
		t.Fatalf("pendentes %v", p)
	}
}

// A coleta corre numa goroutine enquanto o envio lê e marca em outra (o -race do CI pega o que este teste não vê).
func TestCollectorConcorrente(t *testing.T) {
	f := newFakes()
	c := collectOnce(t, f, contract.NodeCentral)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for range 5 {
			c.Collect(context.Background())
		}
	}()
	go func() {
		defer wg.Done()
		for range 50 {
			for _, kind := range c.Pending() {
				if s, ok := c.Current(kind); ok {
					_ = c.MarkSent(kind, s.SHA256)
				}
			}
			c.Hashes()
			c.Errors()
			_, _ = c.ReportFormats()
			_, _ = c.Resync([]contract.StateKind{contract.KindTasks})
		}
	}()
	wg.Wait()
}
