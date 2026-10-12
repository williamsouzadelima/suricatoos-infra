package state

import (
	"bytes"
	"context"
	"reflect"
	"slices"
	"testing"

	"github.com/williamsouzadelima/suricatoos-infra/fleet/contract"
	"github.com/williamsouzadelima/suricatoos-infra/fleet/internal/tenant"
)

func agentPolicy(p contract.AgentPolicy) *contract.AgentPolicy { return &p }

func fullAgent(id, tenantName string) contract.AgentItem {
	return contract.AgentItem{AgentID: id, Tenant: tenantName, Policy: agentPolicy(contract.PolicyAgentEndpoint),
		OS: strp("windows"), Arch: strp("amd64"), AgentVersion: strp("1.4.0"), LastSeen: strp("2026-10-11T11:58:00Z"),
		Online: true}
}

// O tenant de um agente é o O do certificado: só um tenant conhecido do nó (habilitado ou não) é listado; o resto
// — desconhecido, vazio, fora do padrão — é só contado. Agentes de tenants diferentes podem ter o mesmo agent_id
// (o hostname): os dois saem, em ordem de (agent_id, tenant).
func TestAgentsAtribuidosSoATenantConhecido(t *testing.T) {
	f := newFakes()
	f.tenants.list = append(f.tenants.list, tenant.Listing{Name: "initech", Enabled: false})
	a1, a2, a3 := fullAgent("DESKTOP-01", "globex"), fullAgent("DESKTOP-01", "acme"), fullAgent("ALPHA", "initech")
	f.cp.agents = []contract.AgentItem{a1, fullAgent("X", "intruso"), a2, fullAgent("Y", ""), a3, fullAgent("Z", "-ruim-")}
	got := current(t, collectOnce(t, f, contract.NodeCentral), contract.KindAgents).(*contract.DataAgents)
	if want := []contract.AgentItem{a3, a2, a1}; !reflect.DeepEqual(got.Items, want) || got.UnattributedCount != 3 || got.Truncated {
		t.Fatalf("agents %+v", got)
	}
}

func TestItensDoControlPlaneForaDoSchemaSoContados(t *testing.T) {
	f := newFakes()
	badPolicy := contract.AgentPolicy("admin")
	f.cp.agents = []contract.AgentItem{
		fullAgent("ok", "acme"),
		func() contract.AgentItem { a := fullAgent("a,b", "acme"); return a }(),
		func() contract.AgentItem { a := fullAgent("p", "acme"); a.Policy = &badPolicy; return a }(),
		func() contract.AgentItem { a := fullAgent("o", "acme"); a.OS = strp("windows 11 pro for workstations x64"); return a }(),
		func() contract.AgentItem { a := fullAgent("v", "acme"); a.AgentVersion = strp("1.0 beta"); return a }(),
		func() contract.AgentItem { a := fullAgent("l", "acme"); a.LastSeen = strp("ontem"); return a }(),
	}
	f.cp.tokens = []contract.TokenItem{
		{TokenID: "tok_ABCdef12", Tenant: "acme", TokenType: contract.TokenDeployment, Policy: strp("agent-endpoint"),
			MaxUses: 10, Remaining: 9, ExpiresAt: "2026-10-18T12:00:00Z"},
		{TokenID: "tok", Tenant: "acme", TokenType: contract.TokenSingleHost, MaxUses: 1, ExpiresAt: "2026-10-18T12:00:00Z"},
		{TokenID: "tok_ABCdef13", Tenant: "acme", TokenType: "outro", MaxUses: 1, ExpiresAt: "2026-10-18T12:00:00Z"},
		{TokenID: "tok_ABCdef14", Tenant: "acme", TokenType: contract.TokenSingleHost, MaxUses: 0, ExpiresAt: "2026-10-18T12:00:00Z"},
		{TokenID: "tok_ABCdef15", Tenant: "acme", TokenType: contract.TokenSingleHost, MaxUses: 1, Remaining: -1, ExpiresAt: "2026-10-18T12:00:00Z"},
		{TokenID: "tok_ABCdef16", Tenant: "acme", TokenType: contract.TokenSingleHost, MaxUses: 1, ExpiresAt: ""},
	}
	f.cp.sensors = []contract.SensorItem{
		{SensorID: "sensor-filial-01", Tenant: "acme", LastSeen: strp("2026-10-11T11:59:00Z"), Online: true,
			FeedVersion: strp("202610110600"), GVMDUp: boolp(true), ActiveJobs: i64p(1)},
		{SensorID: "sensor<2>", Tenant: "acme"},
		{SensorID: "sensor-3", Tenant: "acme", ActiveJobs: i64p(-1)},
	}
	f.cp.scanRequests = []contract.ScanRequestItem{
		{JobID: "job-1", Tenant: "acme", State: contract.ScanRequestPending, TargetsCount: 12, CreatedAt: "2026-10-11T11:00:00Z",
			ExpiresAt: strp("2026-10-12T11:00:00Z")},
		{JobID: "job.2", Tenant: "acme", State: contract.ScanRequestDone, CreatedAt: "2026-10-11T11:00:00Z"},
		{JobID: "job-3", Tenant: "acme", State: "RUNNING", CreatedAt: "2026-10-11T11:00:00Z"},
		{JobID: "job-4", Tenant: "acme", State: contract.ScanRequestDone, TargetsCount: -1, CreatedAt: "2026-10-11T11:00:00Z"},
	}
	f.cp.remediation = []contract.RemediationItem{
		{JobID: "rem-1", Tenant: "acme", AgentID: "DESKTOP-01", Type: contract.RemediationPackagePatch,
			State: contract.RemediationPendingApproval, CreatedAt: "2026-10-11T10:00:00Z"},
		{JobID: "rem-2", Tenant: "acme", AgentID: "DESKTOP-01", Type: "shell", State: contract.RemediationApplied, CreatedAt: "2026-10-11T10:00:00Z"},
		{JobID: "rem-3", Tenant: "acme", AgentID: "DESKTOP-01", Type: contract.RemediationConfigHardening, State: "DONE", CreatedAt: "2026-10-11T10:00:00Z"},
		{JobID: "rem-4", Tenant: "acme", AgentID: "", Type: contract.RemediationConfigHardening, State: contract.RemediationExpired, CreatedAt: "2026-10-11T10:00:00Z"},
		{JobID: "rem-5", Tenant: "acme", AgentID: "D", Type: contract.RemediationConfigHardening, State: contract.RemediationExpired,
			CreatedAt: "2026-10-11T10:00:00Z", ApprovedAt: strp("x")},
	}
	c := collectOnce(t, f, contract.NodeCentral)
	for kind, want := range map[contract.StateKind][2]int64{
		contract.KindAgents: {1, 5}, contract.KindTokens: {1, 5}, contract.KindSensors: {1, 2},
		contract.KindScanRequests: {1, 3}, contract.KindRemediation: {1, 4},
	} {
		listed, counted := listCounts(t, current(t, c, kind))
		if listed != want[0] || counted != want[1] {
			t.Errorf("%s: %d listados e %d contados, esperava %v", kind, listed, counted, want)
		}
	}
}

func listCounts(t *testing.T, v any) (int64, int64) {
	t.Helper()
	switch d := v.(type) {
	case *contract.DataAgents:
		return int64(len(d.Items)), d.UnattributedCount
	case *contract.DataTokens:
		return int64(len(d.Items)), d.UnattributedCount
	case *contract.DataSensors:
		return int64(len(d.Items)), d.UnattributedCount
	case *contract.DataScanRequests:
		return int64(len(d.Items)), d.UnattributedCount
	case *contract.DataRemediation:
		return int64(len(d.Items)), d.UnattributedCount
	}
	t.Fatalf("tipo %T", v)
	return 0, 0
}

// Os pedidos do loop ADR-0006 não têm tenant: só contados; os jobs de sensor levam a contagem de alvos, nunca os
// alvos (o tipo nem tem onde pô-los).
func TestScanRequestsSemTenantSoContados(t *testing.T) {
	f := newFakes()
	job := contract.ScanRequestItem{JobID: "job-1", Tenant: "acme", State: contract.ScanRequestDelivered, TargetsCount: 3,
		CreatedAt: "2026-10-11T11:00:00Z"}
	f.cp.scanRequests = []contract.ScanRequestItem{job, {JobID: "loop-1", State: contract.ScanRequestPending, TargetsCount: 1,
		CreatedAt: "2026-10-11T11:00:00Z"}}
	got := current(t, collectOnce(t, f, contract.NodeCentral), contract.KindScanRequests).(*contract.DataScanRequests)
	if !reflect.DeepEqual(got.Items, []contract.ScanRequestItem{job}) || got.UnattributedCount != 1 {
		t.Fatalf("scan_requests %+v", got)
	}
}

func TestKindsDoCentralNaoExistemForaDele(t *testing.T) {
	f := newFakes()
	f.cp.agents = []contract.AgentItem{fullAgent("DESKTOP-01", "acme")}
	for _, kind := range []contract.NodeKind{contract.NodeStandalone, contract.NodeSensor} {
		cfg := f.config(t, kind)
		cfg.ControlPlane = f.cp // configurado por engano: ignorado
		c := openCollector(t, cfg)
		c.Collect(context.Background())
		for _, k := range []contract.StateKind{contract.KindAgents, contract.KindTokens, contract.KindSensors,
			contract.KindScanRequests, contract.KindRemediation} {
			if _, ok := c.Current(k); ok || slices.Contains(c.Kinds(), k) {
				t.Errorf("%s: %s existe", kind, k)
			}
		}
	}
	if n := len(f.cp.calls); n != 0 {
		t.Fatalf("o control-plane foi consultado fora do central: %v", f.cp.calls)
	}
}

func TestCentralSemControlPlaneNaoAbre(t *testing.T) {
	f := newFakes()
	cfg := f.config(t, contract.NodeCentral)
	cfg.ControlPlane = nil
	if _, err := Open(cfg); err == nil {
		t.Fatal("central sem a API admin abriu")
	}
}

// Uma leitura do control-plane que falha custa só o seu kind.
func TestFalhaDeUmaLeituraDoControlPlaneIsolada(t *testing.T) {
	f := newFakes()
	f.cp.agents = []contract.AgentItem{fullAgent("DESKTOP-01", "acme")}
	f.cp.tokens = []contract.TokenItem{{TokenID: "tok_ABCdef12", Tenant: "acme", TokenType: contract.TokenSingleHost,
		MaxUses: 1, Remaining: 1, ExpiresAt: "2026-10-18T12:00:00Z"}}
	c := collectOnce(t, f, contract.NodeCentral)
	before, _ := c.Current(contract.KindAgents)
	f.cp.errs[contract.KindAgents] = errFonte
	f.cp.agents = nil
	f.cp.tokens = append(f.cp.tokens, contract.TokenItem{TokenID: "tok_ABCdef13", Tenant: "acme",
		TokenType: contract.TokenSingleHost, MaxUses: 1, ExpiresAt: "2026-10-18T12:00:00Z"})
	c.Collect(context.Background())
	if after, _ := c.Current(contract.KindAgents); !bytes.Equal(after.Data, before.Data) {
		t.Fatal("o kind que falhou perdeu o último retrato")
	}
	if got := current(t, c, contract.KindTokens).(*contract.DataTokens); len(got.Items) != 2 {
		t.Fatalf("tokens não avançou: %+v", got)
	}
	if errs := c.Errors(); errs[contract.KindAgents] == nil || errs[contract.KindTokens] != nil {
		t.Fatalf("erros %v", errs)
	}
}
