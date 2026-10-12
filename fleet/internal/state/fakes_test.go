package state

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/williamsouzadelima/suricatoos-infra/fleet/contract"
	"github.com/williamsouzadelima/suricatoos-infra/fleet/internal/tenant"
)

const testFloor = "2026-10-11T09:00:00Z"

// fakeGVM faz o papel do fleet_ops: devolve o que o teste pôs e guarda o que recebeu.
type fakeGVM struct {
	mu        sync.Mutex
	tasks     contract.DataTasks
	targets   contract.DataTargets
	schedules contract.DataSchedules
	reports   contract.DataReports
	errs      map[contract.StateKind]error
	node      func(req NodeRequest) (contract.DataNode, error) // nil = echoNode
	owners    map[contract.StateKind][]map[string]string
	nodeReqs  []NodeRequest
}

func newFakeGVM() *fakeGVM {
	return &fakeGVM{
		tasks:     contract.DataTasks{Items: []contract.TaskItem{}},
		targets:   contract.DataTargets{Items: []contract.TargetItem{}},
		schedules: contract.DataSchedules{Items: []contract.ScheduleItem{}},
		reports:   contract.DataReports{Items: []contract.ReportItem{}},
		errs:      map[contract.StateKind]error{},
		owners:    map[contract.StateKind][]map[string]string{},
	}
}

func (f *fakeGVM) seen(kind contract.StateKind, owners map[string]string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.owners[kind] = append(f.owners[kind], owners)
	return f.errs[kind]
}

func (f *fakeGVM) Tasks(_ context.Context, owners map[string]string) (contract.DataTasks, error) {
	if err := f.seen(contract.KindTasks, owners); err != nil {
		return contract.DataTasks{}, err
	}
	return f.tasks, nil
}

func (f *fakeGVM) Targets(_ context.Context, owners map[string]string) (contract.DataTargets, error) {
	if err := f.seen(contract.KindTargets, owners); err != nil {
		return contract.DataTargets{}, err
	}
	return f.targets, nil
}

func (f *fakeGVM) Schedules(_ context.Context, owners map[string]string) (contract.DataSchedules, error) {
	if err := f.seen(contract.KindSchedules, owners); err != nil {
		return contract.DataSchedules{}, err
	}
	return f.schedules, nil
}

func (f *fakeGVM) Reports(_ context.Context, owners map[string]string) (contract.DataReports, error) {
	if err := f.seen(contract.KindReports, owners); err != nil {
		return contract.DataReports{}, err
	}
	return f.reports, nil
}

func (f *fakeGVM) Node(_ context.Context, req NodeRequest) (contract.DataNode, error) {
	f.mu.Lock()
	f.nodeReqs = append(f.nodeReqs, req)
	fn, err := f.node, f.errs[contract.KindNode]
	f.mu.Unlock()
	if err != nil {
		return contract.DataNode{}, err
	}
	if fn == nil {
		fn = echoNode
	}
	return fn(req)
}

// echoNode é o que o fleet_ops faz no state.node com o gvmd de pé: devolve os membros do conector e acrescenta os
// do gvmd (versões gmp_protocol e python_gvm, feeds, saúde, report_formats técnicos).
func echoNode(req NodeRequest) (contract.DataNode, error) {
	v := contract.NodeVersions{GMPProtocol: strp("22.7"), PythonGVM: strp("27.10.0")}
	health := contract.NodeHealth{Status: contract.HealthOK, GVMDUp: true}
	if req.Versions != nil {
		v.GVMD, v.OpenVASScanner, v.GSA, v.ControlPlane = req.Versions.GVMD, req.Versions.OpenVASScanner, req.Versions.GSA, req.Versions.ControlPlane
	}
	if req.Health != nil {
		health.ScannerUp, health.DiskFreePct, health.ActiveTasks, health.ClockOffsetS = req.Health.ScannerUp,
			req.Health.DiskFreePct, req.Health.ActiveTasks, req.Health.ClockOffsetS
	}
	return contract.DataNode{
		NodeKind:         req.NodeKind,
		ConnectorVersion: req.ConnectorVersion,
		Versions:         v,
		Feeds:            []contract.FeedStatus{{Feed: contract.FeedNVT, Version: "202610110600", AgeHours: 6, Syncing: false}},
		Health:           health,
		Capabilities: contract.NodeCapabilities{
			SupportedTypes: slices.Clone(req.SupportedTypes),
			StateKinds:     slices.Clone(req.StateKinds),
			ReportFormats: []contract.ReportFormatCapability{
				{Format: contract.FormatSuricatoosPDF, Lang: contract.LangEN, Variants: []contract.ReportVariant{contract.VariantTechnical}},
				{Format: contract.FormatGVMXML, Lang: contract.LangEN, Variants: []contract.ReportVariant{contract.VariantTechnical}},
			},
		},
		Policy:       req.Policy,
		PolicySHA256: req.PolicySHA256,
		ReplayFloor:  req.ReplayFloor,
	}, nil
}

func strp(s string) *string { return &s }
func intp(i int) *int       { return &i }
func i64p(i int64) *int64   { return &i }
func boolp(b bool) *bool    { return &b }

// fakeTenants é o tenant.Source do teste (só o que o estado usa).
type fakeTenants struct {
	mu      sync.Mutex
	list    []tenant.Listing
	listErr error
	pw      map[string]bool
	pwErr   error
}

func (f *fakeTenants) List() ([]tenant.Listing, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.list), f.listErr
}

func (f *fakeTenants) WithPassword() (map[string]bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := map[string]bool{}
	for k, v := range f.pw {
		out[k] = v
	}
	return out, f.pwErr
}

type fakeAudit struct {
	mu   sync.Mutex
	tail contract.DataAuditTail
}

func (f *fakeAudit) Tail() contract.DataAuditTail {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.tail
}

type fakeFloor struct {
	mu    sync.Mutex
	floor string
}

func (f *fakeFloor) ReplayFloor() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.floor
}

// fakes reúne as fontes de um Collector de teste.
type fakes struct {
	gvm     *fakeGVM
	cp      *fakeCP
	tenants *fakeTenants
	audit   *fakeAudit
	floor   *fakeFloor
	now     time.Time
}

func newFakes() *fakes {
	return &fakes{
		gvm: newFakeGVM(),
		cp:  newFakeCP(),
		tenants: &fakeTenants{list: []tenant.Listing{
			{Name: "acme", Enabled: true, Scope: "192.0.2.0/24", GVMUser: "tenant-acme"},
			{Name: "globex", Enabled: true, Scope: "198.51.100.0/24", GVMUser: "tenant-globex"},
		}, pw: map[string]bool{"acme": true}},
		audit: &fakeAudit{tail: contract.DataAuditTail{Exec: contract.AuditStreamTail{Lines: []string{}},
			Reject: contract.AuditStreamTail{Lines: []string{}}}},
		floor: &fakeFloor{floor: testFloor},
		now:   at,
	}
}

func (f *fakes) config(t *testing.T, kind contract.NodeKind) Config {
	t.Helper()
	cfg := Config{
		NodeKind:         kind,
		ConnectorVersion: "1.0.0",
		StateDir:         t.TempDir(),
		GVM:              f.gvm,
		Tenants:          f.tenants,
		Audit:            f.audit,
		Floor:            f.floor,
		Now:              func() time.Time { return f.now },
	}
	if kind == contract.NodeCentral {
		cfg.ControlPlane = f.cp
	}
	return cfg
}

func openCollector(t *testing.T, cfg Config) *Collector {
	t.Helper()
	c, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// collectOnce abre um Collector com as fontes falsas, roda um ciclo e devolve o Collector.
func collectOnce(t *testing.T, f *fakes, kind contract.NodeKind) *Collector {
	t.Helper()
	c := openCollector(t, f.config(t, kind))
	c.Collect(context.Background())
	return c
}

// current devolve o data atual de um kind já decodificado (e conferido) pelo tipo do contrato.
func current(t *testing.T, c *Collector, kind contract.StateKind) any {
	t.Helper()
	s, ok := c.Current(kind)
	if !ok {
		t.Fatalf("%s sem retrato (erros %v)", kind, c.Errors())
	}
	if s.SHA256 != sha(s.Data) {
		t.Fatalf("%s: hash não confere", kind)
	}
	return decodeData(t, kind, s.Data)
}

var errFonte = errors.New("fonte fora do ar")

// fakeCP é a API admin do control-plane (F2.2) do teste.
type fakeCP struct {
	mu           sync.Mutex
	agents       []contract.AgentItem
	tokens       []contract.TokenItem
	sensors      []contract.SensorItem
	scanRequests []contract.ScanRequestItem
	remediation  []contract.RemediationItem
	errs         map[contract.StateKind]error
	calls        map[contract.StateKind]int
}

func newFakeCP() *fakeCP {
	return &fakeCP{errs: map[contract.StateKind]error{}, calls: map[contract.StateKind]int{}}
}

func (f *fakeCP) called(kind contract.StateKind) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls[kind]++
	return f.errs[kind]
}

func (f *fakeCP) Agents(context.Context) ([]contract.AgentItem, error) {
	if err := f.called(contract.KindAgents); err != nil {
		return nil, err
	}
	return slices.Clone(f.agents), nil
}

func (f *fakeCP) Tokens(context.Context) ([]contract.TokenItem, error) {
	if err := f.called(contract.KindTokens); err != nil {
		return nil, err
	}
	return slices.Clone(f.tokens), nil
}

func (f *fakeCP) Sensors(context.Context) ([]contract.SensorItem, error) {
	if err := f.called(contract.KindSensors); err != nil {
		return nil, err
	}
	return slices.Clone(f.sensors), nil
}

func (f *fakeCP) ScanRequests(context.Context) ([]contract.ScanRequestItem, error) {
	if err := f.called(contract.KindScanRequests); err != nil {
		return nil, err
	}
	return slices.Clone(f.scanRequests), nil
}

func (f *fakeCP) Remediation(context.Context) ([]contract.RemediationItem, error) {
	if err := f.called(contract.KindRemediation); err != nil {
		return nil, err
	}
	return slices.Clone(f.remediation), nil
}
