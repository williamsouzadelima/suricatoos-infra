package state

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	"github.com/williamsouzadelima/suricatoos-infra/fleet/contract"
)

func caps(groups ...contract.ReportFormatCapability) []contract.ReportFormatCapability { return groups }

func rf(f contract.ReportFormat, l contract.ReportLang, vs ...contract.ReportVariant) contract.ReportFormatCapability {
	return contract.ReportFormatCapability{Format: f, Lang: l, Variants: vs}
}

const (
	tech = contract.VariantTechnical
	cli  = contract.VariantClient
	exe  = contract.VariantExecutive
)

func nodeOf(t *testing.T, c *Collector) *contract.DataNode {
	t.Helper()
	return current(t, c, contract.KindNode).(*contract.DataNode)
}

func lastNodeReq(t *testing.T, f *fakes) NodeRequest {
	t.Helper()
	if len(f.gvm.nodeReqs) == 0 {
		t.Fatal("o fleet_ops não recebeu state.node")
	}
	return f.gvm.nodeReqs[len(f.gvm.nodeReqs)-1]
}

// O conector manda ao fleet_ops os membros que são dele — node_kind, versão, política em vigor e o seu sha256,
// piso de replay, tipos suportados e kinds do node_kind — e o node sai com eles mais os do gvmd.
func TestNodeConteudo(t *testing.T) {
	for _, kind := range []contract.NodeKind{contract.NodeCentral, contract.NodeStandalone, contract.NodeSensor} {
		f := newFakes()
		c := collectOnce(t, f, kind)
		req := lastNodeReq(t, f)
		pol := contract.DefaultPolicy(kind)
		want := NodeRequest{NodeKind: kind, ConnectorVersion: "1.0.0", Policy: pol, PolicySHA256: contract.PolicySHA256(pol),
			ReplayFloor: testFloor, SupportedTypes: contract.SupportedTypes(kind), StateKinds: KindsOf(kind)}
		if !reflect.DeepEqual(req, want) {
			t.Errorf("%s: pedido %+v", kind, req)
		}
		got := nodeOf(t, c)
		if got.NodeKind != kind || got.ReplayFloor != testFloor || got.PolicySHA256 != want.PolicySHA256 ||
			got.Health.Status != contract.HealthOK || !got.Health.GVMDUp || len(got.Feeds) != 1 || *got.Versions.PythonGVM != "27.10.0" ||
			!slices.Equal(got.Capabilities.StateKinds, KindsOf(kind)) {
			t.Errorf("%s: node %+v", kind, got)
		}
	}
}

func TestNodeComAPoliticaDoArquivo(t *testing.T) {
	f := newFakes()
	cfg := f.config(t, contract.NodeStandalone)
	content := `{"allow":["task.start","state.resync","report.export"],"sensitive_per_hour":10,"total_per_hour":60}`
	if err := os.WriteFile(filepath.Join(cfg.StateDir, "policy.json"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	c := openCollector(t, cfg)
	c.Collect(context.Background())
	got := nodeOf(t, c)
	want := contract.Policy{Allow: []contract.CommandType{contract.TypeTaskStart, contract.TypeStateResync,
		contract.TypeReportExport}, SensitivePerHour: 10, TotalPerHour: 60}
	if !reflect.DeepEqual(got.Policy, want) || got.PolicySHA256 != contract.PolicySHA256(want) {
		t.Fatalf("política %+v %s", got.Policy, got.PolicySHA256)
	}
}

// Uma política que não se lê não vira outra (nem a padrão): o node falha e mantém o último retrato.
func TestNodeComPoliticaInvalidaFalhaSemInventar(t *testing.T) {
	f := newFakes()
	cfg := f.config(t, contract.NodeStandalone)
	c := openCollector(t, cfg)
	c.Collect(context.Background())
	before, ok := c.Current(contract.KindNode)
	if !ok {
		t.Fatal("sem o node bom de antes")
	}
	if err := os.WriteFile(filepath.Join(cfg.StateDir, "policy.json"), []byte(`{"allow":["task.start"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	c.Collect(context.Background())
	if after, _ := c.Current(contract.KindNode); !bytes.Equal(after.Data, before.Data) || c.Errors()[contract.KindNode] == nil {
		t.Fatalf("node com política inválida: erros %v", c.Errors())
	}
	if c.Errors()[contract.KindTasks] != nil {
		t.Fatal("a política quebrada derrubou outro kind")
	}
}

func TestNodeSemPisoDeReplayFalha(t *testing.T) {
	for _, floor := range []string{"", "2026-02-30T00:00:00Z", "2026-10-11T12:00:00.5Z"} {
		f := newFakes()
		f.floor.floor = floor
		c := collectOnce(t, f, contract.NodeStandalone)
		if _, ok := c.Current(contract.KindNode); ok || c.Errors()[contract.KindNode] == nil {
			t.Errorf("piso %q: o node saiu sem piso válido", floor)
		}
	}
}

func TestNodeLevaOQueOConectorSabeSozinho(t *testing.T) {
	f := newFakes()
	cfg := f.config(t, contract.NodeCentral)
	disk := 41.7
	cfg.Local = func() Local {
		return Local{
			Versions: LocalVersions{GVMD: strp("26.31.1"), GSA: strp("27.4.1"), ControlPlane: strp("1.2.0"),
				OpenVASScanner: strp("versão ruim")}, // fora do version_string: omitida
			Health: LocalHealth{ScannerUp: boolp(true), DiskFreePct: &disk, ActiveTasks: i64p(2), ClockOffsetS: i64p(-3)},
		}
	}
	c := openCollector(t, cfg)
	c.Collect(context.Background())
	req := lastNodeReq(t, f)
	wantV := &LocalVersions{GVMD: strp("26.31.1"), GSA: strp("27.4.1"), ControlPlane: strp("1.2.0")}
	floored := 41.0
	wantH := &LocalHealth{ScannerUp: boolp(true), DiskFreePct: &floored, ActiveTasks: i64p(2), ClockOffsetS: i64p(-3)}
	if !reflect.DeepEqual(req.Versions, wantV) || !reflect.DeepEqual(req.Health, wantH) {
		t.Fatalf("pedido versions %+v health %+v", req.Versions, req.Health)
	}
	got := nodeOf(t, c)
	if *got.Versions.GVMD != "26.31.1" || got.Versions.OpenVASScanner != nil || *got.Health.DiskFreePct != 41 ||
		*got.Health.ClockOffsetS != -3 {
		t.Fatalf("node %+v / %+v", got.Versions, got.Health)
	}
}

func TestNodeDescartaMedidasForaDaFaixa(t *testing.T) {
	f := newFakes()
	cfg := f.config(t, contract.NodeStandalone)
	for _, disk := range []float64{-1, 100.5} {
		cfg.Local = func() Local { return Local{Health: LocalHealth{DiskFreePct: &disk, ActiveTasks: i64p(-1)}} }
		c := openCollector(t, cfg)
		c.Collect(context.Background())
		if req := lastNodeReq(t, f); req.Health != nil {
			t.Errorf("disco %v: health %+v", disk, req.Health)
		}
	}
}

// Sem o fleet_ops (erro, resposta que não ecoa o pedido, saúde fora do enum), o node ainda sai — é ele que
// carrega a saúde —, montado só com o que o conector sabe: gvmd fora (down, gvmd_up false), sem feeds nem
// formatos. O erro fica exposto.
func TestNodeSemOGVMSaiComoDown(t *testing.T) {
	bad := map[string]func(NodeRequest) (contract.DataNode, error){
		"erro":            func(NodeRequest) (contract.DataNode, error) { return contract.DataNode{}, errFonte },
		"outro node_kind": func(r NodeRequest) (contract.DataNode, error) { d, _ := echoNode(r); d.NodeKind = contract.NodeCentral; return d, nil },
		"outra política": func(r NodeRequest) (contract.DataNode, error) {
			d, _ := echoNode(r)
			d.Policy.Allow = append(d.Policy.Allow, contract.TypeTaskCreate)
			return d, nil
		},
		"outro piso":      func(r NodeRequest) (contract.DataNode, error) { d, _ := echoNode(r); d.ReplayFloor = "2026-10-11T08:00:00Z"; return d, nil },
		"outra versão":    func(r NodeRequest) (contract.DataNode, error) { d, _ := echoNode(r); d.ConnectorVersion = "9.9.9"; return d, nil },
		"outros tipos":    func(r NodeRequest) (contract.DataNode, error) { d, _ := echoNode(r); d.Capabilities.SupportedTypes = nil; return d, nil },
		"outros kinds":    func(r NodeRequest) (contract.DataNode, error) { d, _ := echoNode(r); d.Capabilities.StateKinds = d.Capabilities.StateKinds[1:]; return d, nil },
		"outro gvmd":      func(r NodeRequest) (contract.DataNode, error) { d, _ := echoNode(r); d.Versions.GVMD = strp("1.0"); return d, nil },
		"outro disco":     func(r NodeRequest) (contract.DataNode, error) { d, _ := echoNode(r); d.Health.DiskFreePct = nil; return d, nil },
		"saúde inválida":  func(r NodeRequest) (contract.DataNode, error) { d, _ := echoNode(r); d.Health.Status = "talvez"; return d, nil },
		"sha divergente":  func(r NodeRequest) (contract.DataNode, error) { d, _ := echoNode(r); d.PolicySHA256 = sha([]byte("x")); return d, nil },
	}
	for name, node := range bad {
		f := newFakes()
		f.gvm.node = node
		cfg := f.config(t, contract.NodeStandalone)
		disk := 50.0
		cfg.Local = func() Local {
			return Local{Versions: LocalVersions{GVMD: strp("26.31.1")}, Health: LocalHealth{DiskFreePct: &disk}}
		}
		c := openCollector(t, cfg)
		c.Collect(context.Background())
		got := nodeOf(t, c)
		pol := contract.DefaultPolicy(contract.NodeStandalone)
		want := &contract.DataNode{NodeKind: contract.NodeStandalone, ConnectorVersion: "1.0.0",
			Versions: contract.NodeVersions{GVMD: strp("26.31.1")}, Feeds: []contract.FeedStatus{},
			Health:       contract.NodeHealth{Status: contract.HealthDown, GVMDUp: false, DiskFreePct: &disk},
			Capabilities: contract.NodeCapabilities{SupportedTypes: contract.SupportedTypes(contract.NodeStandalone),
				StateKinds: KindsOf(contract.NodeStandalone), ReportFormats: []contract.ReportFormatCapability{}},
			Policy: pol, PolicySHA256: contract.PolicySHA256(pol), ReplayFloor: testFloor}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s: node %+v", name, got)
		}
		if c.Errors()[contract.KindNode] == nil {
			t.Errorf("%s: a falha do gvmd não ficou exposta", name)
		}
	}
}

// Uma fonte que falha deixa a saúde do node degradada; quando ela volta, a saúde volta.
func TestNodeDegradadoQuandoOutraFonteFalha(t *testing.T) {
	f := newFakes()
	c := openCollector(t, f.config(t, contract.NodeStandalone))
	c.Collect(context.Background())
	if s := nodeOf(t, c).Health.Status; s != contract.HealthOK {
		t.Fatalf("tudo de pé: %s", s)
	}
	f.gvm.errs[contract.KindTargets] = errFonte
	c.Collect(context.Background())
	if s := nodeOf(t, c).Health.Status; s != contract.HealthDegraded {
		t.Fatalf("targets fora: %s", s)
	}
	delete(f.gvm.errs, contract.KindTargets)
	c.Collect(context.Background())
	if s := nodeOf(t, c).Health.Status; s != contract.HealthOK {
		t.Fatalf("targets de volta: %s", s)
	}
	// down continua down: degradado é só para quem estava ok
	f.gvm.node = func(r NodeRequest) (contract.DataNode, error) {
		d, _ := echoNode(r)
		d.Health = contract.NodeHealth{Status: contract.HealthDown}
		d.Feeds, d.Capabilities.ReportFormats = []contract.FeedStatus{}, []contract.ReportFormatCapability{}
		return d, nil
	}
	f.gvm.errs[contract.KindTargets] = errFonte
	c.Collect(context.Background())
	if s := nodeOf(t, c).Health.Status; s != contract.HealthDown {
		t.Fatalf("gvmd fora: %s", s)
	}
}

// Itens do gvmd fora do schema não saem: um feed ou um formato inválido some, uma versão inválida é omitida.
func TestNodeDescartaPartesInvalidasDoGVM(t *testing.T) {
	f := newFakes()
	f.gvm.node = func(r NodeRequest) (contract.DataNode, error) {
		d, _ := echoNode(r)
		d.Versions.PythonGVM = strp("27 beta")
		d.Feeds = []contract.FeedStatus{
			{Feed: contract.FeedSCAP, Version: "202610100000", AgeHours: 30},
			{Feed: "outro", Version: "1", AgeHours: 1},
			{Feed: contract.FeedCERT, Version: "versão ruim", AgeHours: 1},
			{Feed: contract.FeedGVMDData, Version: "1", AgeHours: -1},
			{Feed: contract.FeedNVT, Version: "202610110600", AgeHours: 6.5, Syncing: true},
		}
		d.Capabilities.ReportFormats = caps(rf("pdf-ruim", contract.LangEN, tech), rf(contract.FormatGVMXML, contract.LangEN),
			rf(contract.FormatGVMXML, contract.LangEN, "edição-ruim"), rf(contract.FormatGVMPDF, contract.LangEN, tech))
		return d, nil
	}
	got := nodeOf(t, collectOnce(t, f, contract.NodeStandalone))
	wantFeeds := []contract.FeedStatus{{Feed: contract.FeedNVT, Version: "202610110600", AgeHours: 6.5, Syncing: true},
		{Feed: contract.FeedSCAP, Version: "202610100000", AgeHours: 30}}
	if got.Versions.PythonGVM != nil || !reflect.DeepEqual(got.Feeds, wantFeeds) ||
		!reflect.DeepEqual(got.Capabilities.ReportFormats, caps(rf(contract.FormatGVMPDF, contract.LangEN, tech))) ||
		got.Health.Status != contract.HealthOK {
		t.Fatalf("node %+v %+v %+v", got.Versions, got.Feeds, got.Capabilities.ReportFormats)
	}
}

// Sem o manifesto da R5, só a edição technical é anunciada; os gvm-* só existem em en + technical (ADR).
func TestNodeReportFormatsSoTechnicalSemManifesto(t *testing.T) {
	f := newFakes()
	f.gvm.node = func(r NodeRequest) (contract.DataNode, error) {
		d, _ := echoNode(r)
		d.Capabilities.ReportFormats = caps(rf(contract.FormatSuricatoosPDF, contract.LangEN, tech, cli, exe),
			rf(contract.FormatSuricatoosPDF, contract.LangPTBR, cli), rf(contract.FormatGVMXML, contract.LangPTBR, tech),
			rf(contract.FormatGVMPDF, contract.LangEN, tech, exe))
		return d, nil
	}
	got := nodeOf(t, collectOnce(t, f, contract.NodeStandalone))
	want := caps(rf(contract.FormatSuricatoosPDF, contract.LangEN, tech), rf(contract.FormatGVMPDF, contract.LangEN, tech))
	if !reflect.DeepEqual(got.Capabilities.ReportFormats, want) {
		t.Fatalf("report_formats %+v", got.Capabilities.ReportFormats)
	}
}

// Com o manifesto, o nó anuncia as combinações dele que o gvmd tem instaladas (as que o fleet_ops viu).
func TestNodeReportFormatsComManifesto(t *testing.T) {
	m, err := ParseManifest([]byte(`{"version":"1","report_formats":[
		{"format":"suricatoos-pdf","lang":"en","variant":"technical","uuid":"` + uuidN(1) + `","name":"a"},
		{"format":"suricatoos-pdf","lang":"en","variant":"client","uuid":"` + uuidN(2) + `","name":"b"},
		{"format":"suricatoos-pdf","lang":"pt_BR","variant":"technical","uuid":"` + uuidN(3) + `","name":"c"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	f := newFakes()
	f.gvm.node = func(r NodeRequest) (contract.DataNode, error) {
		d, _ := echoNode(r)
		d.Capabilities.ReportFormats = caps(rf(contract.FormatSuricatoosPDF, contract.LangPTBR, tech, cli),
			rf(contract.FormatSuricatoosPDF, contract.LangEN, exe, cli, tech), rf(contract.FormatSuricatoosPDF, contract.LangES, tech),
			rf(contract.FormatGVMCSVResults, contract.LangEN, tech))
		return d, nil
	}
	cfg := f.config(t, contract.NodeStandalone)
	cfg.Formats = m
	c := openCollector(t, cfg)
	c.Collect(context.Background())
	want := caps(rf(contract.FormatSuricatoosPDF, contract.LangEN, tech, cli), rf(contract.FormatSuricatoosPDF, contract.LangPTBR, tech),
		rf(contract.FormatGVMCSVResults, contract.LangEN, tech))
	if got := nodeOf(t, c).Capabilities.ReportFormats; !reflect.DeepEqual(got, want) {
		t.Fatalf("report_formats %+v", got)
	}
}

// A ordem dos formatos é a do enum (formato, idioma, edição), grupos repetidos se juntam: mesmos formatos
// instalados, mesmos bytes.
func TestNodeReportFormatsEmOrdemDeterministica(t *testing.T) {
	var hashes []string
	for _, groups := range [][]contract.ReportFormatCapability{
		caps(rf(contract.FormatGVMPDF, contract.LangEN, tech), rf(contract.FormatSuricatoosPDF, contract.LangES, tech),
			rf(contract.FormatSuricatoosPDF, contract.LangEN, tech), rf(contract.FormatGVMXML, contract.LangEN, tech)),
		caps(rf(contract.FormatSuricatoosPDF, contract.LangEN, tech), rf(contract.FormatGVMXML, contract.LangEN, tech),
			rf(contract.FormatSuricatoosPDF, contract.LangES, tech), rf(contract.FormatGVMPDF, contract.LangEN, tech, tech),
			rf(contract.FormatSuricatoosPDF, contract.LangEN, tech)),
	} {
		f := newFakes()
		f.gvm.node = func(r NodeRequest) (contract.DataNode, error) {
			d, _ := echoNode(r)
			d.Capabilities.ReportFormats = groups
			return d, nil
		}
		c := collectOnce(t, f, contract.NodeStandalone)
		want := caps(rf(contract.FormatSuricatoosPDF, contract.LangEN, tech), rf(contract.FormatSuricatoosPDF, contract.LangES, tech),
			rf(contract.FormatGVMXML, contract.LangEN, tech), rf(contract.FormatGVMPDF, contract.LangEN, tech))
		if got := nodeOf(t, c).Capabilities.ReportFormats; !reflect.DeepEqual(got, want) {
			t.Fatalf("report_formats %+v", got)
		}
		s, _ := c.Current(contract.KindNode)
		hashes = append(hashes, s.SHA256)
	}
	if hashes[0] != hashes[1] {
		t.Fatal("mesmos formatos, hashes diferentes")
	}
}

// ReportFormats é o que a linha 8 do verificador compara com um report.export: o capabilities.report_formats do
// node atual; sem node, ou com a parte do gvmd ilegível na última coleta, é erro (unavailable), não lista vazia.
func TestReportFormatsParaOVerificador(t *testing.T) {
	f := newFakes()
	c := openCollector(t, f.config(t, contract.NodeStandalone))
	if _, err := c.ReportFormats(); err == nil {
		t.Fatal("sem node ainda, devia ser erro")
	}
	c.Collect(context.Background())
	got, err := c.ReportFormats()
	if err != nil || !reflect.DeepEqual(got, nodeOf(t, c).Capabilities.ReportFormats) || len(got) == 0 {
		t.Fatalf("ReportFormats = %+v, %v", got, err)
	}
	got[0].Variants[0] = contract.VariantExecutive // cópia
	if again, _ := c.ReportFormats(); again[0].Variants[0] != tech {
		t.Fatal("o chamador alterou o estado")
	}
	f.gvm.errs[contract.KindNode] = errFonte
	c.Collect(context.Background())
	if _, err := c.ReportFormats(); err == nil {
		t.Fatal("com o gvmd ilegível, devia ser erro")
	}
}
