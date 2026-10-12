package policy

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/williamsouzadelima/suricatoos-infra/fleet/contract"
)

var allKinds = []contract.NodeKind{contract.NodeCentral, contract.NodeStandalone, contract.NodeSensor}

// writePolicy writes FLEET_STATE_DIR/policy.json under a fresh state dir and returns the dir.
func writePolicy(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, FileName), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestCarregarArquivoAusenteDevolvePadraoPorNodeKind(t *testing.T) {
	for _, k := range allKinds {
		snap, err := Load(t.TempDir(), k)
		if err != nil {
			t.Fatalf("%s: %v", k, err)
		}
		def := contract.DefaultPolicy(k)
		if snap.FromFile {
			t.Errorf("%s: sem arquivo, FromFile deveria ser false", k)
		}
		if !slices.Equal(snap.Policy.Allow, def.Allow) || snap.Policy.SensitivePerHour != 30 || snap.Policy.TotalPerHour != 120 {
			t.Errorf("%s: política %+v, esperava o padrão %+v", k, snap.Policy, def)
		}
		if snap.SHA256 != contract.PolicySHA256(def) {
			t.Errorf("%s: sha256 %s != do padrão %s", k, snap.SHA256, contract.PolicySHA256(def))
		}
	}
	// o padrão depende do node_kind: agent.scan_now só no central
	central, _ := Load(t.TempDir(), contract.NodeCentral)
	sensor, _ := Load(t.TempDir(), contract.NodeSensor)
	if !slices.Contains(central.Policy.Allow, contract.TypeAgentScanNow) || slices.Contains(sensor.Policy.Allow, contract.TypeAgentScanNow) {
		t.Error("o padrão deveria seguir o node_kind")
	}
}

func TestCarregarNuncaEscreve(t *testing.T) {
	// o conector nunca escreve policy.json: só o operador local o cria e o edita
	empty := t.TempDir()
	if _, err := Load(empty, contract.NodeCentral); err != nil {
		t.Fatal(err)
	}
	if entries, err := os.ReadDir(empty); err != nil || len(entries) != 0 {
		t.Fatalf("sem policy.json, Load não cria nada (nem o padrão): %v %v", entries, err)
	}

	content := `{"allow":["state.resync"],"sensitive_per_hour":5,"total_per_hour":50}`
	dir := writePolicy(t, content)
	path := filepath.Join(dir, FileName)
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Load(dir, contract.NodeCentral); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(path)
	if string(got) != content || !after.ModTime().Equal(before.ModTime()) {
		t.Fatal("Load não pode mexer no arquivo do operador")
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Fatalf("Load não deixa arquivo ao lado do policy.json: %v", entries)
	}
}

func TestCarregarArquivoValido(t *testing.T) {
	dir := writePolicy(t, `{"allow":["state.resync","task.start","task.create"],"sensitive_per_hour":5,"total_per_hour":50}`)
	snap, err := Load(dir, contract.NodeCentral)
	if err != nil {
		t.Fatal(err)
	}
	want := contract.Policy{
		Allow:            []contract.CommandType{contract.TypeStateResync, contract.TypeTaskStart, contract.TypeTaskCreate},
		SensitivePerHour: 5,
		TotalPerHour:     50,
	}
	if !snap.FromFile || !slices.Equal(snap.Policy.Allow, want.Allow) || snap.Policy.SensitivePerHour != 5 || snap.Policy.TotalPerHour != 50 {
		t.Fatalf("política %+v (FromFile=%v), esperava %+v", snap.Policy, snap.FromFile, want)
	}
	if snap.SHA256 != contract.PolicySHA256(want) {
		t.Errorf("sha256 %s != %s", snap.SHA256, contract.PolicySHA256(want))
	}
}

func TestArquivoNaoPrecisaSerCompactoNemOrdenado(t *testing.T) {
	a := writePolicy(t, "{\n  \"total_per_hour\": 50,\n  \"allow\": [\"task.start\", \"state.resync\"],\n  \"sensitive_per_hour\": 5\n}\n")
	b := writePolicy(t, `{"allow":["state.resync","task.start"],"sensitive_per_hour":5,"total_per_hour":50}`)
	sa, err := Load(a, contract.NodeCentral)
	if err != nil {
		t.Fatal(err)
	}
	sb, err := Load(b, contract.NodeCentral)
	if err != nil {
		t.Fatal(err)
	}
	if sa.SHA256 != sb.SHA256 {
		t.Fatal("a ordem dos membros e de allow não pode mudar o policy_sha256")
	}
}

func TestTipoNaoSuportadoPeloNodeKindEAceitoNoArquivo(t *testing.T) {
	// a linha 7 devolve unsupported antes de type_not_allowed: o arquivo pode listar o tipo mesmo assim
	dir := writePolicy(t, `{"allow":["agent.scan_now","feed.sync_now"],"sensitive_per_hour":30,"total_per_hour":120}`)
	snap, err := Load(dir, contract.NodeSensor)
	if err != nil {
		t.Fatalf("agent.scan_now é do catálogo; o node_kind não pode invalidar o arquivo: %v", err)
	}
	if !slices.Contains(snap.Policy.Allow, contract.TypeAgentScanNow) {
		t.Fatal("o tipo deveria ficar em allow")
	}
}

func TestAllowVazioEValido(t *testing.T) {
	snap, err := Load(writePolicy(t, `{"allow":[],"sensitive_per_hour":0,"total_per_hour":0}`), contract.NodeCentral)
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Policy.Allow) != 0 || !snap.FromFile {
		t.Fatalf("allow vazio: %+v", snap)
	}
}

func TestBordasDasFaixas(t *testing.T) {
	ok := []string{
		`{"allow":[],"sensitive_per_hour":0,"total_per_hour":0}`,
		`{"allow":[],"sensitive_per_hour":1000,"total_per_hour":3600}`,
	}
	for _, c := range ok {
		if _, err := parse([]byte(c)); err != nil {
			t.Errorf("%s: %v", c, err)
		}
	}
	bad := []string{
		`{"allow":[],"sensitive_per_hour":-1,"total_per_hour":0}`,
		`{"allow":[],"sensitive_per_hour":1001,"total_per_hour":0}`,
		`{"allow":[],"sensitive_per_hour":0,"total_per_hour":-1}`,
		`{"allow":[],"sensitive_per_hour":0,"total_per_hour":3601}`,
	}
	for _, c := range bad {
		if _, err := parse([]byte(c)); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: esperava ErrInvalid, deu %v", c, err)
		}
	}
}

func TestArquivoInvalidoEErroNuncaPadrao(t *testing.T) {
	cases := []struct{ name, content string }{
		{"json quebrado", `{"allow":[`},
		{"vazio", ``},
		{"só espaço", " \n\t "},
		{"não é objeto", `[]`},
		{"null", `null`},
		{"dado depois do valor", `{"allow":[],"sensitive_per_hour":1,"total_per_hour":1} {}`},
		{"chave duplicada", `{"allow":[],"allow":["task.start"],"sensitive_per_hour":1,"total_per_hour":1}`},
		{"chave duplicada após escape", `{"allow":[],"` + `\` + `u0061llow":[],"sensitive_per_hour":1,"total_per_hour":1}`},
		{"tipo desconhecido", `{"allow":["task.explode"],"sensitive_per_hour":1,"total_per_hour":1}`},
		{"tipo do formato mas fora do catálogo", `{"allow":["tenant.scope_set"],"sensitive_per_hour":1,"total_per_hour":1}`},
		{"tipo com caixa errada", `{"allow":["Task.Start"],"sensitive_per_hour":1,"total_per_hour":1}`},
		{"item repetido", `{"allow":["task.start","state.resync","task.start"],"sensitive_per_hour":1,"total_per_hour":1}`},
		{"sensível acima da faixa", `{"allow":[],"sensitive_per_hour":1001,"total_per_hour":1}`},
		{"total acima da faixa", `{"allow":[],"sensitive_per_hour":1,"total_per_hour":3601}`},
		{"sensível negativo", `{"allow":[],"sensitive_per_hour":-1,"total_per_hour":1}`},
		{"total negativo", `{"allow":[],"sensitive_per_hour":1,"total_per_hour":-5}`},
		{"campo a mais", `{"allow":[],"sensitive_per_hour":1,"total_per_hour":1,"extra":true}`},
		{"campo com caixa diferente", `{"Allow":[],"sensitive_per_hour":1,"total_per_hour":1}`},
		{"falta allow", `{"sensitive_per_hour":1,"total_per_hour":1}`},
		{"falta sensitive_per_hour", `{"allow":[],"total_per_hour":1}`},
		{"falta total_per_hour", `{"allow":[],"sensitive_per_hour":1}`},
		{"allow nulo", `{"allow":null,"sensitive_per_hour":1,"total_per_hour":1}`},
		{"allow não é array", `{"allow":"task.start","sensitive_per_hour":1,"total_per_hour":1}`},
		{"item de allow não é string", `{"allow":[1],"sensitive_per_hour":1,"total_per_hour":1}`},
		{"item de allow nulo", `{"allow":[null],"sensitive_per_hour":1,"total_per_hour":1}`},
		{"limite em string", `{"allow":[],"sensitive_per_hour":"30","total_per_hour":1}`},
		{"limite com fração", `{"allow":[],"sensitive_per_hour":30.0,"total_per_hour":1}`},
		{"limite com expoente", `{"allow":[],"sensitive_per_hour":3e1,"total_per_hour":1}`},
		{"limite nulo", `{"allow":[],"sensitive_per_hour":null,"total_per_hour":1}`},
		{"limite fora de int64", `{"allow":[],"sensitive_per_hour":99999999999999999999,"total_per_hour":1}`},
		{"BOM", "\xef\xbb\xbf" + `{"allow":[],"sensitive_per_hour":1,"total_per_hour":1}`},
		{"UTF-8 inválido", "{\"allow\":[\"task.\xff\"],\"sensitive_per_hour\":1,\"total_per_hour\":1}"},
		{"surrogate solto", `{"allow":["` + `\` + `ud800"],"sensitive_per_hour":1,"total_per_hour":1}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			snap, err := Load(writePolicy(t, c.content), contract.NodeCentral)
			if err == nil {
				t.Fatalf("arquivo presente e inválido tinha de ser erro, deu %+v", snap)
			}
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("conteúdo inválido deveria satisfazer ErrInvalid: %v", err)
			}
			// nunca a política padrão (nem parte dela) no lugar do arquivo ruim
			if snap.Policy.Allow != nil || snap.SHA256 != "" || snap.FromFile {
				t.Fatalf("em erro o Snapshot tem de vir vazio, veio %+v", snap)
			}
		})
	}
}

func TestArquivoIlegivelEErroNuncaPadrao(t *testing.T) {
	// policy.json existe, mas é um diretório: presente e ilegível
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, FileName), 0o700); err != nil {
		t.Fatal(err)
	}
	snap, err := Load(dir, contract.NodeCentral)
	if err == nil {
		t.Fatalf("policy.json ilegível tinha de ser erro, deu %+v", snap)
	}
	if snap.SHA256 != "" || snap.Policy.Allow != nil {
		t.Fatalf("em erro o Snapshot tem de vir vazio, veio %+v", snap)
	}
}

func TestArquivoGrandeDemaisEErro(t *testing.T) {
	// JSON válido (só espaço no fim): o único defeito é o tamanho
	valid := `{"allow":[],"sensitive_per_hour":1,"total_per_hour":1}`
	if _, err := Load(writePolicy(t, valid+strings.Repeat(" ", maxFileBytes)), contract.NodeCentral); err == nil {
		t.Fatal("arquivo acima do teto deveria ser erro")
	}
	if _, err := Load(writePolicy(t, valid+strings.Repeat(" ", maxFileBytes-len(valid))), contract.NodeCentral); err != nil {
		t.Fatalf("arquivo exatamente no teto deveria ser aceito: %v", err)
	}
}

func TestStateDirVazioEErro(t *testing.T) {
	// "" viraria ./policy.json: o diretório de trabalho nunca é fonte de política
	if _, err := Load("", contract.NodeCentral); err == nil {
		t.Fatal("FLEET_STATE_DIR vazio deveria ser erro")
	}
}

func TestNodeKindInvalidoEErro(t *testing.T) {
	for _, k := range []contract.NodeKind{"", "hub", "Central"} {
		if _, err := Load(t.TempDir(), k); err == nil {
			t.Errorf("node_kind %q deveria ser erro", k)
		}
	}
}

func TestRecargaDetectaMudancaPeloSha(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, FileName)
	first, err := Load(dir, contract.NodeCentral) // sem arquivo: padrão
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{"allow":["state.resync"],"sensitive_per_hour":3,"total_per_hour":9}`), 0o600); err != nil {
		t.Fatal(err)
	}
	second, err := Load(dir, contract.NodeCentral)
	if err != nil {
		t.Fatal(err)
	}
	if second.SHA256 == first.SHA256 || !second.FromFile || second.Policy.TotalPerHour != 9 {
		t.Fatalf("a política nova deveria valer já: %+v", second)
	}
	again, err := Load(dir, contract.NodeCentral)
	if err != nil || again.SHA256 != second.SHA256 {
		t.Fatalf("sem mudança o sha não pode mudar: %v %v", again.SHA256, err)
	}
	if err := os.WriteFile(path, []byte(`{"allow":["state.resync","task.start"],"sensitive_per_hour":3,"total_per_hour":9}`), 0o600); err != nil {
		t.Fatal(err)
	}
	third, err := Load(dir, contract.NodeCentral)
	if err != nil || third.SHA256 == second.SHA256 || !slices.Contains(third.Policy.Allow, contract.TypeTaskStart) {
		t.Fatalf("a edição deveria mudar o sha: %+v %v", third, err)
	}
}

func TestRecargaComArquivoQuebradoNaoMantemAPoliticaAntiga(t *testing.T) {
	// o operador aperta a política com um erro de digitação: a política antiga, mais frouxa, não pode seguir valendo
	dir := writePolicy(t, `{"allow":["state.resync","task.create"],"sensitive_per_hour":3,"total_per_hour":9}`)
	if _, err := Load(dir, contract.NodeCentral); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, FileName), []byte(`{"allow":["state.resync",],"sensitive_per_hour":3,"total_per_hour":9}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if snap, err := Load(dir, contract.NodeCentral); err == nil {
		t.Fatalf("a edição quebrada tinha de ser erro, deu %+v", snap)
	}
	// corrigido o arquivo, volta
	if err := os.WriteFile(filepath.Join(dir, FileName), []byte(`{"allow":["state.resync"],"sensitive_per_hour":3,"total_per_hour":9}`), 0o600); err != nil {
		t.Fatal(err)
	}
	snap, err := Load(dir, contract.NodeCentral)
	if err != nil || slices.Contains(snap.Policy.Allow, contract.TypeTaskCreate) {
		t.Fatalf("depois de corrigir: %+v %v", snap, err)
	}
}

func TestRecargaComArquivoRemovidoVoltaAoPadrao(t *testing.T) {
	dir := writePolicy(t, `{"allow":[],"sensitive_per_hour":0,"total_per_hour":0}`)
	if _, err := Load(dir, contract.NodeCentral); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, FileName)); err != nil {
		t.Fatal(err)
	}
	snap, err := Load(dir, contract.NodeCentral)
	if err != nil || snap.FromFile || snap.SHA256 != contract.PolicySHA256(contract.DefaultPolicy(contract.NodeCentral)) {
		t.Fatalf("sem o arquivo vale o padrão: %+v %v", snap, err)
	}
}

func TestSnapshotsNaoCompartilhamAllow(t *testing.T) {
	a, _ := Load(t.TempDir(), contract.NodeCentral)
	a.Policy.Allow[0] = "x.y"
	b, _ := Load(t.TempDir(), contract.NodeCentral)
	if b.Policy.Allow[0] == "x.y" {
		t.Fatal("o padrão devolvido por uma chamada não pode ser alterado por quem recebeu outra")
	}
}

func TestMissingEAllows(t *testing.T) {
	allow := func(ts ...contract.CommandType) contract.Policy { return contract.Policy{Allow: ts} }
	cases := []struct {
		name       string
		p          contract.Policy
		typ        contract.CommandType
		linksTasks bool
		missing    contract.CommandType // "" = permitido
	}{
		{"tipo em allow", allow(contract.TypeTaskStart), contract.TypeTaskStart, false, ""},
		{"tipo fora de allow", allow(contract.TypeTaskStart), contract.TypeTaskStop, false, contract.TypeTaskStop},
		{"allow vazio", allow(), contract.TypeStateResync, false, contract.TypeStateResync},
		{"tipo fora do catálogo nunca está em allow", allow(contract.TypeTaskStart), "task.explode", false, "task.explode"},
		{"schedule.create sem task_ids só precisa de si", allow(contract.TypeScheduleCreate), contract.TypeScheduleCreate, false, ""},
		{"schedule.create com task_ids e task.modify", allow(contract.TypeScheduleCreate, contract.TypeTaskModify), contract.TypeScheduleCreate, true, ""},
		{"schedule.create com task_ids sem task.modify", allow(contract.TypeScheduleCreate), contract.TypeScheduleCreate, true, contract.TypeTaskModify},
		{"schedule.create com task_ids e sem nenhum dos dois", allow(contract.TypeTaskStart), contract.TypeScheduleCreate, true, contract.TypeScheduleCreate},
		{"task.modify sozinho não libera schedule.create", allow(contract.TypeTaskModify), contract.TypeScheduleCreate, true, contract.TypeScheduleCreate},
		{"a regra do task_ids é só do schedule.create", allow(contract.TypeScheduleModify), contract.TypeScheduleModify, true, ""},
		{"schedule.modify não pede task.modify", allow(contract.TypeScheduleModify), contract.TypeScheduleModify, false, ""},
		{"task.modify não pede mais nada", allow(contract.TypeTaskModify), contract.TypeTaskModify, true, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, miss := Missing(c.p, c.typ, c.linksTasks)
			if miss != (c.missing != "") || got != c.missing {
				t.Fatalf("Missing = (%q, %v), esperava %q", got, miss, c.missing)
			}
			if Allows(c.p, c.typ, c.linksTasks) != (c.missing == "") {
				t.Fatalf("Allows = %v", !(c.missing == ""))
			}
		})
	}
}

// TestFaixasConferemComOSchema: the bounds and the shape validate enforces are the ones of
// fleet-state.schema.json#/$defs/data_node/properties/policy, read from the file.
func TestFaixasConferemComOSchema(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "schema", "fleet-state.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	obj := func(m map[string]any, k string) map[string]any {
		t.Helper()
		v, ok := m[k].(map[string]any)
		if !ok {
			t.Fatalf("o schema não tem o objeto %q", k)
		}
		return v
	}
	node := obj(obj(obj(obj(doc, "$defs"), "data_node"), "properties"), "policy")
	props := obj(node, "properties")

	if node["additionalProperties"] != false {
		t.Error("a política do schema é fechada (additionalProperties: false)")
	}
	var required []string
	for _, r := range node["required"].([]any) {
		required = append(required, r.(string))
	}
	slices.Sort(required)
	if !slices.Equal(required, []string{"allow", "sensitive_per_hour", "total_per_hour"}) {
		t.Errorf("required do schema: %v", required)
	}
	allow := obj(props, "allow")
	if allow["uniqueItems"] != true {
		t.Error("allow do schema não repete item (uniqueItems)")
	}
	if ref := obj(allow, "items")["$ref"]; ref != "fleet-command.schema.json#/$defs/command_type" {
		t.Errorf("itens de allow: %v", ref)
	}
	for name, want := range map[string][2]float64{
		"sensitive_per_hour": {MinPerHour, MaxSensitivePerHour},
		"total_per_hour":     {MinPerHour, MaxTotalPerHour},
	} {
		p := obj(props, name)
		if p["type"] != "integer" || p["minimum"] != want[0] || p["maximum"] != want[1] {
			t.Errorf("%s: schema {type %v, minimum %v, maximum %v}, Go {integer, %v, %v}", name, p["type"], p["minimum"], p["maximum"], want[0], want[1])
		}
	}
}
