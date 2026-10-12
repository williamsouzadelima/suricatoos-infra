package state

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/williamsouzadelima/suricatoos-infra/fleet/contract"
	"github.com/williamsouzadelima/suricatoos-infra/fleet/internal/fleetops"
)

const bridgePassword = "senha-ficticia-do-leitor"

type runCall struct {
	request        string
	user, password string
}

// fakeRunner é o fleetops.Runner do teste: guarda o pedido (compacto, como iria na entrada padrão) e devolve a
// resposta que o teste pôs para o op.
type fakeRunner struct {
	mu    sync.Mutex
	calls []runCall
	out   map[string]fleetops.Result
	err   map[string]error
}

func (f *fakeRunner) Run(_ context.Context, request any, user, password string) (fleetops.Result, error) {
	b, err := contract.MarshalCompact(request)
	if err != nil {
		return fleetops.Result{}, err
	}
	var head struct {
		Op string `json:"op"`
	}
	if err := json.Unmarshal(b, &head); err != nil {
		return fleetops.Result{}, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, runCall{string(b), user, password})
	return f.out[head.Op], f.err[head.Op]
}

func newBridge(t *testing.T, r Runner) (*Bridge, string) {
	t.Helper()
	pw := filepath.Join(t.TempDir(), "gmp.pass")
	if err := os.WriteFile(pw, []byte(bridgePassword+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return &Bridge{Runner: r, User: "fleet-leitor", PasswordFile: pw}, pw
}

func output(s string) fleetops.Result { return fleetops.Result{Output: json.RawMessage(s)} }

// Cada leitura é um state.<kind> do fleet_ops com os donos, como o usuário gvmd atual do nó; a senha vem do
// arquivo, sem a quebra de linha final.
func TestBridgeListaMandaOPedidoDoFleetOps(t *testing.T) {
	r := &fakeRunner{out: map[string]fleetops.Result{
		"state.tasks":     output(`{"items":[],"truncated":false,"unattributed_count":2}`),
		"state.targets":   output(`{"items":[],"truncated":false,"unattributed_count":0}`),
		"state.schedules": output(`{"items":[],"truncated":true,"unattributed_count":0}`),
		"state.reports":   output(`{"items":[],"truncated":false,"unattributed_count":0}`),
	}}
	b, _ := newBridge(t, r)
	owners := map[string]string{"tenant-acme": "acme", "tenant-globex": "globex"}
	ctx := context.Background()
	tasks, err := b.Tasks(ctx, owners)
	if err != nil || tasks.UnattributedCount != 2 || tasks.Items == nil {
		t.Fatalf("Tasks = %+v, %v", tasks, err)
	}
	if _, err := b.Targets(ctx, owners); err != nil {
		t.Fatal(err)
	}
	if s, err := b.Schedules(ctx, nil); err != nil || !s.Truncated {
		t.Fatalf("Schedules = %+v, %v", s, err)
	}
	if _, err := b.Reports(ctx, owners); err != nil {
		t.Fatal(err)
	}
	want := []string{
		`{"op":"state.tasks","command_id":"","owners":{"tenant-acme":"acme","tenant-globex":"globex"},"payload":{}}`,
		`{"op":"state.targets","command_id":"","owners":{"tenant-acme":"acme","tenant-globex":"globex"},"payload":{}}`,
		`{"op":"state.schedules","command_id":"","owners":{},"payload":{}}`, // sem donos: objeto vazio, nunca null
		`{"op":"state.reports","command_id":"","owners":{"tenant-acme":"acme","tenant-globex":"globex"},"payload":{}}`,
	}
	for i, c := range r.calls {
		if c.request != want[i] || c.user != "fleet-leitor" || c.password != bridgePassword {
			t.Errorf("chamada %d: %+v", i, c)
		}
	}
}

func TestBridgeNodeMandaOsMembrosDoConector(t *testing.T) {
	req := NodeRequest{NodeKind: contract.NodeSensor, ConnectorVersion: "1.0.0", Policy: contract.DefaultPolicy(contract.NodeSensor),
		PolicySHA256: contract.PolicySHA256(contract.DefaultPolicy(contract.NodeSensor)), ReplayFloor: testFloor,
		SupportedTypes: contract.SupportedTypes(contract.NodeSensor), StateKinds: KindsOf(contract.NodeSensor),
		Versions: &LocalVersions{GVMD: strp("26.31.1")}}
	node, _ := echoNode(req)
	nodeJSON, err := contract.MarshalCompact(node)
	if err != nil {
		t.Fatal(err)
	}
	r := &fakeRunner{out: map[string]fleetops.Result{"state.node": output(string(nodeJSON))}}
	b, _ := newBridge(t, r)
	got, err := b.Node(context.Background(), req)
	if err != nil || !reflect.DeepEqual(got, node) {
		t.Fatalf("Node = %+v, %v", got, err)
	}
	payload, err := contract.MarshalCompact(req)
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"op":"state.node","command_id":"","payload":` + string(payload) + `}`; r.calls[0].request != want {
		t.Fatalf("pedido %s", r.calls[0].request)
	}
	if strings.Contains(r.calls[0].request, "gmp_protocol") || strings.Contains(r.calls[0].request, "python_gvm") {
		t.Fatal("o conector não manda o que é do gvmd")
	}
}

// A resposta é decodificada estrita pelo tipo do contrato: um membro que o contrato não tem — um comment, um
// hostname, um achado — derruba a leitura; nunca é descartado em silêncio nem chega ao estado.
func TestBridgeDecodificaEstrito(t *testing.T) {
	item := `{"task_id":"` + uuidTask1 + `","tenant":"acme","name":"t","status":"Done","report_count":0`
	cases := map[string]string{
		"comment no item":        `{"items":[` + item + `,"comment":"segredo do cliente"}],"truncated":false,"unattributed_count":0}`,
		"membro extra":           `{"items":[],"truncated":false,"unattributed_count":0,"hosts":["srv01.acme.example"]}`,
		"sem unattributed_count": `{"items":[],"truncated":false}`,
		"null":                   `{"items":null,"truncated":false,"unattributed_count":0}`,
		"inteiro com fração":     `{"items":[],"truncated":false,"unattributed_count":1.0}`,
		"caixa diferente":        `{"Items":[],"truncated":false,"unattributed_count":0}`,
		"chave repetida":         `{"items":[],"items":[],"truncated":false,"unattributed_count":0}`,
	}
	for name, out := range cases {
		r := &fakeRunner{out: map[string]fleetops.Result{"state.tasks": output(out)}}
		b, _ := newBridge(t, r)
		if got, err := b.Tasks(context.Background(), map[string]string{}); err == nil {
			t.Errorf("%s: aceito: %+v", name, got)
		}
	}
	r := &fakeRunner{out: map[string]fleetops.Result{"state.reports": {Output: json.RawMessage(
		`{"items":[],"truncated":false,"unattributed_count":0}`), Artifact: json.RawMessage(`{}`)}}}
	b, _ := newBridge(t, r)
	if _, err := b.Reports(context.Background(), nil); err == nil {
		t.Fatal("resposta de estado com artifact aceita")
	}
}

// Pela coleta inteira: o fleet_ops que devolve comment derruba só o kind dele, que nunca sai com o comment.
func TestCommentDoFleetOpsNuncaChegaAoEstado(t *testing.T) {
	item := `{"task_id":"` + uuidTask1 + `","tenant":"acme","name":"t","status":"Done","report_count":0,"comment":"segredo do cliente"}`
	empty := output(`{"items":[],"truncated":false,"unattributed_count":0}`)
	r := &fakeRunner{out: map[string]fleetops.Result{
		"state.tasks":     output(`{"items":[` + item + `],"truncated":false,"unattributed_count":0}`),
		"state.targets":   empty,
		"state.schedules": empty,
		"state.reports":   empty,
	}, err: map[string]error{"state.node": errFonte}}
	b, _ := newBridge(t, r)
	f := newFakes()
	cfg := f.config(t, contract.NodeStandalone)
	cfg.GVM = b
	c := openCollector(t, cfg)
	c.Collect(context.Background())
	if _, ok := c.Current(contract.KindTasks); ok || c.Errors()[contract.KindTasks] == nil {
		t.Fatal("tasks com comment saiu")
	}
	for _, kind := range c.Kinds() {
		if s, ok := c.Current(kind); ok && strings.Contains(string(s.Data), "segredo") {
			t.Fatalf("%s levou o comment", kind)
		}
	}
	current(t, c, contract.KindTargets)
}

func TestBridgeErroDoFleetOpsPassaAdiante(t *testing.T) {
	r := &fakeRunner{err: map[string]error{"state.targets": &fleetops.Error{Code: contract.ErrorTimeout, Message: "x"}}}
	b, _ := newBridge(t, r)
	_, err := b.Targets(context.Background(), nil)
	var fe *fleetops.Error
	if !errors.As(err, &fe) || fe.Code != contract.ErrorTimeout {
		t.Fatalf("erro %v", err)
	}
}

// A senha é lida a cada chamada: uma troca vale na leitura seguinte. Sem senha (arquivo ausente, vazio ou
// ilegível) ou sem usuário, nada é executado.
func TestBridgeSenhaLidaACadaChamada(t *testing.T) {
	r := &fakeRunner{out: map[string]fleetops.Result{"state.tasks": output(`{"items":[],"truncated":false,"unattributed_count":0}`)}}
	b, pw := newBridge(t, r)
	if _, err := b.Tasks(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pw, []byte("senha-nova-ficticia\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Tasks(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if r.calls[0].password != bridgePassword || r.calls[1].password != "senha-nova-ficticia" {
		t.Fatalf("senhas %q, %q", r.calls[0].password, r.calls[1].password)
	}

	for name, mutate := range map[string]func(*Bridge){
		"arquivo ausente": func(b *Bridge) { b.PasswordFile = filepath.Join(t.TempDir(), "nao-existe") },
		"arquivo vazio": func(b *Bridge) {
			if err := os.WriteFile(b.PasswordFile, []byte("\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"diretório":    func(b *Bridge) { b.PasswordFile = t.TempDir() },
		"sem caminho":  func(b *Bridge) { b.PasswordFile = "" },
		"sem usuário":  func(b *Bridge) { b.User = "" },
		"sem executor": func(b *Bridge) { b.Runner = nil },
	} {
		r := &fakeRunner{}
		b, _ := newBridge(t, r)
		mutate(b)
		if _, err := b.Tasks(context.Background(), nil); err == nil || len(r.calls) != 0 {
			t.Errorf("%s: executou (%d chamadas, %v)", name, len(r.calls), err)
		}
	}
}
