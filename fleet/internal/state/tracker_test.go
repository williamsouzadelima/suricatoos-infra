package state

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/williamsouzadelima/suricatoos-infra/fleet/contract"
	"github.com/williamsouzadelima/suricatoos-infra/fleet/internal/fsutil"
)

var (
	centralKinds = []contract.StateKind{contract.KindNode, contract.KindTasks, contract.KindTargets,
		contract.KindSchedules, contract.KindReports, contract.KindAgents, contract.KindTokens, contract.KindSensors,
		contract.KindScanRequests, contract.KindRemediation, contract.KindScope, contract.KindAuditTail}
	localKinds = []contract.StateKind{contract.KindNode, contract.KindTasks, contract.KindTargets,
		contract.KindSchedules, contract.KindReports, contract.KindScope, contract.KindAuditTail}
)

func TestKindsDeCadaNodeKind(t *testing.T) {
	if got := KindsOf(contract.NodeCentral); !slices.Equal(got, centralKinds) {
		t.Errorf("central: %v", got)
	}
	for _, k := range []contract.NodeKind{contract.NodeStandalone, contract.NodeSensor} {
		if got := KindsOf(k); !slices.Equal(got, localKinds) {
			t.Errorf("%s: %v", k, got)
		}
	}
	if got := KindsOf("hub"); got != nil {
		t.Errorf("node_kind inválido: %v", got)
	}
	// a ordem é a do enum do schema
	enum := schemaAt(t, "fleet-state.schema.json#/$defs/state_kind")["enum"].([]any)
	for i, k := range centralKinds {
		if enum[i] != string(k) {
			t.Errorf("posição %d: schema %v, Go %s", i, enum[i], k)
		}
	}
}

func openTestTracker(t *testing.T, dir string, kinds []contract.StateKind) *tracker {
	t.Helper()
	tr, rec, err := openTracker(dir, kinds)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Lost != nil {
		t.Fatalf("estado perdido inesperado: %v", rec.Lost)
	}
	return tr
}

func snap(t *testing.T, kind contract.StateKind, names ...string) Snapshot {
	t.Helper()
	s, err := encode(kind, tasksData(names...), at)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestPendenteEnviadoSemPendencia(t *testing.T) {
	tr := openTestTracker(t, t.TempDir(), localKinds)
	if p := tr.pending(); len(p) != 0 {
		t.Fatalf("sem retrato nada está pendente: %v", p)
	}
	s := snap(t, contract.KindTasks, "a")
	tr.update(s)
	if p := tr.pending(); !slices.Equal(p, []contract.StateKind{contract.KindTasks}) {
		t.Fatalf("pendentes %v", p)
	}
	cur, ok := tr.snapshot(contract.KindTasks)
	if !ok || !bytes.Equal(cur.Data, s.Data) || cur.SHA256 != s.SHA256 {
		t.Fatalf("retrato atual %+v", cur)
	}
	if err := tr.markSent(contract.KindTasks, s.SHA256); err != nil {
		t.Fatal(err)
	}
	if p := tr.pending(); len(p) != 0 {
		t.Fatalf("depois de enviado: %v", p)
	}
}

func TestSoMudancaVoltaAPendencia(t *testing.T) {
	tr := openTestTracker(t, t.TempDir(), localKinds)
	s := snap(t, contract.KindTasks, "a")
	tr.update(s)
	if err := tr.markSent(contract.KindTasks, s.SHA256); err != nil {
		t.Fatal(err)
	}
	same := s
	same.CollectedAt = at.Add(time.Minute)
	tr.update(same)
	if p := tr.pending(); len(p) != 0 {
		t.Fatalf("mesmo conteúdo numa coleta nova não é mudança: %v", p)
	}
	if cur, _ := tr.snapshot(contract.KindTasks); !cur.CollectedAt.Equal(same.CollectedAt) {
		t.Fatalf("o collected_at acompanha a última coleta: %v", cur.CollectedAt)
	}
	tr.update(snap(t, contract.KindTasks, "b"))
	if p := tr.pending(); !slices.Equal(p, []contract.StateKind{contract.KindTasks}) {
		t.Fatalf("conteúdo novo: %v", p)
	}
}

// O chamador marca o hash que de fato enviou: se uma coleta trouxe outro conteúdo enquanto ele enviava, o kind
// continua pendente.
func TestEnviadoAntigoMantemPendencia(t *testing.T) {
	tr := openTestTracker(t, t.TempDir(), localKinds)
	old := snap(t, contract.KindTasks, "a")
	tr.update(old)
	tr.update(snap(t, contract.KindTasks, "b"))
	if err := tr.markSent(contract.KindTasks, old.SHA256); err != nil {
		t.Fatal(err)
	}
	if p := tr.pending(); !slices.Equal(p, []contract.StateKind{contract.KindTasks}) {
		t.Fatalf("pendentes %v", p)
	}
}

func TestPendentesNaOrdemDoSchema(t *testing.T) {
	tr := openTestTracker(t, t.TempDir(), localKinds)
	for _, k := range []contract.StateKind{contract.KindAuditTail, contract.KindScope, contract.KindNode, contract.KindTasks} {
		tr.update(snap(t, k, "x"))
	}
	want := []contract.StateKind{contract.KindNode, contract.KindTasks, contract.KindScope, contract.KindAuditTail}
	if p := tr.pending(); !slices.Equal(p, want) {
		t.Fatalf("pendentes %v", p)
	}
}

func TestResyncForcaOReenvio(t *testing.T) {
	tr := openTestTracker(t, t.TempDir(), localKinds)
	s := snap(t, contract.KindTasks, "a")
	tr.update(s)
	if err := tr.markSent(contract.KindTasks, s.SHA256); err != nil {
		t.Fatal(err)
	}
	got, err := tr.resync([]contract.StateKind{contract.KindAgents, contract.KindTasks, contract.KindScope,
		contract.KindTasks, "inventado"})
	if err != nil {
		t.Fatal(err)
	}
	// agents não existe num nó standalone e é ignorado; um kind sem retrato ainda é aceito
	if want := []contract.StateKind{contract.KindTasks, contract.KindScope}; !slices.Equal(got, want) {
		t.Fatalf("resync aceitou %v", got)
	}
	if p := tr.pending(); !slices.Equal(p, []contract.StateKind{contract.KindTasks}) {
		t.Fatalf("pendentes %v", p)
	}
	tr.update(snap(t, contract.KindScope, "s"))
	if p := tr.pending(); !slices.Equal(p, []contract.StateKind{contract.KindTasks, contract.KindScope}) {
		t.Fatalf("pendentes %v", p)
	}
}

// Um reinício lê o que o hub já tem e não reenvia o que não mudou; o que mudou, ou o que um resync pediu, vai.
func TestReinicioNaoReenviaSemNecessidade(t *testing.T) {
	dir := t.TempDir()
	tr := openTestTracker(t, dir, localKinds)
	tasks, scope, audit := snap(t, contract.KindTasks, "a"), snap(t, contract.KindScope, "s"), snap(t, contract.KindAuditTail, "x")
	for _, s := range []Snapshot{tasks, scope, audit} {
		tr.update(s)
		if err := tr.markSent(s.Kind, s.SHA256); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := tr.resync([]contract.StateKind{contract.KindAuditTail}); err != nil {
		t.Fatal(err)
	}

	again := openTestTracker(t, dir, localKinds)
	if p := again.pending(); len(p) != 0 { // hashes aceitos lidos do arquivo, mas ainda nenhum retrato
		t.Fatalf("pendente sem retrato depois do reinício: %v", p)
	}
	again.update(tasks)                                  // igual ao enviado
	again.update(snap(t, contract.KindScope, "outro"))   // mudou durante a parada
	again.update(audit)                                  // o resync antes da parada continua valendo
	again.update(snap(t, contract.KindNode, "primeiro")) // nunca enviado
	want := []contract.StateKind{contract.KindNode, contract.KindScope, contract.KindAuditTail}
	if p := again.pending(); !slices.Equal(p, want) {
		t.Fatalf("pendentes depois do reinício %v, esperava %v", p, want)
	}
}

func TestArquivoInutilizavelReenviaTudo(t *testing.T) {
	good := sha([]byte("x"))
	cases := map[string]string{
		"não é JSON":          `{`,
		"versão desconhecida": `{"version":2,"sent":{}}`,
		"membro desconhecido": `{"version":1,"sent":{},"extra":1}`,
		"hash inválido":       `{"version":1,"sent":{"tasks":"abc"}}`,
		"kind inexistente":    `{"version":1,"sent":{"inventado":"` + good + `"}}`,
		"chave repetida":      `{"version":1,"sent":{"tasks":"` + good + `","tasks":"` + good + `"}}`,
		"null":                `{"version":1,"sent":null}`,
	}
	for name, content := range cases {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, SentFileName), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		tr, rec, err := openTracker(dir, localKinds)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if rec.Lost == nil {
			t.Errorf("%s: arquivo inutilizável sem Lost", name)
		}
		tr.update(snap(t, contract.KindTasks, "x"))
		if p := tr.pending(); !slices.Equal(p, []contract.StateKind{contract.KindTasks}) {
			t.Errorf("%s: pendentes %v", name, p)
		}
	}
}

func TestArquivoAusenteOuIlegivel(t *testing.T) {
	if _, rec, err := openTracker(t.TempDir(), localKinds); err != nil || rec.Lost != nil {
		t.Fatalf("ausente: %+v, %v", rec, err)
	}
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, SentFileName), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, rec, err := openTracker(dir, localKinds); err != nil || rec.Lost == nil {
		t.Fatalf("diretório no lugar do arquivo: %+v, %v", rec, err)
	}
	if _, _, err := openTracker("", localKinds); err == nil {
		t.Fatal("FLEET_STATE_DIR vazio aceito")
	}
}

// Um kind que este nó não tem (o arquivo de um nó que era central) é só ignorado.
func TestArquivoComKindDeOutroNodeKindEIgnorado(t *testing.T) {
	dir := t.TempDir()
	content := fmt.Sprintf(`{"version":1,"sent":{"agents":%q,"tasks":%q}}`, sha([]byte("a")), sha([]byte("t")))
	if err := os.WriteFile(filepath.Join(dir, SentFileName), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	tr := openTestTracker(t, dir, localKinds)
	if _, ok := tr.sent[contract.KindAgents]; ok || tr.sent[contract.KindTasks] != sha([]byte("t")) {
		t.Fatalf("enviados %v", tr.sent)
	}
}

// A memória é a verdade: o hub aceitou, então o kind não está pendente mesmo que a gravação falhe (inclusive
// ErrNotDurable). O arquivo só fica atrasado — um reinício reenviaria, o lado seguro — e a próxima gravação o
// refaz inteiro.
func TestGravacaoQueFalhaNaoMudaAVerdadeEmMemoria(t *testing.T) {
	dir := t.TempDir()
	tr := openTestTracker(t, dir, localKinds)
	writes := 0
	failing := true
	tr.write = func(path string, data []byte) error {
		writes++
		if failing {
			return fmt.Errorf("%w: disco", fsutil.ErrNotDurable)
		}
		return fsutil.WriteAtomic(path, data)
	}
	tasks := snap(t, contract.KindTasks, "a")
	tr.update(tasks)
	if err := tr.markSent(contract.KindTasks, tasks.SHA256); err == nil {
		t.Fatal("a falha de gravação tem de ser informada")
	}
	if p := tr.pending(); len(p) != 0 {
		t.Fatalf("o hub aceitou: nada pendente, veio %v", p)
	}
	failing = false
	if err := tr.markSent(contract.KindTasks, tasks.SHA256); err != nil { // a mesma marca repetida regrava já
		t.Fatal(err)
	}
	again := openTestTracker(t, dir, localKinds)
	if again.sent[contract.KindTasks] != tasks.SHA256 {
		t.Fatalf("a marca repetida não regravou: %v", again.sent)
	}

	// o flush do fim de cada ciclo refaz o arquivo atrasado
	scope := snap(t, contract.KindScope, "s")
	tr.update(scope)
	failing = true
	if err := tr.markSent(contract.KindScope, scope.SHA256); err == nil {
		t.Fatal("a falha de gravação tem de ser informada")
	}
	failing = false
	if err := tr.flush(); err != nil {
		t.Fatal(err)
	}
	again = openTestTracker(t, dir, localKinds)
	if again.sent[contract.KindScope] != scope.SHA256 || again.sent[contract.KindTasks] != tasks.SHA256 {
		t.Fatalf("o flush não gravou: %v", again.sent)
	}
	n := writes
	if err := tr.flush(); err != nil || writes != n {
		t.Fatalf("flush sem pendência gravou de novo (%d gravações)", writes-n)
	}
}

func TestMarcarOMesmoHashNaoRegrava(t *testing.T) {
	tr := openTestTracker(t, t.TempDir(), localKinds)
	writes := 0
	tr.write = func(path string, data []byte) error { writes++; return fsutil.WriteAtomic(path, data) }
	s := snap(t, contract.KindTasks, "a")
	tr.update(s)
	for range 3 {
		if err := tr.markSent(contract.KindTasks, s.SHA256); err != nil {
			t.Fatal(err)
		}
	}
	if writes != 1 {
		t.Fatalf("%d gravações para uma marca", writes)
	}
}

func TestMarkSentRecusaKindOuHashInvalido(t *testing.T) {
	tr := openTestTracker(t, t.TempDir(), localKinds)
	good := sha([]byte("x"))
	for _, c := range []struct {
		kind contract.StateKind
		hash string
	}{{contract.KindAgents, good}, {"inventado", good}, {contract.KindTasks, "abc"}, {contract.KindTasks, ""}} {
		if err := tr.markSent(c.kind, c.hash); err == nil {
			t.Errorf("markSent(%q, %q) aceito", c.kind, c.hash)
		}
	}
}

func TestFalhaDeColetaMantemORetratoEExpoeOErro(t *testing.T) {
	tr := openTestTracker(t, t.TempDir(), localKinds)
	s := snap(t, contract.KindTasks, "a")
	tr.update(s)
	boom := errors.New("fonte fora do ar")
	tr.fail(contract.KindTasks, boom)
	if cur, ok := tr.snapshot(contract.KindTasks); !ok || cur.SHA256 != s.SHA256 {
		t.Fatalf("a falha apagou o retrato: %+v", cur)
	}
	if errs := tr.errors(); !errors.Is(errs[contract.KindTasks], boom) || len(errs) != 1 {
		t.Fatalf("erros %v", errs)
	}
	tr.update(s)
	if errs := tr.errors(); len(errs) != 0 {
		t.Fatalf("uma coleta boa limpa o erro: %v", errs)
	}
	tr.fail(contract.KindScope, boom) // sem retrato nenhum: continua sem
	if _, ok := tr.snapshot(contract.KindScope); ok {
		t.Fatal("retrato inventado")
	}
}

func TestRetratoDevolvidoEUmaCopia(t *testing.T) {
	tr := openTestTracker(t, t.TempDir(), localKinds)
	s := snap(t, contract.KindTasks, "a")
	tr.update(s)
	cur, _ := tr.snapshot(contract.KindTasks)
	cur.Data[0] = 'X'
	if again, _ := tr.snapshot(contract.KindTasks); again.Data[0] != '{' {
		t.Fatal("o chamador alterou a verdade em memória")
	}
}

func TestHashesSaoOsDosRetratosAtuais(t *testing.T) {
	tr := openTestTracker(t, t.TempDir(), localKinds)
	a, b := snap(t, contract.KindTasks, "a"), snap(t, contract.KindScope, "b")
	tr.update(a)
	tr.update(b)
	want := map[contract.StateKind]string{contract.KindTasks: a.SHA256, contract.KindScope: b.SHA256}
	if got := tr.hashes(); !reflect.DeepEqual(got, want) {
		t.Fatalf("hashes %v", got)
	}
}

func TestOpenRemoveTemporariosOrfaos(t *testing.T) {
	dir := t.TempDir()
	orphan := filepath.Join(dir, SentFileName+".tmp-123456")
	other := filepath.Join(dir, "budget.json.tmp-123456")
	for _, p := range []string{orphan, other} {
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	openTestTracker(t, dir, localKinds)
	if _, err := os.Stat(orphan); !os.IsNotExist(err) {
		t.Fatalf("o temporário órfão ficou: %v", err)
	}
	if _, err := os.Stat(other); err != nil {
		t.Fatalf("o temporário de outro arquivo foi removido: %v", err)
	}
}

func TestTrackerConcorrente(t *testing.T) {
	tr := openTestTracker(t, t.TempDir(), localKinds)
	snaps := make([][]Snapshot, 8)
	for i := range snaps {
		for j := range 20 {
			snaps[i] = append(snaps[i], snap(t, contract.KindTasks, fmt.Sprint(i, j)))
		}
	}
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for _, s := range snaps[i] {
				tr.update(s)
				_ = tr.markSent(s.Kind, s.SHA256)
				tr.pending()
				tr.hashes()
				_, _ = tr.resync([]contract.StateKind{contract.KindTasks})
			}
		}()
	}
	wg.Wait()
}
