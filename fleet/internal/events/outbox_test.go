package events

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/williamsouzadelima/suricatoos-infra/fleet/contract"
	"github.com/williamsouzadelima/suricatoos-infra/fleet/internal/fsutil"
)

const testNode = "node-lab-0001"

var errDisco = errors.New("disco fora do ar")

// faults injeta falhas nas chamadas de arquivo da outbox.
type faults struct {
	mu               sync.Mutex
	writeErr         error // a gravação escreve metade da linha e falha
	syncErr          error
	truncateErr      error
	truncateCuts     bool  // o corte acontece, mas devolve erro (o fsync dele falhou)
	streamErr        error // a reescrita falha antes do rename
	streamNotDurable bool  // a reescrita vai ao disco, mas o diretório não se confirma
	syncDirErr       error
	streams          int
}

func (f *faults) set(fn func(f *faults)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn(f)
}

func (f *faults) rewrites() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.streams
}

func (f *faults) ops() fileOps {
	base := defaultOps()
	return fileOps{
		openAppend: func(p string) (appendFile, error) {
			af, err := base.openAppend(p)
			if err != nil {
				return nil, err
			}
			return &faultyFile{appendFile: af, f: f}, nil
		},
		openRead: base.openRead,
		truncate: func(p string, n int64) error {
			f.mu.Lock()
			err, cuts := f.truncateErr, f.truncateCuts
			f.mu.Unlock()
			if err != nil {
				if cuts {
					_ = base.truncate(p, n)
				}
				return err
			}
			return base.truncate(p, n)
		},
		syncDir: func(d string) error {
			f.mu.Lock()
			err := f.syncDirErr
			f.mu.Unlock()
			if err != nil {
				return err
			}
			return base.syncDir(d)
		},
		writeStream: func(p string, fill func(io.Writer) error) error {
			f.mu.Lock()
			f.streams++
			err, notDurable := f.streamErr, f.streamNotDurable
			f.mu.Unlock()
			if err != nil {
				return err
			}
			if err := base.writeStream(p, fill); err != nil {
				return err
			}
			if notDurable {
				return fmt.Errorf("%w: diretório não confirmado", fsutil.ErrNotDurable)
			}
			return nil
		},
	}
}

type faultyFile struct {
	appendFile
	f *faults
}

func (w *faultyFile) Write(p []byte) (int, error) {
	w.f.mu.Lock()
	err := w.f.writeErr
	w.f.mu.Unlock()
	if err != nil {
		n, _ := w.appendFile.Write(p[:len(p)/2]) // metade chega ao arquivo antes da falha
		return n, err
	}
	return w.appendFile.Write(p)
}

func (w *faultyFile) Sync() error {
	w.f.mu.Lock()
	err := w.f.syncErr
	w.f.mu.Unlock()
	if err != nil {
		return err
	}
	return w.appendFile.Sync()
}

// ids gera event_ids previsíveis e distintos.
type ids struct {
	mu sync.Mutex
	n  int
}

func (g *ids) next() string {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.n++
	return fmt.Sprintf("eeeeeeee-%04x-4000-8000-%012x", g.n>>16, g.n&0xffff)
}

// box é uma outbox de teste com o seu diretório, as suas falhas e os seus ids (um reinício reaproveita os três).
type box struct {
	t      *testing.T
	dir    string
	kind   contract.NodeKind
	faults *faults
	ids    *ids
	*Outbox
}

func newBox(t *testing.T) *box {
	t.Helper()
	b := &box{t: t, dir: t.TempDir(), kind: contract.NodeCentral, faults: &faults{}, ids: &ids{}}
	b.open()
	return b
}

func (b *box) open() {
	b.t.Helper()
	o, err := open(Config{StateDir: b.dir, NodeKind: b.kind}, b.faults.ops(), b.ids.next)
	if err != nil {
		b.t.Fatal(err)
	}
	b.Outbox = o
}

// restart abre outra outbox sobre o mesmo diretório, como um reinício do conector (a anterior não segura arquivo).
// Um reinício que não seja de um teste de corrupção exige um boot limpo: nenhum registro recusado nem descartado.
func (b *box) restart() *box {
	b.t.Helper()
	b.open()
	if r := b.Recovery(); r.Corrupt != 0 || r.DiscardedBytes != 0 || r.Unreadable != nil {
		b.t.Fatalf("o boot achou o arquivo estragado: %+v", r)
	}
	return b
}

// restartRaw é o reinício de um teste que estragou o arquivo de propósito.
func (b *box) restartRaw() *box {
	b.t.Helper()
	b.open()
	return b
}

// ev é um evento de tarefa distinto por n.
func ev(n int) pending {
	return pending{typ: contract.EventTaskStatusChanged, tenant: "acme", at: testAt,
		data: contract.DataTaskStatusChanged{TaskID: uuidN(n), From: "Running", To: "Done"}}
}

func evs(from, to int) []pending {
	var out []pending
	for i := from; i <= to; i++ {
		out = append(out, ev(i))
	}
	return out
}

func (b *box) add(ps ...pending) {
	b.t.Helper()
	if err := b.Outbox.add(ps...); err != nil {
		b.t.Fatal(err)
	}
}

// next exige um lote, confere o corpo como o hub conferiria e devolve os task_ids dos eventos, na ordem.
func (b *box) next() (Batch, []string) {
	b.t.Helper()
	bt, ok, err := b.Next(testNode)
	if err != nil || !ok {
		b.t.Fatalf("sem lote: ok %v, erro %v", ok, err)
	}
	return bt, taskIDs(b.t, checkBatch(b.t, bt))
}

// checkBatch confere um corpo de lote como o hub: DecodeStrict do EventBatch, 1–100 eventos, ≤ 1 MiB, cada evento
// válido e com o event_id do lote.
func checkBatch(t *testing.T, bt Batch) []contract.Event {
	t.Helper()
	var batch contract.EventBatch
	if err := contract.DecodeStrict(bt.Body, &batch); err != nil {
		t.Fatalf("corpo do lote fora do contrato: %v", err)
	}
	if batch.SchemaVersion != contract.SchemaVersion || batch.NodeID != testNode {
		t.Fatalf("cabeçalho do lote %q %q", batch.SchemaVersion, batch.NodeID)
	}
	if n := len(batch.Events); n < 1 || n > contract.MaxEventsPerBatch || len(bt.Body) > contract.MaxEventBatchBytes {
		t.Fatalf("lote com %d eventos e %d bytes", n, len(bt.Body))
	}
	if len(bt.IDs) != len(batch.Events) {
		t.Fatalf("%d ids para %d eventos", len(bt.IDs), len(batch.Events))
	}
	again, err := contract.MarshalCompact(batch)
	if err != nil || !bytes.Equal(again, bt.Body) {
		t.Fatalf("o corpo não é a forma compacta do lote")
	}
	for i, e := range batch.Events {
		if e.EventID != bt.IDs[i] {
			t.Fatalf("evento %d: id %s, lote diz %s", i, e.EventID, bt.IDs[i])
		}
		enc, _ := contract.MarshalCompact(e)
		if err := checkEventBytes(enc); err != nil {
			t.Fatalf("evento %d inválido: %v", i, err)
		}
		decodeEventData(t, e)
	}
	return batch.Events
}

func taskIDs(t *testing.T, events []contract.Event) []string {
	t.Helper()
	var out []string
	for _, e := range events {
		d, ok := decodeEventData(t, e).(*contract.DataTaskStatusChanged)
		if !ok {
			t.Fatalf("evento %s não é de tarefa", e.Type)
		}
		out = append(out, d.TaskID)
	}
	return out
}

func idsOf(from, to int) []string {
	var out []string
	for i := from; i <= to; i++ {
		out = append(out, uuidN(i))
	}
	return out
}

func (b *box) delivered(bt Batch) {
	b.t.Helper()
	if err := b.Delivered(bt); err != nil {
		b.t.Fatal(err)
	}
}

func (b *box) empty() {
	b.t.Helper()
	if _, ok, err := b.Next(testNode); ok || err != nil {
		b.t.Fatalf("outbox não está vazia: ok %v, erro %v", ok, err)
	}
	if b.Len() != 0 {
		b.t.Fatalf("Len %d", b.Len())
	}
}

func (b *box) fileSize() int64 {
	b.t.Helper()
	fi, err := os.Stat(filepath.Join(b.dir, FileName))
	if err != nil {
		b.t.Fatal(err)
	}
	return fi.Size()
}

// Um evento só conta como enfileirado depois de gravado: a outbox o tem, o arquivo também, e um reinício o devolve
// com o mesmo event_id e os mesmos bytes.
func TestEventoSoEnfileiradoDepoisDeGravado(t *testing.T) {
	b := newBox(t)
	if r := b.Recovery(); !r.Absent || !r.BaselineLost || r.Events != 0 {
		t.Fatalf("primeiro boot: %+v", r)
	}
	b.add(ev(1))
	if b.Len() != 1 {
		t.Fatalf("Len %d", b.Len())
	}
	first, got := b.next()
	if !slices.Equal(got, idsOf(1, 1)) {
		t.Fatalf("eventos %v", got)
	}
	b.restart()
	if r := b.Recovery(); r.Absent || r.Events != 1 || r.Corrupt != 0 {
		t.Fatalf("reinício: %+v", r)
	}
	again, _ := b.next()
	if !bytes.Equal(again.Body, first.Body) || !slices.Equal(again.IDs, first.IDs) {
		t.Fatal("o reinício mudou o evento enfileirado")
	}
}

// Lotes de no máximo 100 eventos, na ordem em que entraram; cada lote só sai da outbox com o 2xx.
func TestLotesDeAte100NaOrdem(t *testing.T) {
	b := newBox(t)
	b.add(evs(1, 120)...)
	b.add(evs(121, 250)...)
	for _, want := range [][2]int{{1, 100}, {101, 200}, {201, 250}} {
		bt, got := b.next()
		if !slices.Equal(got, idsOf(want[0], want[1])) {
			t.Fatalf("lote %v: %d eventos, de %s a %s", want, len(got), got[0], got[len(got)-1])
		}
		b.delivered(bt)
	}
	b.empty()
}

// O teto de bytes do lote (1 MiB) também corta, sem perder nem reordenar evento; com os maiores eventos válidos, o
// teto de 100 eventos é o que corta primeiro.
func TestLoteRespeitaOTetoDeBytes(t *testing.T) {
	b := newBox(t)
	b.batchLimit = 2000
	b.add(evs(1, 40)...)
	var all []string
	for b.Len() > 0 {
		bt, got := b.next()
		if len(bt.Body) > 2000 {
			t.Fatalf("lote de %d bytes acima do teto", len(bt.Body))
		}
		if len(got) >= 40 {
			t.Fatal("o teto de bytes não cortou")
		}
		all = append(all, got...)
		b.delivered(bt)
	}
	if !slices.Equal(all, idsOf(1, 40)) {
		t.Fatalf("eventos perdidos ou fora de ordem: %v", all)
	}

	// o maior evento válido: rejeição com detalhe de 512 runas de 4 bytes e o maior tenant
	big := pending{typ: contract.EventCommandRejectedByPolicy, tenant: strings.Repeat("t", 64), at: testAt,
		data: contract.DataCommandRejected{CommandID: uuidN(1),
			Type:   contract.CommandType("a." + strings.Repeat("b", 62)),
			Reason: contract.ReasonUnsupportedReportVariant, Detail: strp(strings.Repeat("\U0001F600", 512))}}
	_, enc, err := build(uuidN(1), big)
	if err != nil {
		t.Fatal(err)
	}
	if len(enc)*contract.MaxEventsPerBatch+200 > contract.MaxEventBatchBytes || len(enc) > maxEventBytes {
		t.Fatalf("o maior evento válido tem %d bytes: 100 não cabem em 1 MiB", len(enc))
	}
	c := newBox(t)
	var many []pending
	for range 150 {
		many = append(many, big)
	}
	c.add(many...)
	bt, ok, err := c.Next(testNode)
	if err != nil || !ok || len(bt.IDs) != contract.MaxEventsPerBatch {
		t.Fatalf("lote de eventos máximos: %d eventos, %v", len(bt.IDs), err)
	}
	checkBatch(t, bt)
}

// Um lote que dá exatamente o teto de bytes cabe; com um byte a menos de teto, o último evento fica para o próximo.
func TestLoteNaBordaExataDoTetoDeBytes(t *testing.T) {
	b := newBox(t)
	b.add(evs(1, 5)...)
	whole, _ := b.next()
	b.batchLimit = len(whole.Body)
	if bt, _ := b.next(); len(bt.IDs) != 5 {
		t.Fatalf("no teto exato: %d eventos", len(bt.IDs))
	}
	b.batchLimit = len(whole.Body) - 1
	if bt, _ := b.next(); len(bt.IDs) != 4 {
		t.Fatalf("um byte abaixo do teto: %d eventos", len(bt.IDs))
	}
}

// Cheia, a outbox descarta os mais antigos — inclusive os de um lote a caminho — e conta em Dropped; a ordem dos que
// ficam não muda, e um reinício começa a contagem de novo ("desde o início").
func TestTetoDescartaOsMaisAntigosEConta(t *testing.T) {
	b := newBox(t)
	b.add(evs(1, MaxOutbox)...)
	if b.Len() != MaxOutbox || b.Dropped() != 0 {
		t.Fatalf("Len %d, Dropped %d", b.Len(), b.Dropped())
	}
	b.add(evs(MaxOutbox+1, MaxOutbox+5)...)
	if b.Len() != MaxOutbox || b.Dropped() != 5 {
		t.Fatalf("depois do teto: Len %d, Dropped %d", b.Len(), b.Dropped())
	}
	_, got := b.next()
	if got[0] != uuidN(6) {
		t.Fatalf("o primeiro depois do descarte é %s", got[0])
	}
	b.restart()
	if b.Len() != MaxOutbox || b.Dropped() != 0 {
		t.Fatalf("reinício: Len %d, Dropped %d", b.Len(), b.Dropped())
	}

	// teto pequeno: o lote a caminho perde os seus mais antigos; os que o hub aceitar e já saíram não voltam
	c := newBox(t)
	c.capacity = 4
	c.add(evs(1, 3)...)
	bt, _ := c.next() // 1, 2, 3
	c.add(evs(4, 6)...)
	if c.Dropped() != 2 || c.Len() != 4 {
		t.Fatalf("Dropped %d, Len %d", c.Dropped(), c.Len())
	}
	c.delivered(bt) // o hub aceitou 1–3; 1 e 2 já tinham saído
	_, got = c.next()
	if !slices.Equal(got, idsOf(4, 6)) {
		t.Fatalf("depois do lote: %v", got)
	}
	// um único commit maior que o teto guarda só os mais novos
	d := newBox(t)
	d.capacity = 3
	d.add(evs(1, 5)...)
	if _, got := d.next(); !slices.Equal(got, idsOf(3, 5)) || d.Dropped() != 2 {
		t.Fatalf("commit acima do teto: %v, Dropped %d", got, d.Dropped())
	}
	d.restart()
	if _, got := d.next(); !slices.Equal(got, idsOf(3, 5)) {
		t.Fatalf("reinício depois do commit acima do teto: %v", got)
	}
}

// Sem 2xx, o mesmo lote volta — antes e depois de um reinício —, com os mesmos event_ids e os mesmos bytes.
func TestSemDoisXXOLoteVolta(t *testing.T) {
	b := newBox(t)
	b.add(evs(1, 3)...)
	first, _ := b.next()
	again, _ := b.next()
	if !bytes.Equal(first.Body, again.Body) {
		t.Fatal("o lote mudou sem 2xx")
	}
	b.restart()
	after, _ := b.next()
	if !bytes.Equal(first.Body, after.Body) || !slices.Equal(first.IDs, after.IDs) {
		t.Fatal("o reinício mudou o lote não confirmado")
	}
}

// Com 2xx, os eventos somem — inclusive através de um reinício —, e só os do lote: o que entrou enquanto ele ia
// continua.
func TestComDoisXXSomeInclusiveDepoisDeReinicio(t *testing.T) {
	b := newBox(t)
	b.add(evs(1, 150)...)
	bt, _ := b.next()
	b.add(evs(151, 152)...)
	b.delivered(bt)
	if b.Len() != 52 {
		t.Fatalf("Len %d", b.Len())
	}
	b.restart()
	if b.Len() != 52 {
		t.Fatalf("reinício: Len %d", b.Len())
	}
	bt, got := b.next()
	if !slices.Equal(got, idsOf(101, 152)) {
		t.Fatalf("depois do reinício: %v", got)
	}
	b.delivered(bt)
	b.delivered(bt) // um 2xx repetido não muda nada
	b.restart()
	b.empty()
}

// Uma gravação que falha (na escrita ou no fsync) não enfileira: a outbox não muda, o arquivo volta ao tamanho de
// antes e o chamador recebe o erro; a próxima gravação funciona e um reinício só vê o que foi confirmado.
func TestGravacaoQueFalhaNaoEnfileira(t *testing.T) {
	for name, fault := range map[string]func(f *faults){
		"escrita": func(f *faults) { f.writeErr = errDisco },
		"fsync":   func(f *faults) { f.syncErr = errDisco },
	} {
		b := newBox(t)
		b.add(ev(1))
		size := b.fileSize()
		b.faults.set(fault)
		if err := b.Outbox.add(ev(2)); err == nil {
			t.Fatalf("%s: a gravação falhou e o evento foi dado como enfileirado", name)
		}
		if b.Len() != 1 || b.fileSize() != size {
			t.Fatalf("%s: Len %d, arquivo de %d bytes (antes %d)", name, b.Len(), b.fileSize(), size)
		}
		b.faults.set(func(f *faults) { f.writeErr, f.syncErr = nil, nil })
		b.add(ev(3))
		b.restart()
		if r := b.Recovery(); r.Corrupt != 0 || r.DiscardedBytes != 0 {
			t.Fatalf("%s: %+v", name, r)
		}
		if _, got := b.next(); !slices.Equal(got, []string{uuidN(1), uuidN(3)}) {
			t.Fatalf("%s: depois do reinício %v", name, got)
		}
	}
}

// Se até o corte de volta falha — não cortou, ou cortou sem confirmar —, nada mais é anexado ao arquivo: a próxima
// gravação o reescreve da memória antes (o tamanho certo não prova que o corte é durável).
func TestCorteQueFalhaReescreveAntes(t *testing.T) {
	for _, cuts := range []bool{false, true} {
		b := newBox(t)
		b.add(ev(1))
		b.faults.set(func(f *faults) { f.writeErr, f.truncateErr, f.truncateCuts = errDisco, errDisco, cuts })
		if err := b.Outbox.add(ev(2)); err == nil {
			t.Fatal("a gravação falhou e o evento foi dado como enfileirado")
		}
		b.faults.set(func(f *faults) { f.writeErr, f.truncateErr = nil, nil })
		before := b.faults.rewrites()
		b.add(ev(3))
		if b.faults.rewrites() != before+1 {
			t.Fatalf("corte que cortou %v: a gravação seguinte não reescreveu o arquivo antes", cuts)
		}
		b.restart()
		if _, got := b.next(); !slices.Equal(got, []string{uuidN(1), uuidN(3)}) {
			t.Fatalf("depois do reinício %v", got)
		}
	}
}

// A reescrita do boot que não pode ser feita deixa a outbox sem entregar nem gravar nada até dar certo: o que o boot
// leu só vale depois de confirmado no disco.
func TestReescritaDoBootQueFalhaSegura(t *testing.T) {
	b := newBox(t)
	b.add(evs(1, 2)...)
	b.faults.set(func(f *faults) { f.streamErr = errDisco })
	b.restart()
	if r := b.Recovery(); r.RewriteErr == nil || r.Events != 2 {
		t.Fatalf("%+v", r)
	}
	if _, _, err := b.Next(testNode); err == nil {
		t.Fatal("entregou o que o boot não confirmou")
	}
	if err := b.Outbox.add(ev(3)); err == nil {
		t.Fatal("gravou sem a reescrita")
	}
	b.faults.set(func(f *faults) { f.streamErr = nil })
	if _, got := b.next(); !slices.Equal(got, idsOf(1, 2)) {
		t.Fatalf("depois da reescrita: %v", got)
	}
	b.add(ev(3))
	if b.Len() != 3 {
		t.Fatalf("Len %d", b.Len())
	}
}

// Uma reescrita no lugar mas com o diretório não confirmado (ErrNotDurable) também segura tudo até o diretório se
// confirmar.
func TestReescritaSemDiretorioConfirmadoSegura(t *testing.T) {
	b := newBox(t)
	b.add(ev(1))
	b.faults.set(func(f *faults) { f.streamNotDurable, f.syncDirErr = true, errDisco })
	b.restart()
	if r := b.Recovery(); r.RewriteErr != nil {
		t.Fatalf("ErrNotDurable não é falha da reescrita: %+v", r)
	}
	if _, _, err := b.Next(testNode); err == nil {
		t.Fatal("entregou com o diretório não confirmado")
	}
	if err := b.Outbox.add(ev(2)); err == nil {
		t.Fatal("gravou com o diretório não confirmado")
	}
	b.faults.set(func(f *faults) { f.streamNotDurable, f.syncDirErr = false, nil })
	if _, got := b.next(); !slices.Equal(got, idsOf(1, 1)) {
		t.Fatalf("depois de confirmar: %v", got)
	}
}

// O 2xx conta na memória na hora; se o arquivo não o registra, um reinício entrega de novo os mesmos eventos (mesmos
// event_ids: o hub deduplica) — até a próxima gravação, que leva a cabeça da outbox.
func TestEntregueComGravacaoQueFalha(t *testing.T) {
	b := newBox(t)
	b.add(evs(1, 3)...)
	bt, _ := b.next()
	b.faults.set(func(f *faults) { f.syncErr = errDisco })
	if err := b.Delivered(bt); err == nil {
		t.Fatal("a gravação do 2xx falhou sem erro")
	}
	if b.Len() != 0 {
		t.Fatalf("o 2xx não contou na memória: Len %d", b.Len())
	}
	b.faults.set(func(f *faults) { f.syncErr = nil })
	b.restart()
	again, _ := b.next()
	if !slices.Equal(again.IDs, bt.IDs) {
		t.Fatalf("a reentrega trocou os event_ids: %v, %v", again.IDs, bt.IDs)
	}
	// agora o 2xx não grava, mas a gravação seguinte leva a cabeça junto
	b.faults.set(func(f *faults) { f.syncErr = errDisco })
	_ = b.Delivered(again)
	b.faults.set(func(f *faults) { f.syncErr = nil })
	b.add(ev(4))
	b.restart()
	if _, got := b.next(); !slices.Equal(got, idsOf(4, 4)) {
		t.Fatalf("a cabeça não foi junto: %v", got)
	}
}

// Lote vazio ou que esta outbox não fez é recusado; node_id inválido não faz lote.
func TestLoteAlheioENodeIDInvalido(t *testing.T) {
	b := newBox(t)
	b.add(ev(1))
	if err := b.Delivered(Batch{}); err == nil {
		t.Fatal("lote vazio aceito")
	}
	if err := b.Delivered(Batch{last: 99}); err == nil {
		t.Fatal("lote alheio aceito")
	}
	for _, id := range []string{"", "No", "Node-1", "node_1", strings.Repeat("a", 65)} {
		if _, _, err := b.Next(id); err == nil {
			t.Errorf("node_id %q fez lote", id)
		}
	}
	if b.Len() != 1 {
		t.Fatal("a outbox mudou")
	}
}

// O arquivo que mudou por fora (outro tamanho) não recebe mais nada: é reescrito da memória e a gravação segue.
func TestArquivoQueMudouPorForaEReescrito(t *testing.T) {
	b := newBox(t)
	b.add(ev(1))
	f, err := os.OpenFile(filepath.Join(b.dir, FileName), os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("lixo de fora\n"); err != nil {
		t.Fatal(err)
	}
	f.Close()
	b.add(ev(2))
	b.restart()
	if r := b.Recovery(); r.Corrupt != 0 {
		t.Fatalf("o lixo ficou no arquivo: %+v", r)
	}
	if _, got := b.next(); !slices.Equal(got, idsOf(1, 2)) {
		t.Fatalf("depois do reinício %v", got)
	}
}

// Um registro final incompleto (queda no meio da gravação) é deixado de fora no boot; o resto vale.
func TestRegistroFinalIncompletoDescartado(t *testing.T) {
	b := newBox(t)
	b.add(evs(1, 2)...)
	f, err := os.OpenFile(filepath.Join(b.dir, FileName), os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(`0badbeef {"k":"tx","events":[`); err != nil {
		t.Fatal(err)
	}
	f.Close()
	b.restartRaw()
	if r := b.Recovery(); r.DiscardedBytes == 0 || r.Corrupt != 0 || r.Events != 2 {
		t.Fatalf("%+v", r)
	}
	b.restart() // o boot reescreveu: o resto não volta
	if r := b.Recovery(); r.DiscardedBytes != 0 {
		t.Fatalf("o registro incompleto ficou no arquivo: %+v", r)
	}
}

// Um arquivo sem nenhum registro completo (vazio, ou só com um incompleto) vale como ausente: sem linha de base.
func TestArquivoSemRegistroCompletoValeComoAusente(t *testing.T) {
	for name, content := range map[string]string{"vazio": "", "só incompleto": `0badbeef {"k":"he`} {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, FileName), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		o, err := Open(Config{StateDir: dir, NodeKind: contract.NodeStandalone})
		if err != nil {
			t.Fatal(err)
		}
		if r := o.Recovery(); !r.Absent || !r.BaselineLost || r.Corrupt != 0 {
			t.Fatalf("%s: %+v", name, r)
		}
	}
}

// Um registro com checksum que não confere é corrupção: fica de fora, a linha de base cai, os outros eventos ficam.
func TestRegistroCorrompidoFicaDeFora(t *testing.T) {
	b := newBox(t)
	b.add(ev(1))
	b.add(ev(2))
	b.add(ev(3))
	path := filepath.Join(b.dir, FileName)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.SplitAfter(data, []byte("\n"))
	target := -1
	for i, l := range lines {
		if bytes.Contains(l, []byte(uuidN(2))) {
			target = i
		}
	}
	if target < 0 {
		t.Fatal("registro do evento 2 não achado")
	}
	lines[target] = bytes.Replace(lines[target], []byte(`"Running"`), []byte(`"Runnung"`), 1)
	if err := os.WriteFile(path, bytes.Join(lines, nil), 0o600); err != nil {
		t.Fatal(err)
	}
	b.restartRaw()
	if r := b.Recovery(); r.Corrupt != 1 || !r.BaselineLost || r.FirstCorrupt == "" || r.Events != 2 {
		t.Fatalf("%+v", r)
	}
	if _, got := b.next(); !slices.Equal(got, []string{uuidN(1), uuidN(3)}) {
		t.Fatalf("eventos %v", got)
	}
}

// Uma linha com checksum certo mas que quebra as regras — evento fora do schema, seq que não avança, done abaixo da
// cabeça, cabeçalho fora do lugar, tipo desconhecido — é corrupção: fica de fora inteira, e os outros registros valem.
func TestRegistroComRegrasQuebradasFicaDeFora(t *testing.T) {
	_, valid, err := build(uuidN(50), ev(50))
	if err != nil {
		t.Fatal(err)
	}
	invalid := []byte(strings.Replace(string(valid), `"to":"Done"`, `"to":"Done1"`, 1))
	for name, rec := range map[string]record{
		"evento fora do schema": {K: kindTx, Events: []stored{{Seq: 9, Event: invalid}}},
		"seq que não avança":    {K: kindTx, Events: []stored{{Seq: 3, Event: valid}}},
		"done abaixo da cabeça": {K: kindTx, Done: 1},
		"cabeçalho no meio":     {K: kindHead, Version: fileVersion},
		"tipo desconhecido":     {K: "ack"},
	} {
		b := newBox(t)
		b.add(evs(1, 3)...)
		bt, _ := b.next()
		b.delivered(Batch{last: 2, IDs: bt.IDs[:2]}) // a cabeça em 2: fica o evento 3
		line, err := encodeLine(rec)
		if err != nil {
			t.Fatal(err)
		}
		f, err := os.OpenFile(filepath.Join(b.dir, FileName), os.O_APPEND|os.O_WRONLY, 0)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.Write(line); err != nil {
			t.Fatal(err)
		}
		f.Close()
		b.restartRaw()
		if r := b.Recovery(); r.Corrupt != 1 || r.Events != 1 {
			t.Fatalf("%s: %+v", name, r)
		}
		if _, got := b.next(); !slices.Equal(got, idsOf(3, 3)) {
			t.Fatalf("%s: eventos %v", name, got)
		}
	}
}

// O arquivo é compactado quando cresce além do dobro do que a última reescrita gravou (mais a folga), sem perder nada.
func TestCompactaSemPerder(t *testing.T) {
	b := newBox(t)
	b.compactSlack = 4 << 10
	before := b.faults.rewrites()
	for i := 1; i <= 60; i++ {
		b.add(ev(i))
		if i%2 == 0 {
			bt, _ := b.next()
			b.delivered(bt)
		}
	}
	if b.faults.rewrites() == before {
		t.Fatal("não compactou")
	}
	if b.fileSize() > 2*b.baseSize+b.compactSlack+4<<10 {
		t.Fatalf("arquivo de %d bytes", b.fileSize())
	}
	b.restart()
	if b.Len() != 0 {
		t.Fatalf("Len %d", b.Len())
	}
	b.add(ev(61))
	if _, got := b.next(); !slices.Equal(got, idsOf(61, 61)) {
		t.Fatalf("depois da compactação %v", got)
	}
}
