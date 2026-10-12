package state

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/williamsouzadelima/suricatoos-infra/fleet/contract"
)

var at = time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)

func tasksData(names ...string) contract.DataTasks {
	d := contract.DataTasks{Items: []contract.TaskItem{}}
	for i, n := range names {
		d.Items = append(d.Items, contract.TaskItem{TaskID: uuidN(i + 1), Tenant: "acme", Name: n, Status: "Done"})
	}
	return d
}

func TestEncodeSaoOsBytesCompactosEOHashDeles(t *testing.T) {
	v := tasksData("Varredura semanal")
	s, err := encode(contract.KindTasks, v, at)
	if err != nil {
		t.Fatal(err)
	}
	want, err := contract.MarshalCompact(v)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(s.Data, want) || s.SHA256 != sha(want) || s.Kind != contract.KindTasks || !s.CollectedAt.Equal(at) {
		t.Fatalf("encode = %+v", s)
	}
	decodeData(t, contract.KindTasks, s.Data)
}

func TestMesmoEstadoMesmosBytesEMesmoHash(t *testing.T) {
	a, err := encode(contract.KindTasks, tasksData("a", "b"), at)
	if err != nil {
		t.Fatal(err)
	}
	b, err := encode(contract.KindTasks, tasksData("a", "b"), at.Add(time.Hour)) // collected_at fica fora do data
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a.Data, b.Data) || a.SHA256 != b.SHA256 {
		t.Fatalf("mesmo estado, bytes diferentes:\n%s\n%s", a.Data, b.Data)
	}
	c, err := encode(contract.KindTasks, tasksData("a", "c"), at)
	if err != nil {
		t.Fatal(err)
	}
	if c.SHA256 == a.SHA256 {
		t.Fatal("estado diferente, mesmo hash")
	}
}

// O data vai dentro do corpo byte a byte: o content_sha256 confere com o trecho cru, mesmo com <, >, &, U+2028,
// U+2029, aspas, barra invertida e acentos nos nomes (nenhum re-codificador toca o data depois do hash).
func TestBodyEmbuteODataSemRecodificar(t *testing.T) {
	ls, ps := string(rune(0x2028)), string(rune(0x2029))
	v := tasksData(`<script>&"x"\`+ls+ps+"ção", "outra")
	s, err := encode(contract.KindTasks, v, at)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(s.Data, []byte(ls)) || bytes.Contains(s.Data, []byte("\\"+"u2028")) || bytes.Contains(s.Data, []byte("\\"+"u003c")) {
		t.Fatalf("o data escapou o que devia ir literal: %s", s.Data)
	}
	body, err := s.Body("node-lab-0001")
	if err != nil {
		t.Fatal(err)
	}
	var snap contract.StateSnapshot
	if err := contract.DecodeStrict(body, &snap); err != nil {
		t.Fatal(err)
	}
	if snap.SchemaVersion != "1.0.0" || snap.NodeID != "node-lab-0001" || snap.Kind != contract.KindTasks ||
		snap.CollectedAt != "2026-10-11T12:00:00Z" || snap.ContentSHA256 != s.SHA256 {
		t.Fatalf("corpo %s", body)
	}
	if !bytes.Equal(snap.Data, s.Data) || sha(snap.Data) != snap.ContentSHA256 {
		t.Fatalf("o data do corpo não é o hasheado:\n%s\n%s", snap.Data, s.Data)
	}
	if !bytes.Contains(body, append([]byte(`"data":`), s.Data...)) {
		t.Fatal("o trecho cru do data no corpo não é o hasheado")
	}
}

func TestBodyRecusaNodeIDInvalido(t *testing.T) {
	s, err := encode(contract.KindTasks, tasksData("a"), at)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"", "No", "node_lab", strings.Repeat("a", 65), "node-lab\n"} {
		if _, err := s.Body(id); err == nil {
			t.Errorf("node_id %q aceito", id)
		}
	}
}

// O corpo de um data no teto ainda cabe nos 16 MiB do PUT, com o maior node_id e o maior kind.
func TestBodyDeDataNoTetoCabeNoLimite(t *testing.T) {
	padded := func(n int) []byte { // um objeto JSON compacto de exatamente n bytes
		return []byte(`{"x":"` + strings.Repeat("a", n-len(`{"x":""}`)) + `"}`)
	}
	data := padded(maxDataBytes)
	s := Snapshot{Kind: contract.KindScanRequests, Data: data, SHA256: sha(data), CollectedAt: at}
	body, err := s.Body("node-" + strings.Repeat("a", 59))
	if err != nil {
		t.Fatal(err)
	}
	if len(body) > contract.MaxStateBytes {
		t.Fatalf("corpo de %d bytes", len(body))
	}
	big := padded(contract.MaxStateBytes) // o corpo passaria dos 16 MiB
	s = Snapshot{Kind: contract.KindScanRequests, Data: big, SHA256: sha(big), CollectedAt: at}
	if _, err := s.Body("node-lab-0001"); err == nil {
		t.Fatal("corpo acima do teto")
	}
}

// Body confere o que vai no corpo: um data que não é objeto JSON, ou cujo hash não é o do retrato, nunca sai.
func TestBodyRecusaRetratoIncoerente(t *testing.T) {
	s, err := encode(contract.KindTasks, tasksData("a"), at)
	if err != nil {
		t.Fatal(err)
	}
	bad := s
	bad.Data = bytes.Clone(s.Data)
	bad.Data[len(bad.Data)-2] = '1' // outro conteúdo, mesmo hash
	if _, err := bad.Body("node-lab-0001"); err == nil {
		t.Fatal("data que não confere com o hash virou corpo")
	}
	for _, data := range [][]byte{nil, []byte(`[]`), []byte(`{`), []byte(`{"a":1} `)} {
		bad = Snapshot{Kind: contract.KindTasks, Data: data, SHA256: sha(data), CollectedAt: at}
		if _, err := bad.Body("node-lab-0001"); err == nil {
			t.Errorf("data %q virou corpo", data)
		}
	}
}
