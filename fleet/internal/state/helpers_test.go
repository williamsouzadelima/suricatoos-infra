package state

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/williamsouzadelima/suricatoos-infra/fleet/contract"
)

// Valores fictícios dos testes (RFC 5737 / RFC 3849 para endereços, UUIDs inventados).
const (
	uuidTask1   = "11111111-1111-4111-8111-111111111111"
	uuidTask2   = "22222222-2222-4222-8222-222222222222"
	uuidTask3   = "33333333-3333-4333-8333-333333333333"
	uuidTarget1 = "44444444-4444-4444-8444-444444444444"
	uuidTarget2 = "55555555-5555-4555-8555-555555555555"
	uuidSched1  = "66666666-6666-4666-8666-666666666666"
	uuidReport1 = "77777777-7777-4777-8777-777777777777"
	uuidReport2 = "88888888-8888-4888-8888-888888888888"
	uuidConfig  = "99999999-9999-4999-8999-999999999999"
	uuidScanner = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	uuidPorts   = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"

	ical = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nDTSTART:20261011T020000Z\r\nRRULE:FREQ=WEEKLY\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n"
)

func uuidN(n int) string {
	s := strconv.FormatInt(int64(n), 16)
	return "00000000-0000-4000-8000-" + strings.Repeat("0", 12-len(s)) + s
}

// decodeData exige que o data gerado passe no DecodeStrict do tipo do contrato do kind e o devolve decodificado.
func decodeData(t *testing.T, kind contract.StateKind, data []byte) any {
	t.Helper()
	var v any
	switch kind {
	case contract.KindNode:
		v = &contract.DataNode{}
	case contract.KindTasks:
		v = &contract.DataTasks{}
	case contract.KindTargets:
		v = &contract.DataTargets{}
	case contract.KindSchedules:
		v = &contract.DataSchedules{}
	case contract.KindReports:
		v = &contract.DataReports{}
	case contract.KindAgents:
		v = &contract.DataAgents{}
	case contract.KindTokens:
		v = &contract.DataTokens{}
	case contract.KindSensors:
		v = &contract.DataSensors{}
	case contract.KindScanRequests:
		v = &contract.DataScanRequests{}
	case contract.KindRemediation:
		v = &contract.DataRemediation{}
	case contract.KindScope:
		v = &contract.DataScope{}
	case contract.KindAuditTail:
		v = &contract.DataAuditTail{}
	default:
		t.Fatalf("kind %q", kind)
	}
	if err := contract.DecodeStrict(data, v); err != nil {
		t.Fatalf("data de %s não passa no DecodeStrict: %v\n%s", kind, err, short(data))
	}
	again, err := contract.MarshalCompact(v)
	if err != nil {
		t.Fatal(err)
	}
	if string(again) != string(data) { // compacto e na forma que o MarshalCompact produz
		t.Fatalf("data de %s não é a serialização compacta do tipo:\n%s\n%s", kind, short(data), short(again))
	}
	return v
}

func short(b []byte) string {
	if len(b) > 600 {
		return string(b[:600]) + "…"
	}
	return string(b)
}

func sha(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// schemas lê os dois arquivos de schema de que o estado depende.
var schemas = sync.OnceValues(func() (map[string]map[string]any, error) {
	out := map[string]map[string]any{}
	for _, name := range []string{"fleet-command.schema.json", "fleet-state.schema.json"} {
		b, err := os.ReadFile(filepath.Join("..", "..", "..", "schema", name))
		if err != nil {
			return nil, err
		}
		var m map[string]any
		if err := json.Unmarshal(b, &m); err != nil {
			return nil, err
		}
		out[name] = m
	}
	return out, nil
})

// schemaAt resolve "arquivo#/ponteiro/json" num dos schemas.
func schemaAt(t *testing.T, ref string) map[string]any {
	t.Helper()
	all, err := schemas()
	if err != nil {
		t.Fatal(err)
	}
	file, pointer, _ := strings.Cut(ref, "#")
	var cur any = all[file]
	for _, seg := range strings.Split(strings.TrimPrefix(pointer, "/"), "/") {
		m, ok := cur.(map[string]any)
		if !ok {
			t.Fatalf("%s: %q não é objeto", ref, seg)
		}
		cur = m[seg]
	}
	m, ok := cur.(map[string]any)
	if !ok {
		t.Fatalf("%s não existe no schema", ref)
	}
	return m
}
