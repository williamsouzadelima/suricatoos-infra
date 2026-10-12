package replay

import (
	"errors"
	"strings"
	"testing"
)

// Uma linha é "<crc32c em 8 hex minúsculos> <json>\n": ida e volta exata, e qualquer bit trocado na linha — no
// checksum ou no JSON — é detectado.
func TestLinhaIdaEVoltaEChecksum(t *testing.T) {
	r := record{K: kindEntry, At: 1791720000123456789, Canon: strings.Repeat("a", 64), Nonce: strings.Repeat("b", 64),
		Cmd: "6f1c2a9e-3b7d-4c8a-9e21-5d4f0a7b3c18", Type: "task.start", Tenant: "acme", Decision: "accepted",
		Expires: 1792324800}
	line, err := encodeLine(r)
	if err != nil {
		t.Fatal(err)
	}
	if line[8] != ' ' || line[len(line)-1] != '\n' || strings.Count(string(line), "\n") != 1 {
		t.Fatalf("forma da linha: %q", line)
	}
	got, err := decodeLine(line[:len(line)-1])
	if err != nil || got != r {
		t.Fatalf("ida e volta: %+v, %v", got, err)
	}
	for i := range len(line) - 1 {
		flipped := []byte(string(line[:len(line)-1]))
		flipped[i] ^= 0x01
		if _, err := decodeLine(flipped); err == nil {
			t.Fatalf("bit trocado no byte %d passou: %q", i, flipped)
		}
	}
}

// O decode é estrito: membro desconhecido, chave duplicada, caixa diferente, checksum em maiúsculas ou sem o
// espaço, e JSON que não é um registro são recusados — mesmo com o checksum certo.
func TestLinhaEstrita(t *testing.T) {
	cases := map[string]string{
		"membro desconhecido": `{"k":"floor","at":1,"x":1}`,
		"chave duplicada":     `{"k":"floor","at":1,"at":2}`,
		"caixa diferente":     `{"K":"floor","at":1}`,
		"fração":              `{"k":"floor","at":1.5}`,
		"não é objeto":        `["floor"]`,
		"nulo":                `{"k":null}`,
	}
	for name, js := range cases {
		if _, err := decodeLine([]byte(checksum([]byte(js)) + " " + js)); err == nil {
			t.Errorf("%s: aceito", name)
		}
	}
	js := `{"k":"floor","at":1}`
	for name, line := range map[string]string{
		"sem espaço": checksum([]byte(js)) + js,
		"curta":      "0000",
		"vazia":      "",
	} {
		if _, err := decodeLine([]byte(line)); err == nil {
			t.Errorf("%s: aceito", name)
		}
	}
	if _, err := decodeLine([]byte(checksum([]byte(js)) + " " + js)); err != nil {
		t.Fatalf("a linha válida foi recusada: %v", err)
	}
	// o checksum é hexadecimal MINÚSCULO, com exatamente 8 dígitos
	for in, ok := range map[string]bool{"0000000a": true, "deadbeef": true, "0000000A": false, "DEADBEEF": false,
		"0000000g": false, "000000a": false, "+000000a": false, " 000000a": false} {
		if _, valid := parseChecksum([]byte(in)); valid != ok {
			t.Errorf("parseChecksum(%q) = %v, esperava %v", in, valid, ok)
		}
	}
}

// Um registro acima do teto de uma linha é erro do chamador: nada é gravado.
func TestLinhaAcimaDoTetoEErro(t *testing.T) {
	r := record{K: kindResult, Canon: strings.Repeat("a", 64), At: 1, Result: &wireResult{
		Status: "succeeded", StartedAt: "2026-10-11T12:00:00Z", FinishedAt: "2026-10-11T12:00:01Z",
		Output: []byte(`{"x":"` + strings.Repeat("y", maxLineBytes) + `"}`),
	}}
	if _, err := encodeLine(r); !errors.Is(err, ErrInvalid) {
		t.Fatalf("esperava ErrInvalid, deu %v", err)
	}
}
