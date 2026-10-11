package contract

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func violationOf(t *testing.T, err error) (string, string) {
	t.Helper()
	if err == nil {
		return "", ""
	}
	var v *Violation
	if !errors.As(err, &v) {
		t.Fatalf("erro não é *Violation: %T %v", err, err)
	}
	return v.Keyword, v.Path
}

// esc writes a JSON \u escape of hex (built by concatenation so the source never holds a raw surrogate escape).
func esc(hex string) string { return `\` + "u" + hex }

// TestScanJSON covers the type-agnostic pass of "Codificação JSON": UTF-8 without BOM, exactly one value,
// no duplicate key at any level (after unescaping), bounded depth and, for the command envelope, integers only.
func TestScanJSON(t *testing.T) {
	cases := []struct {
		name     string
		in       string
		intsOnly bool
		keyword  string
		path     string
	}{
		{"objeto simples", `{"a":1}`, false, "", ""},
		{"espaço depois do valor", "{\"a\":1} \r\n\t", false, "", ""},
		{"segundo valor", `{"a":1} {}`, false, "json_syntax", ""},
		{"lixo depois do valor", `{"a":1}x`, false, "json_syntax", ""},
		{"vazio", ``, false, "json_syntax", ""},
		{"só espaço", "  \n", false, "json_syntax", ""},
		{"BOM", "\xef\xbb\xbf{}", false, "json_syntax", ""},
		{"UTF-8 inválido", "{\"a\":\"\xff\"}", false, "json_syntax", ""},
		{"chave duplicada no topo", `{"a":1,"a":2}`, false, "duplicate_key", "/a"},
		{"chave duplicada aninhada", `{"p":{"x":1,"y":[{"k":1,"k":1}]}}`, false, "duplicate_key", "/p/y/0/k"},
		{"duplicata depois de unescape", `{"a":1,"\` + `u0061":2}`, false, "duplicate_key", "/a"},
		{"caixa diferente não é duplicata", `{"a":1,"A":2}`, false, "", ""},
		{"ponteiro escapado", `{"a/b":{"~":1,"~":2}}`, false, "duplicate_key", "/a~1b/~0"},
		{"fração permitida fora do envelope", `{"a":1.5,"b":2e3}`, false, "", ""},
		{"fração no envelope", `{"p":{"n":70.0}}`, true, "integer_lexical", "/p/n"},
		{"expoente no envelope", `{"n":7e1}`, true, "integer_lexical", "/n"},
		{"expoente maiúsculo no envelope", `{"a":[1,1E2]}`, true, "integer_lexical", "/a/1"},
		{"menos zero é inteiro", `{"n":-0}`, true, "", ""},
		{"zero à esquerda", `{"n":01}`, false, "json_syntax", ""},
		{"sem dois-pontos", `{"a" 1}`, false, "json_syntax", ""},
		{"vírgula sobrando", `{"a":1,}`, false, "json_syntax", ""},
		{"controle cru em string", "{\"a\":\"\x01\"}", false, "json_syntax", ""},
		{"profundidade no limite", strings.Repeat("[", maxDepth) + strings.Repeat("]", maxDepth), false, "", ""},
		{"profundidade demais", strings.Repeat("[", maxDepth+1) + strings.Repeat("]", maxDepth+1), false, "json_syntax", ""},
		{"surrogate alto sozinho", `{"a":"x` + esc("d800") + `y"}`, false, "json_syntax", ""},
		{"surrogate baixo sozinho", `{"a":"` + esc("DC00") + `"}`, false, "json_syntax", ""},
		{"par invertido", `{"a":"` + esc("dc00") + esc("d800") + `"}`, false, "json_syntax", ""},
		{"alto seguido de alto e par", `{"a":"` + esc("d800") + esc("d800") + esc("dc00") + `"}`, false, "json_syntax", ""},
		{"alto no fim da string", `{"a":"` + esc("dbff") + `"}`, false, "json_syntax", ""},
		{"surrogate numa chave", `{"` + esc("d800") + `":1}`, false, "json_syntax", ""},
		{"duas chaves de surrogate distintas não viram duplicata", `{"` + esc("d800") + `":1,"` + esc("d801") + `":2}`, false, "json_syntax", ""},
		{"par válido", `{"a":"` + esc("d83d") + esc("DE00") + `"}`, false, "", ""},
		{"escape comum", `{"a":"` + esc("0041") + `\n\"\\"}`, false, "", ""},
		{"barra escapada antes de u", `{"a":"\\` + `ud800"}`, false, "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			kw, path := "", ""
			if v := scanJSON([]byte(c.in), scanOptions{integersOnly: c.intsOnly}); v != nil {
				kw, path = v.Keyword, v.Path
			}
			if kw != c.keyword || (c.keyword != "json_syntax" && path != c.path) {
				t.Fatalf("got (%q, %q), want (%q, %q)", kw, path, c.keyword, c.path)
			}
		})
	}
}

type strictInner struct {
	N int     `json:"n"`
	F float64 `json:"f"`
}

type strictOuter struct {
	S   string            `json:"s"`
	P   *string           `json:"p,omitzero"`
	I   int64             `json:"i"`
	B   bool              `json:"b"`
	L   []string          `json:"l"`
	M   map[string]string `json:"m,omitzero"`
	R   json.RawMessage   `json:"r,omitzero"`
	In  strictInner       `json:"in"`
	Ins []strictInner     `json:"ins,omitzero"`
}

const strictOK = `{"s":"x","i":1,"b":true,"l":["a"],"in":{"n":2,"f":2.5}}`

// TestDecodeStrict covers the typed pass: case-exact member names, no unknown member, every required member,
// no null, JSON types matching the Go types, integers lexically, and json.RawMessage kept byte for byte.
func TestDecodeStrict(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		keyword string
		path    string
	}{
		{"válido", strictOK, "", ""},
		{"membro desconhecido", `{"s":"x","i":1,"b":true,"l":[],"in":{"n":2,"f":0},"x":1}`, "additionalProperties", ""},
		{"caixa diferente", `{"S":"x","i":1,"b":true,"l":[],"in":{"n":2,"f":0}}`, "additionalProperties", ""},
		{"desconhecido aninhado", `{"s":"x","i":1,"b":true,"l":[],"in":{"n":2,"f":0,"g":1}}`, "additionalProperties", "/in"},
		{"obrigatório faltando", `{"s":"x","b":true,"l":[],"in":{"n":2,"f":0}}`, "required", ""},
		{"obrigatório aninhado faltando", `{"s":"x","i":1,"b":true,"l":[],"in":{"f":0}}`, "required", "/in"},
		{"null em obrigatório", `{"s":null,"i":1,"b":true,"l":[],"in":{"n":2,"f":0}}`, "type", "/s"},
		{"null em opcional", `{"s":"x","p":null,"i":1,"b":true,"l":[],"in":{"n":2,"f":0}}`, "type", "/p"},
		{"número em string", `{"s":1,"i":1,"b":true,"l":[],"in":{"n":2,"f":0}}`, "type", "/s"},
		{"string em inteiro", `{"s":"x","i":"1","b":true,"l":[],"in":{"n":2,"f":0}}`, "type", "/i"},
		{"número em booleano", `{"s":"x","i":1,"b":1,"l":[],"in":{"n":2,"f":0}}`, "type", "/b"},
		{"objeto em array", `{"s":"x","i":1,"b":true,"l":{},"in":{"n":2,"f":0}}`, "type", "/l"},
		{"array em objeto", `{"s":"x","i":1,"b":true,"l":[],"in":[]}`, "type", "/in"},
		{"elemento de tipo errado", `{"s":"x","i":1,"b":true,"l":["a",2],"in":{"n":2,"f":0}}`, "type", "/l/1"},
		{"inteiro com fração", `{"s":"x","i":1.0,"b":true,"l":[],"in":{"n":2,"f":0}}`, "integer_lexical", "/i"},
		{"inteiro com expoente", `{"s":"x","i":1,"b":true,"l":[],"in":{"n":2e0,"f":0}}`, "integer_lexical", "/in/n"},
		{"inteiro grande demais", `{"s":"x","i":9223372036854775808,"b":true,"l":[],"in":{"n":2,"f":0}}`, "maximum", "/i"},
		{"inteiro pequeno demais", `{"s":"x","i":-9223372036854775809,"b":true,"l":[],"in":{"n":2,"f":0}}`, "minimum", "/i"},
		{"número aceita fração e expoente", `{"s":"x","i":1,"b":true,"l":[],"in":{"n":2,"f":1.5e2}}`, "", ""},
		{"RawMessage precisa ser objeto", `{"s":"x","i":1,"b":true,"l":[],"r":[1],"in":{"n":2,"f":0}}`, "type", "/r"},
		{"mapa com chaves livres", `{"s":"x","i":1,"b":true,"l":[],"m":{"K":"v","k":"w"},"in":{"n":2,"f":0}}`, "", ""},
		{"valor de mapa tipado", `{"s":"x","i":1,"b":true,"l":[],"m":{"k":1},"in":{"n":2,"f":0}}`, "type", "/m/k"},
		{"topo não é objeto", `[]`, "type", ""},
		{"duplicata vence o tipo", `{"s":"x","s":1}`, "duplicate_key", "/s"},
		{"dado depois do valor", strictOK + ` {}`, "json_syntax", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var v strictOuter
			kw, path := violationOf(t, DecodeStrict([]byte(c.in), &v))
			if kw != c.keyword || (c.keyword != "json_syntax" && path != c.path) {
				t.Fatalf("got (%q, %q), want (%q, %q)", kw, path, c.keyword, c.path)
			}
		})
	}
}

func TestDecodeStrictValues(t *testing.T) {
	in := `{"s":"x","p":"","i":-0,"b":false,"l":[],"r":{ "k" : [1, 2.5] },"in":{"n":2,"f":0},"ins":[]}`
	var v strictOuter
	if err := DecodeStrict([]byte(in), &v); err != nil {
		t.Fatal(err)
	}
	if v.P == nil || *v.P != "" {
		t.Errorf("opcional presente e vazio deve ficar distinto de ausente: %v", v.P)
	}
	if v.Ins == nil || len(v.Ins) != 0 {
		t.Errorf("[] presente deve ser slice vazio não-nil: %#v", v.Ins)
	}
	if v.M != nil {
		t.Errorf("mapa ausente deve ser nil: %#v", v.M)
	}
	if string(v.R) != `{ "k" : [1, 2.5] }` {
		t.Errorf("RawMessage deve guardar os bytes exatos, got %q", v.R)
	}
	if err := DecodeStrict([]byte(strictOK), v); err == nil {
		t.Error("destino que não é ponteiro deve falhar")
	}
}

// TestMarshalCompact: compact, no trailing newline, NO HTML escaping and U+2028/U+2029 literal ('<', '>', '&'
// and the JS line terminators travel as they are, ADR-0011 "Codificação JSON") — on every Go toolchain: on the
// json/v2 core (GOEXPERIMENT=jsonv2, in the baseline of go1.27) encoding/json escapes U+2028 even inside a
// json.RawMessage. A string that holds the six characters backslash-u-2-0-2-8 must keep its escaped backslash.
func TestMarshalCompact(t *testing.T) {
	ls := "\xe2\x80\xa8"
	backslashU := `\` + `u2028`
	v := struct {
		Name string          `json:"name"`
		Text string          `json:"text"`
		Raw  json.RawMessage `json:"raw"`
	}{Name: "Rede <LAB> & DMZ" + ls + "x", Text: backslashU, Raw: json.RawMessage(`{"c":"a` + ls + `b <x>"}`)}
	got, err := MarshalCompact(v)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"name":"Rede <LAB> & DMZ` + ls + `x","text":"\` + backslashU + `","raw":{"c":"a` + ls + `b <x>"}}`
	if string(got) != want {
		t.Fatalf("got  %q\nwant %q", got, want)
	}
	if bytes.HasSuffix(got, []byte("\n")) {
		t.Fatalf("newline final: %q", got)
	}
	var back struct {
		Name, Text string
	}
	if err := json.Unmarshal(got, &back); err != nil || back.Name != v.Name || back.Text != v.Text {
		t.Fatalf("ida e volta: %v %#v", err, back)
	}
}
