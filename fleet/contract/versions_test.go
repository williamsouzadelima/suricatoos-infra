package contract

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// TestParseWireVersion: schema_version_wire is MAJOR.MINOR.0, decimal without leading zeros, 1–3 digits.
func TestParseWireVersion(t *testing.T) {
	for in, want := range map[string]Version{"1.0.0": {1, 0}, "0.0.0": {0, 0}, "1.12.0": {1, 12}, "999.999.0": {999, 999}, "2.1.0": {2, 1}} {
		got, err := ParseWireVersion(in)
		if err != nil || got != want {
			t.Errorf("%q: %v %v", in, got, err)
		}
		if got.Wire() != in {
			t.Errorf("%q: Wire %q", in, got.Wire())
		}
	}
	for _, bad := range []string{"01.0.0", "1.00.0", "1.0.1", "1.0", "1000.0.0", "1.0.0\n", "v1.0.0", "", " 1.0.0", "1.0.00", "1.-1.0"} {
		if _, err := ParseWireVersion(bad); !errors.Is(err, ErrVersionMalformed) {
			t.Errorf("%q: %v", bad, err)
		}
	}
	if (Version{1, 2}).String() != "1.2" {
		t.Error("String")
	}
}

// TestSupportedVersions: v1 speaks only 1.0, whose wire form is the SchemaVersion every v1 body carries.
func TestSupportedVersions(t *testing.T) {
	vs := SupportedVersions()
	if len(vs) != 1 || vs[0] != (Version{1, 0}) || vs[0].Wire() != SchemaVersion {
		t.Fatalf("%v", vs)
	}
	if got := Announcement(vs); !slices.Equal(got, []string{"1.0"}) {
		t.Fatalf("anúncio %v", got)
	}
}

// TestParseAnnouncement: schema_versions (MAJOR.MINOR) with exactly the schema's constraints.
func TestParseAnnouncement(t *testing.T) {
	got, err := ParseAnnouncement([]string{"1.0", "1.1", "2.0"})
	if err != nil || !slices.Equal(got, []Version{{1, 0}, {1, 1}, {2, 0}}) {
		t.Fatalf("%v %v", got, err)
	}
	cases := map[string]struct {
		in      []string
		keyword string
	}{
		"vazio":          {[]string{}, "minItems"},
		"nove":           {[]string{"1.0", "1.1", "1.2", "1.3", "1.4", "1.5", "1.6", "1.7", "1.8"}, "maxItems"},
		"repetido":       {[]string{"1.0", "1.0"}, "uniqueItems"},
		"com PATCH":      {[]string{"1.0.0"}, "pattern"},
		"newline":        {[]string{"1.0\n"}, "not"},
		"quatro dígitos": {[]string{"1000.0"}, "pattern"},
	}
	for name, c := range cases {
		_, err := ParseAnnouncement(c.in)
		if kw, _ := violationOf(t, err); kw != c.keyword {
			t.Errorf("%s: %q, esperado %q", name, kw, c.keyword)
		}
	}
	if _, err := ParseAnnouncement(nil); err == nil {
		t.Error("anúncio ausente")
	}
}

// TestHighestCommon: each side speaks the highest version common to the other's latest announcement; none in
// common means blocked_version.
func TestHighestCommon(t *testing.T) {
	v := func(s ...string) []Version {
		out, err := ParseAnnouncement(s)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	cases := []struct {
		name         string
		ours, theirs []Version
		want         Version
		ok           bool
	}{
		{"mesma versão", v("1.0"), v("1.0"), Version{1, 0}, true},
		{"nó novo, hub antigo", v("1.0", "1.1"), v("1.0"), Version{1, 0}, true},
		{"hub novo, nó antigo", v("1.0"), v("1.1", "1.0"), Version{1, 0}, true},
		{"maior comum", v("1.0", "1.1", "2.0"), v("2.0", "1.1"), Version{2, 0}, true},
		{"MINOR comum abaixo de MAJOR novo", v("1.1", "2.0"), v("1.0", "1.1"), Version{1, 1}, true},
		{"nenhuma comum", v("1.0"), v("2.0"), Version{}, false},
		{"hub rebaixado", v("1.0", "1.1"), v("0.9"), Version{}, false},
		{"anúncio vazio", v("1.0"), nil, Version{}, false},
	}
	for _, c := range cases {
		got, ok := HighestCommon(c.ours, c.theirs)
		if got != c.want || ok != c.ok {
			t.Errorf("%s: %v %v, esperado %v %v", c.name, got, ok, c.want, c.ok)
		}
	}
}

// TestPeekSchemaVersion: what the hub reads at the top of every body BEFORE strict validation — absent or
// outside the wire form => malformed (400); in the form but not supported => unsupported (426). Only the top
// member counts: the rest of a body in an unknown version is not judged here.
func TestPeekSchemaVersion(t *testing.T) {
	supported := SupportedVersions()
	cases := []struct {
		name string
		body string
		err  error
	}{
		{"v1", `{"schema_version":"1.0.0","node_id":"node-lab-0001"}`, nil},
		{"v1 no fim do corpo", `{"node_id":"node-lab-0001","x":{"schema_version":"9.9.9"},"schema_version":"1.0.0"}`, nil},
		{"MINOR sem suporte", `{"schema_version":"1.12.0","campo_novo":[1,2,3]}`, ErrVersionUnsupported},
		{"MAJOR novo com outra forma", `{"schema_version":"2.0.0","tudo":"diferente"}`, ErrVersionUnsupported},
		{"zero à esquerda", `{"schema_version":"01.0.0"}`, ErrVersionMalformed},
		{"com PATCH", `{"schema_version":"1.0.1"}`, ErrVersionMalformed},
		{"ausente", `{"node_id":"node-lab-0001"}`, ErrVersionMalformed},
		{"só aninhado", `{"x":{"schema_version":"1.0.0"}}`, ErrVersionMalformed},
		{"não é string", `{"schema_version":1.0}`, ErrVersionMalformed},
		{"duplicado", `{"schema_version":"1.0.0","schema_version":"1.0.0"}`, ErrVersionMalformed},
		{"não é objeto", `["1.0.0"]`, ErrVersionMalformed},
		{"JSON inválido", `{"schema_version":"1.0.0",`, ErrVersionMalformed},
		{"dado depois", `{"schema_version":"1.0.0"} {}`, ErrVersionMalformed},
		{"corpo do 426 (sem versão)", `{"schema_versions":["1.0"]}`, ErrVersionMalformed},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v, err := PeekSchemaVersion([]byte(c.body), supported)
			if !errors.Is(err, c.err) || (err == nil && v != (Version{1, 0})) {
				t.Fatalf("got %v %v, want %v", v, err, c.err)
			}
		})
	}
	// the committed examples: a valid heartbeat is 1.0; the leading-zero one is a 400, never a 426
	read := func(rel string) []byte {
		b, err := os.ReadFile(filepath.Join(examplesDir, filepath.FromSlash(rel)))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	if _, err := PeekSchemaVersion(read("valid/heartbeat/request.json"), supported); err != nil {
		t.Errorf("heartbeat válido: %v", err)
	}
	if _, err := PeekSchemaVersion(read("invalid/heartbeat/heartbeat_request--schema-version-leading-zero.json"), supported); !errors.Is(err, ErrVersionMalformed) {
		t.Errorf("zero à esquerda: %v", err)
	}
	for _, s := range []string{"valid/command/schema_version_wire--unsupported-minor.json"} {
		body := []byte(`{"schema_version":` + strings.TrimSpace(string(read(s))) + `}`)
		if _, err := PeekSchemaVersion(body, supported); !errors.Is(err, ErrVersionUnsupported) {
			t.Errorf("%s: %v", s, err)
		}
	}
}
