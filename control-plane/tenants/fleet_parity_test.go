package tenants

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The fleet connector (module fleet, ADR-0011) reads TENANTS_FILE on its own, because fleet does not import this
// module. The format is guarded by a fixture shared by both sides: fleet/internal/tenant/testdata/tenants.json
// is read here and by fleet/internal/tenant (parity_test.go), and each side asserts the same view of it. Change
// the format of the file and one of the two suites breaks.
//
// The fixture is also what this package WRITES: TestFixtureEOQueORegistroGrava re-creates it byte for byte
// through Registry.Put, so it cannot drift into a file nobody produces.
var fixturePath = filepath.Join("..", "..", "fleet", "internal", "tenant", "testdata", "tenants.json")

// fixtureView is the view both suites assert: keep it identical to fixtureView in
// fleet/internal/tenant/parity_test.go.
var fixtureView = []struct {
	Name    string
	Enabled bool
	Scope   string
	GmpUser string
}{
	{"acme", true, "192.0.2.0/24, 198.51.100.0/24", "tenant-acme"},
	{"globex", true, "203.0.113.0/24", ""},
	{"initech", false, "192.0.2.0/25 198.51.100.0/25", "tenant-initech"},
	{"umbrella", true, "", "tenant-umbrella"},
}

func TestFixtureDaFrotaTemAMesmaVisao(t *testing.T) {
	r, err := NewRegistry(fixturePath)
	if err != nil {
		t.Fatalf("o fixture compartilhado com a frota tem de ser lido pelo registro: %v", err)
	}
	list := r.List() // por nome, como o fixture
	if len(list) != len(fixtureView) {
		t.Fatalf("o fixture tem %d tenants, a visão espera %d", len(list), len(fixtureView))
	}
	for i, want := range fixtureView {
		got := list[i]
		if got.Name != want.Name || got.Enabled != want.Enabled || got.Scope != want.Scope || got.GmpUser != want.GmpUser {
			t.Errorf("tenant %d: lido %+v, a visão espera %+v", i, got, want)
		}
		// o que o registro responde ao resto do control-plane: habilitado ⇒ conhecido, com escopo e usuário;
		// desabilitado ⇒ deny-all
		if r.Known(want.Name) != want.Enabled {
			t.Errorf("%s: Known = %v, enabled = %v", want.Name, r.Known(want.Name), want.Enabled)
		}
		wantScope, wantUser := want.Scope, want.GmpUser
		if !want.Enabled {
			wantScope, wantUser = "", ""
		}
		if r.ScopeSpec(want.Name) != wantScope || r.GmpUser(want.Name) != wantUser {
			t.Errorf("%s: ScopeSpec %q / GmpUser %q, esperava %q / %q", want.Name, r.ScopeSpec(want.Name), r.GmpUser(want.Name), wantScope, wantUser)
		}
	}
}

func TestFixtureEOQueORegistroGrava(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tenants.json")
	r, err := NewRegistry(path)
	if err != nil {
		t.Fatal(err)
	}
	r.now = func() time.Time { return time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC) }
	// fora de ordem de propósito: o arquivo sai ordenado por nome
	for _, i := range []int{2, 0, 3, 1} {
		v := fixtureView[i]
		if err := r.Put(Record{Name: v.Name, Scope: v.Scope, GmpUser: v.GmpUser, Enabled: v.Enabled}); err != nil {
			t.Fatal(err)
		}
	}
	written, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	fixture, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatal(err)
	}
	// a árvore de trabalho no Windows tem CRLF (core.autocrlf); o conteúdo é o mesmo
	norm := func(b []byte) string {
		return strings.TrimRight(strings.ReplaceAll(string(b), "\r\n", "\n"), "\n")
	}
	if norm(written) != norm(fixture) {
		t.Fatalf("o registro grava um arquivo diferente do fixture da frota; se o formato mudou de propósito, "+
			"atualize o fixture e o leitor em fleet/internal/tenant.\n--- gravado:\n%s\n--- fixture:\n%s", written, fixture)
	}
}
