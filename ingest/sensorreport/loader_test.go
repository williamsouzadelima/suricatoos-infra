package sensorreport

import (
	"os"
	"path/filepath"
	"testing"
)

func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestFileResolverHappyPath(t *testing.T) {
	dir := t.TempDir()
	tenants := writeFile(t, dir, "tenants.json",
		`[{"name":"acme","scope":"10.20.0.0/16","gmp_user":"tenant-acme","enabled":true}]`)
	secrets := writeFile(t, dir, "secrets.json", `{"acme":"pw-acme"}`)
	r := NewFileResolver(tenants, secrets)

	tc, ok := r.Resolve("acme")
	if !ok {
		t.Fatal("acme deveria resolver")
	}
	if tc.GmpUsername != "tenant-acme" || tc.GmpPassword != "pw-acme" {
		t.Fatalf("config errada: %+v", tc)
	}
	if !tc.Scope.ContainsIP("10.20.5.5") || tc.Scope.ContainsIP("8.8.8.8") {
		t.Fatal("escopo carregado errado")
	}
}

func TestFileResolverDenies(t *testing.T) {
	dir := t.TempDir()
	tenants := writeFile(t, dir, "tenants.json", `[
		{"name":"acme","scope":"10.20.0.0/16","gmp_user":"tenant-acme","enabled":true},
		{"name":"disabled","scope":"10.30.0.0/16","gmp_user":"tenant-d","enabled":false},
		{"name":"noscope","scope":"","gmp_user":"tenant-n","enabled":true},
		{"name":"nopw","scope":"10.40.0.0/16","gmp_user":"tenant-np","enabled":true}
	]`)
	secrets := writeFile(t, dir, "secrets.json", `{"acme":"pw","disabled":"pw","noscope":"pw"}`)
	r := NewFileResolver(tenants, secrets)

	if _, ok := r.Resolve("unknown"); ok {
		t.Error("tenant desconhecido não deveria resolver")
	}
	if _, ok := r.Resolve("disabled"); ok {
		t.Error("tenant desabilitado não deveria resolver")
	}
	if _, ok := r.Resolve("noscope"); ok {
		t.Error("tenant sem escopo não deveria resolver (nunca import ilimitado)")
	}
	if _, ok := r.Resolve("nopw"); ok {
		t.Error("tenant sem senha não deveria resolver")
	}
	if _, ok := r.Resolve("acme"); !ok {
		t.Error("acme válido deveria resolver")
	}
}

func TestFileResolverFreshRead(t *testing.T) {
	dir := t.TempDir()
	tenants := writeFile(t, dir, "tenants.json",
		`[{"name":"acme","scope":"10.20.0.0/16","gmp_user":"tenant-acme","enabled":true}]`)
	secrets := writeFile(t, dir, "secrets.json", `{"acme":"pw"}`)
	r := NewFileResolver(tenants, secrets)
	if _, ok := r.Resolve("acme"); !ok {
		t.Fatal("acme deveria resolver inicialmente")
	}
	// Desabilita acme editando o arquivo — deve refletir sem reconstruir o resolver.
	writeFile(t, dir, "tenants.json",
		`[{"name":"acme","scope":"10.20.0.0/16","gmp_user":"tenant-acme","enabled":false}]`)
	if _, ok := r.Resolve("acme"); ok {
		t.Fatal("edição do tenants.json deveria refletir na próxima resolução")
	}
}

func TestFileResolverMissingFiles(t *testing.T) {
	r := NewFileResolver("/nao/existe.json", "/nao/existe-secrets.json")
	if _, ok := r.Resolve("acme"); ok {
		t.Fatal("arquivos ausentes → deny")
	}
}
