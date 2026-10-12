//go:build unix

package audit

import (
	"os"
	"path/filepath"
	"testing"
)

// Um link no lugar do arquivo atual ou de um girado (para um arquivo qualquer do nó) não é seguido: o Open falha
// em vez de ler o outro arquivo — que iria verbatim ao hub na cauda — e nada é escrito no destino.
func TestBootNaoSegueLink(t *testing.T) {
	for _, name := range []string{ExecFileName, ExecFileName + ".1"} {
		dir := t.TempDir()
		target := filepath.Join(dir, "outro.pem")
		content := "-----BEGIN CERTIFICATE-----\nTUlJQmZpY3RpY2lv\n-----END CERTIFICATE-----\n"
		if err := os.WriteFile(target, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
		if l, err := open(dir, testBoot, Options{}, defaultConfig()); err == nil {
			t.Fatalf("%s: o Open seguiu o link (cauda exec: %q)", name, l.Tail().Exec.Lines)
		}
		if got, err := os.ReadFile(target); err != nil || string(got) != content {
			t.Fatalf("%s: o destino do link mudou: %q, %v", name, got, err)
		}
	}
}
