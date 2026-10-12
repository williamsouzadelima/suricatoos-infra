//go:build linux

package tenant

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/williamsouzadelima/suricatoos-infra/fleet/contract"
)

// Com modos de verdade: o aviso sai para o arquivo de segredos do central e para o arquivo de senha do local,
// e só quando o grupo ou os outros alcançam o arquivo.
func TestSecretFileWarningsComModosReais(t *testing.T) {
	write := func(path string, mode os.FileMode) {
		t.Helper()
		if err := os.WriteFile(path, []byte(`{"acme":"senha-ficticia"}`), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
	}
	cases := []struct {
		mode os.FileMode
		warn bool
	}{{0o600, false}, {0o400, false}, {0o644, true}, {0o640, true}, {0o604, true}, {0o666, true}}

	for _, c := range cases {
		e := newCentralEnv(t)
		write(e.secrets, c.mode)
		got := e.open(t).SecretFileWarnings()
		if (len(got) == 1) != c.warn || len(got) > 1 {
			t.Errorf("central, modo %04o: avisos %v", c.mode, got)
		}
		if c.warn && (!strings.Contains(got[0], e.secrets) || strings.Contains(got[0], "senha-ficticia")) {
			t.Errorf("o aviso cita o caminho e nunca o conteúdo: %s", got[0])
		}

		l := newLocalEnv(t)
		write(l.passwordFile, c.mode)
		got = l.open(t, contract.NodeStandalone).SecretFileWarnings()
		if (len(got) == 1) != c.warn || len(got) > 1 {
			t.Errorf("local, modo %04o: avisos %v", c.mode, got)
		}
	}

	// sem arquivo de segredos, ou sem caminho configurado, não há o que avisar
	e := newCentralEnv(t)
	if err := os.Remove(e.secrets); err != nil {
		t.Fatal(err)
	}
	if got := e.open(t).SecretFileWarnings(); len(got) != 0 {
		t.Errorf("arquivo ausente: %v", got)
	}
	src, err := Open(contract.NodeCentral, Config{TenantsFile: filepath.Join(t.TempDir(), "tenants.json")})
	if err != nil {
		t.Fatal(err)
	}
	if got := src.SecretFileWarnings(); len(got) != 0 {
		t.Errorf("SENSOR_TENANT_SECRETS não definido: %v", got)
	}
}
