package tenant

import (
	"errors"
	"io/fs"
	"strings"
	"testing"
)

// secretFileWarnings avisa do modo de um arquivo de segredos, nunca recusa, e o aviso só traz o caminho e o modo.
func TestSecretFileWarnings(t *testing.T) {
	const path = "/run/segredos/tenants.json"
	called := 0
	mode := func(perm fs.FileMode, loose bool, err error) func(string) (fs.FileMode, bool, error) {
		return func(p string) (fs.FileMode, bool, error) {
			called++
			if p != path {
				t.Errorf("conferiu %q, esperava %q", p, path)
			}
			return perm, loose, err
		}
	}

	got := secretFileWarnings("SENSOR_TENANT_SECRETS", path, mode(0o644, true, nil))
	if len(got) != 1 {
		t.Fatalf("esperava um aviso, veio %v", got)
	}
	for _, want := range []string{"SENSOR_TENANT_SECRETS", path, "0644", "0600"} {
		if !strings.Contains(got[0], want) {
			t.Errorf("o aviso deveria citar %q: %s", want, got[0])
		}
	}
	if w := secretFileWarnings("X", path, mode(0o640, true, nil)); len(w) != 1 || !strings.Contains(w[0], "0640") {
		t.Errorf("0640: %v", w)
	}
	for name, fn := range map[string]func(string) (fs.FileMode, bool, error){
		"0600, sem aviso": mode(0o600, false, nil),
		"arquivo ausente: outro caminho já responde por isso": mode(0, false, fs.ErrNotExist),
		"erro de leitura do modo":                             mode(0, false, errors.New("EIO")),
	} {
		if w := secretFileWarnings("X", path, fn); len(w) != 0 {
			t.Errorf("%s: não devia avisar, veio %v", name, w)
		}
	}
	before := called
	if w := secretFileWarnings("X", "", mode(0o644, true, nil)); len(w) != 0 || called != before {
		t.Errorf("caminho não definido: nada a conferir (avisos %v, chamadas %d)", w, called-before)
	}
}
