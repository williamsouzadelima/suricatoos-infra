package fsutil

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

func TestReadBoundedLeAteOTeto(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "f")
	if err := os.WriteFile(p, []byte("12345"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := ReadBounded(p, 5)
	if err != nil || string(got) != "12345" {
		t.Fatalf("no teto exato: %q, %v", got, err)
	}
	if _, err := ReadBounded(p, 4); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("um byte acima do teto deveria dar ErrTooLarge, deu %v", err)
	}
}

func TestReadBoundedArquivoAusenteSatisfazErrNotExist(t *testing.T) {
	_, err := ReadBounded(filepath.Join(t.TempDir(), "nao-existe"), 10)
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("esperava fs.ErrNotExist, deu %v", err)
	}
	// o diretório pai ausente também é "ausente"
	_, err = ReadBounded(filepath.Join(t.TempDir(), "sem", "pai", "f"), 10)
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("pai ausente: esperava fs.ErrNotExist, deu %v", err)
	}
}

func TestReadBoundedRecusaQuemNaoEArquivoRegular(t *testing.T) {
	_, err := ReadBounded(t.TempDir(), 10)
	if !errors.Is(err, ErrNotRegular) {
		t.Fatalf("diretório: esperava ErrNotRegular, deu %v", err)
	}
	if errors.Is(err, fs.ErrNotExist) {
		t.Fatal("um diretório existe: não pode passar por ausente")
	}
}

func TestReadBoundedSegueSymlink(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real")
	if err := os.WriteFile(real, []byte("conteudo"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("symlink indisponível neste host: %v", err)
	}
	got, err := ReadBounded(link, 64)
	if err != nil || string(got) != "conteudo" {
		t.Fatalf("symlink para arquivo regular (montagens de ConfigMap): %q, %v", got, err)
	}
}

// danglingLink makes dir/link, an entry whose target does not exist. Where symlinks cannot be created (Windows
// without the privilege) it uses a directory junction whose target is then removed: Stat fails and Lstat
// succeeds, exactly as for a dangling symlink.
func danglingLink(t *testing.T, dir string) string {
	t.Helper()
	link := filepath.Join(dir, "link")
	err := os.Symlink(filepath.Join(dir, "nao-existe"), link)
	if err == nil {
		return link
	}
	if runtime.GOOS != "windows" {
		t.Skipf("symlink indisponível neste host: %v", err)
	}
	target := filepath.Join(dir, "alvo")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", link, target).CombinedOutput(); err != nil {
		t.Skipf("mklink /J indisponível: %v %s", err, out)
	}
	if err := os.Remove(target); err != nil {
		t.Fatal(err)
	}
	return link
}

func TestReadBoundedLinkSemDestinoNaoEAusente(t *testing.T) {
	// há uma entrada no caminho (uma montagem de configuração quebrada, por exemplo): não é "ausente", porque
	// ausente vira a política padrão, o orçamento vazio, o registro sem tenants
	link := danglingLink(t, t.TempDir())
	_, err := ReadBounded(link, 64)
	if !errors.Is(err, ErrDanglingLink) {
		t.Fatalf("esperava ErrDanglingLink, deu %v", err)
	}
	if errors.Is(err, fs.ErrNotExist) {
		t.Fatal("há uma entrada no caminho: não pode passar por ausente (viraria a política padrão, o orçamento vazio...)")
	}
}

func TestWriteAtomicCriaESubstitui(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "estado.json")
	if err := WriteAtomic(p, []byte("um")); err != nil {
		t.Fatal(err)
	}
	if err := WriteAtomic(p, []byte("dois")); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(p)
	if err != nil || !bytes.Equal(got, []byte("dois")) {
		t.Fatalf("conteúdo: %q, %v", got, err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "estado.json" {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("sobrou arquivo temporário no diretório: %v", names)
	}
}

func TestWriteAtomicModo0600(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("modos POSIX não existem no Windows")
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "estado.json")
	// um arquivo anterior mais aberto não pode deixar o novo aberto
	if err := os.WriteFile(p, []byte("antigo"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := WriteAtomic(p, []byte("novo")); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("modo %v, esperava 0600", fi.Mode().Perm())
	}
}

func TestWriteAtomicFalhaNaoDeixaTemporario(t *testing.T) {
	dir := t.TempDir()
	// o destino é um diretório não vazio: o rename falha depois do temp escrito e sincronizado
	dst := filepath.Join(dir, "estado.json")
	if err := os.Mkdir(dst, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dst, "x"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := WriteAtomic(dst, []byte("dados")); err == nil {
		t.Fatal("rename sobre diretório deveria falhar")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "estado.json" {
		t.Fatalf("o temporário deveria ter sido removido, sobrou %d entradas", len(entries))
	}
}

func TestWriteAtomicDiretorioAusenteEErro(t *testing.T) {
	if err := WriteAtomic(filepath.Join(t.TempDir(), "sem", "pai", "f"), []byte("x")); err == nil {
		t.Fatal("diretório ausente deveria dar erro")
	}
}
