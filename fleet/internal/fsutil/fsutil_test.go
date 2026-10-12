package fsutil

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"syscall"
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

// A regularidade é conferida no descritor que se abriu, não no caminho: entre um Stat e um Open o caminho pode
// virar outra coisa (uma FIFO trava o Open para sempre). readRegular é o passo que decide, com o descritor na mão.
func TestReadRegularConfereODescritorAberto(t *testing.T) {
	dir := t.TempDir()

	// um diretório aberto é um descritor que não é arquivo regular em qualquer sistema
	d, err := os.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if _, err := readRegular(d, "dir", 64); !errors.Is(err, ErrNotRegular) {
		t.Fatalf("descritor de diretório: esperava ErrNotRegular, deu %v", err)
	}

	// um arquivo regular passa, com o teto
	p := filepath.Join(dir, "f")
	if err := os.WriteFile(p, []byte("abc"), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	got, err := readRegular(f, p, 3)
	if err != nil || string(got) != "abc" {
		t.Fatalf("arquivo regular no teto: %q, %v", got, err)
	}
	if _, err := f.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := readRegular(f, p, 2); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("um byte acima do teto: esperava ErrTooLarge, deu %v", err)
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

// swapSyncDirectory troca, durante o teste, a função que sincroniza o diretório depois do rename.
func swapSyncDirectory(t *testing.T, fn func(dir string) error) {
	t.Helper()
	old := syncDirectory
	syncDirectory = fn
	t.Cleanup(func() { syncDirectory = old })
}

// O rename já aconteceu quando o diretório é sincronizado: o conteúdo novo está no lugar, mas não se sabe se
// sobrevive a uma queda de energia. O chamador (o orçamento, o store anti-replay) tem de saber disso.
func TestWriteAtomicDevolveOErroDoSyncDoDiretorio(t *testing.T) {
	boom := errors.New("EIO simulado")
	var gotDir string
	swapSyncDirectory(t, func(dir string) error { gotDir = dir; return boom })

	dir := t.TempDir()
	p := filepath.Join(dir, "estado.json")
	if err := os.WriteFile(p, []byte("antigo"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := WriteAtomic(p, []byte("novo"))
	if !errors.Is(err, ErrNotDurable) {
		t.Fatalf("esperava ErrNotDurable, deu %v", err)
	}
	if !errors.Is(err, boom) {
		t.Fatalf("o erro do sync tem de continuar acessível: %v", err)
	}
	if gotDir != dir {
		t.Fatalf("sincronizou %q, esperava o diretório do arquivo %q", gotDir, dir)
	}
	// o rename já tinha acontecido: o conteúdo novo está lá, e nenhum temporário sobra
	if got, _ := os.ReadFile(p); string(got) != "novo" {
		t.Fatalf("conteúdo %q", got)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Fatalf("sobrou arquivo ao lado de estado.json: %d entradas", len(entries))
	}
}

func TestWriteAtomicSemErroNoSyncDoDiretorioDevolveNil(t *testing.T) {
	called := 0
	swapSyncDirectory(t, func(string) error { called++; return nil })
	if err := WriteAtomic(filepath.Join(t.TempDir(), "estado.json"), []byte("x")); err != nil {
		t.Fatal(err)
	}
	if called != 1 {
		t.Fatalf("o diretório deveria ser sincronizado uma vez, foi %d", called)
	}
}

// Só "este sistema de arquivos não sincroniza diretório" é tolerado; qualquer outro erro de E/S não é.
func TestDirSyncToleraSoONaoSuportado(t *testing.T) {
	tolerated := map[string]error{
		"EINVAL":                syscall.EINVAL,
		"EINVAL embrulhado":     fmt.Errorf("sync: %w", syscall.EINVAL),
		"ENOTSUP":               syscall.ENOTSUP,
		"EOPNOTSUPP":            syscall.EOPNOTSUPP,
		"ENOTSUP em *PathError": &fs.PathError{Op: "sync", Path: "/d", Err: syscall.ENOTSUP},
	}
	for name, err := range tolerated {
		if !dirSyncUnsupported(err) {
			t.Errorf("%s: deveria ser tolerado", name)
		}
	}
	refused := map[string]error{
		"nil": nil,
		// só EINVAL e ENOTSUP/EOPNOTSUPP são "este sistema de arquivos não sincroniza diretório"; o resto não é
		"ENOSYS":                       syscall.ENOSYS,
		"errors.ErrUnsupported":        errors.ErrUnsupported,
		"ErrUnsupported em *PathError": &fs.PathError{Op: "sync", Path: "/d", Err: errors.ErrUnsupported},
		"EIO":                          syscall.EIO,
		"EIO embrulhado":               fmt.Errorf("sync: %w", syscall.EIO),
		"EACCES":                       syscall.EACCES,
		"ENOSPC":                       syscall.ENOSPC,
		"não existe":                   fs.ErrNotExist,
		"erro qualquer":                errors.New("falhou"),
		"EIO em *PathError":            &fs.PathError{Op: "sync", Path: "/d", Err: syscall.EIO},
	}
	for name, err := range refused {
		if dirSyncUnsupported(err) {
			t.Errorf("%s: não pode ser tolerado", name)
		}
	}
}

// Uma queda entre criar o temporário e o rename deixa "<arquivo>.tmp-<dígitos>" para sempre. Só os do próprio
// arquivo saem, e só com o sufixo que o os.CreateTemp gera (dígitos decimais): o diretório é dividido com os
// outros arquivos de estado do conector, e um arquivo do operador com o mesmo prefixo não é temporário.
func TestRemoveOrphanTempsRemoveSoOsDoProprioArquivo(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "estado.json")
	mine := []string{"estado.json.tmp-1", "estado.json.tmp-987654321", "estado.json.tmp-4294967295"}
	others := []string{
		"estado.json",                             // o próprio arquivo
		"estado.json.bak",                         // outro sufixo
		"estado.json.tmp",                         // sem o hífen do sufixo aleatório
		"estado.json.tmp-",                        // sem sufixo
		"estado.json.tmp-abc",                     // sufixo que o os.CreateTemp nunca gera: pode ser do operador
		"estado.json.tmp-12a",                     // idem, dígitos e letra
		"estado.json.tmp-1.bak",                   // cópia do operador de um temporário
		"estado.json.tmp--1",                      // sinal não é dígito
		"estado.json.tmp-+1",                      // idem
		"estado.json.tmp-" + string(rune(0x0663)), // dígito Unicode (árabe-índico) não é dígito ASCII
		"outro.json.tmp-1",                        // temporário de outro arquivo de estado
		"estado.jsonx.tmp-1",                      // prefixo parecido, outro arquivo
		"xestado.json.tmp-1",                      // idem
		"politica.json.tmp-7",                     // de outro módulo
	}
	for _, name := range append(append([]string{}, mine...), others...) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// um diretório com o nome exato de um temporário não é um temporário
	for _, name := range []string{"estado.json.tmp-42", "estado.json.tmp-dir"} {
		if err := os.Mkdir(filepath.Join(dir, name), 0o700); err != nil {
			t.Fatal(err)
		}
		others = append(others, name)
	}

	removed, err := RemoveOrphanTemps(path)
	if err != nil || removed != len(mine) {
		t.Fatalf("removidos %d (esperava %d), erro %v", removed, len(mine), err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var left []string
	for _, e := range entries {
		left = append(left, e.Name())
	}
	slices.Sort(others)
	if !slices.Equal(left, others) {
		t.Fatalf("sobraram %v, esperava %v", left, others)
	}
}

// A limpeza só reconhece sufixo de dígitos porque é o que o os.CreateTemp gera: se a biblioteca mudar isso, este
// teste quebra antes que temporários reais passem a sobrar para sempre.
func TestCreateTempGeraSufixoDeDigitosQueALimpezaReconhece(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "estado.json")
	const n = 20
	for range n {
		f, err := os.CreateTemp(dir, filepath.Base(path)+tempInfix+"*")
		if err != nil {
			t.Fatal(err)
		}
		suffix := strings.TrimPrefix(filepath.Base(f.Name()), filepath.Base(path)+tempInfix)
		f.Close()
		if suffix == "" || strings.Trim(suffix, "0123456789") != "" {
			t.Fatalf("os.CreateTemp gerou o sufixo %q: a limpeza só reconhece dígitos", suffix)
		}
	}
	if removed, err := RemoveOrphanTemps(path); err != nil || removed != n {
		t.Fatalf("removidos %d de %d, erro %v", removed, n, err)
	}
}

func TestRemoveOrphanTempsSemNadaParaLimparNaoEErro(t *testing.T) {
	dir := t.TempDir()
	if n, err := RemoveOrphanTemps(filepath.Join(dir, "estado.json")); n != 0 || err != nil {
		t.Fatalf("diretório vazio: %d %v", n, err)
	}
	if n, err := RemoveOrphanTemps(filepath.Join(dir, "sem", "pai", "estado.json")); n != 0 || err != nil {
		t.Fatalf("diretório que não existe: %d %v", n, err)
	}
}

// Um arquivo de segredos tem de ser 0600: qualquer bit de grupo ou de outros o deixa "frouxo".
func TestLooseBits(t *testing.T) {
	cases := []struct {
		perm  fs.FileMode
		loose bool
	}{
		{0o600, false}, {0o400, false}, {0o700, false}, {0o500, false}, {0o000, false},
		{0o644, true}, {0o640, true}, {0o604, true}, {0o660, true}, {0o666, true}, {0o601 | 0o010, true}, {0o602, true},
		{0o755, true}, {0o777, true},
	}
	for _, c := range cases {
		if got := looseBits(c.perm); got != c.loose {
			t.Errorf("looseBits(%04o) = %v, esperava %v", c.perm, got, c.loose)
		}
	}
	// só os bits de permissão contam: o tipo do arquivo (link, diretório...) não
	if looseBits(fs.ModeSymlink | 0o600) {
		t.Error("o bit de tipo não é bit de permissão")
	}
}

func TestLooseModeArquivoAusenteEErro(t *testing.T) {
	_, loose, err := LooseMode(filepath.Join(t.TempDir(), "nao-existe"))
	if !errors.Is(err, fs.ErrNotExist) || loose {
		t.Fatalf("arquivo ausente: loose=%v err=%v", loose, err)
	}
}

// No Windows o modo não é controle de acesso (todo arquivo aparece como 0666): avisar sempre seria só ruído.
func TestLooseModeNoWindowsNuncaAvisa(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("só no Windows")
	}
	p := filepath.Join(t.TempDir(), "segredo")
	if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, loose, err := LooseMode(p); err != nil || loose {
		t.Fatalf("loose=%v err=%v", loose, err)
	}
}

func TestWriteAtomicDiretorioAusenteEErro(t *testing.T) {
	if err := WriteAtomic(filepath.Join(t.TempDir(), "sem", "pai", "f"), []byte("x")); err == nil {
		t.Fatal("diretório ausente deveria dar erro")
	}
}
