//go:build unix

package fsutil

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// Abrir para ler o que estiver no caminho (o desenho é abrir e só então conferir o descritor) não pode travar —
// uma FIFO sem escritor prende um open bloqueante para sempre — nem dar um terminal de controle ao serviço: um tty
// aberto sem O_NOCTTY vira o terminal de controle de um líder de sessão que ainda não tem um, que é o caso de um
// serviço. O efeito do O_NONBLOCK tem teste de comportamento no Linux (TestReadBoundedFIFONaoTravaOChamador); o do
// O_NOCTTY não se provoca num teste comum, então a flag fica presa aqui.
func TestOpenReadNaoTravaNemPegaTerminalDeControle(t *testing.T) {
	for name, flag := range map[string]int{"O_NONBLOCK": syscall.O_NONBLOCK, "O_NOCTTY": syscall.O_NOCTTY} {
		if readFlags&flag != flag {
			t.Errorf("openRead abre sem %s", name)
		}
	}
	if readFlags&(os.O_WRONLY|os.O_RDWR|os.O_CREATE|os.O_TRUNC|os.O_APPEND) != 0 {
		t.Errorf("openRead tem de abrir só para leitura: flags %#x", readFlags)
	}
}

// O acréscimo e o corte nunca passam por um link simbólico, não travam numa FIFO e não pegam terminal; o
// acréscimo cria (sem truncar) e só acrescenta, e o corte nunca cria nem acrescenta (sem O_APPEND, que no Windows
// tira o direito de cortar).
func TestFlagsDoAcrescimoEDoCorte(t *testing.T) {
	common := map[string]int{"O_NOFOLLOW": syscall.O_NOFOLLOW, "O_NONBLOCK": syscall.O_NONBLOCK, "O_NOCTTY": syscall.O_NOCTTY, "O_WRONLY": os.O_WRONLY}
	for name, flag := range common {
		if appendFlags&flag != flag {
			t.Errorf("OpenAppend abre sem %s", name)
		}
		if truncateFlags&flag != flag {
			t.Errorf("TruncateDurable abre sem %s", name)
		}
	}
	if appendFlags&(os.O_APPEND|os.O_CREATE) != os.O_APPEND|os.O_CREATE || appendFlags&(os.O_TRUNC|os.O_RDWR) != 0 {
		t.Errorf("OpenAppend: flags %#x", appendFlags)
	}
	if truncateFlags&(os.O_APPEND|os.O_CREATE|os.O_TRUNC|os.O_RDWR) != 0 {
		t.Errorf("TruncateDurable: flags %#x", truncateFlags)
	}
}

// Ler no lugar um arquivo próprio (a auditoria, no boot) não segue link — um link plantado no lugar dele levaria o
// conector a ler, e passar adiante, outro arquivo do nó —, não trava numa FIFO e não pega terminal.
func TestOpenRegularNoFollowRecusaLink(t *testing.T) {
	for name, flag := range map[string]int{"O_NOFOLLOW": syscall.O_NOFOLLOW, "O_NONBLOCK": syscall.O_NONBLOCK, "O_NOCTTY": syscall.O_NOCTTY} {
		if readNoFollowFlags&flag != flag {
			t.Errorf("OpenRegularNoFollow abre sem %s", name)
		}
	}
	if readNoFollowFlags&(os.O_WRONLY|os.O_RDWR|os.O_CREATE|os.O_TRUNC|os.O_APPEND) != 0 {
		t.Errorf("OpenRegularNoFollow tem de abrir só para leitura: flags %#x", readNoFollowFlags)
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "chave.pem")
	if err := os.WriteFile(target, []byte("conteudo de outro arquivo\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "audit.jsonl")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	dangling := filepath.Join(dir, "audit-reject.jsonl")
	if err := os.Symlink(filepath.Join(dir, "nao-existe"), dangling); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{link, dangling} {
		f, err := OpenRegularNoFollow(p)
		if err == nil {
			f.Close()
			t.Fatalf("%s: abriu através de um link", filepath.Base(p))
		}
		if errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("%s: um link no caminho não é ausente (%v)", filepath.Base(p), err)
		}
	}
}

func TestOpenAppendCriaCom0600(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	f, err := OpenAppend(path)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("modo %04o, esperava 0600", fi.Mode().Perm())
	}
}

// Quem troca o arquivo de auditoria por um link (para o policy.json, para a chave do nó...) não faz o conector
// escrever através dele: o acréscimo e o corte falham e o destino fica intacto.
func TestAcrescimoECorteNaoPassamPorLink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "alvo")
	if err := os.WriteFile(target, []byte("intocado\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "audit.jsonl")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if f, err := OpenAppend(link); err == nil {
		f.Close()
		t.Fatal("OpenAppend abriu através de um link")
	}
	if err := TruncateDurable(link, 0); err == nil {
		t.Fatal("TruncateDurable cortou através de um link")
	}
	if got := readFile(t, target); got != "intocado\n" {
		t.Fatalf("o destino do link mudou: %q", got)
	}
}
