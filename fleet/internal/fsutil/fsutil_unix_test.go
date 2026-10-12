//go:build unix

package fsutil

import (
	"os"
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
