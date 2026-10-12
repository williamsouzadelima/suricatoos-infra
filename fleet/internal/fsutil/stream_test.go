package fsutil

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// O conteúdo grande (o store anti-replay compactado) vai para o arquivo temporário em pedaços, sem ficar inteiro
// na memória, e só substitui o anterior depois do fsync e do rename, como no WriteAtomic.
func TestWriteAtomicStreamGravaEmPedacos(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "store.log")
	if err := os.WriteFile(p, []byte("anterior"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := WriteAtomicStream(p, func(w io.Writer) error {
		for i := range 3 {
			if _, err := io.WriteString(w, strings.Repeat(string(rune('a'+i)), 4)); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(p); err != nil || string(got) != "aaaabbbbcccc" {
		t.Fatalf("conteúdo %q, %v", got, err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Fatalf("sobrou temporário: %v", entries)
	}
}

// Um erro do produtor do conteúdo sai antes do rename: o arquivo anterior fica intacto, nenhum temporário sobra, e
// o erro devolvido é o do produtor (não um ErrNotDurable: nada foi trocado).
func TestWriteAtomicStreamErroDoProdutorNaoTrocaNada(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "store.log")
	if err := os.WriteFile(p, []byte("anterior"), 0o600); err != nil {
		t.Fatal(err)
	}
	boom := errors.New("produtor falhou")
	err := WriteAtomicStream(p, func(w io.Writer) error {
		if _, err := io.WriteString(w, "meio caminho"); err != nil {
			return err
		}
		return boom
	})
	if !errors.Is(err, boom) || errors.Is(err, ErrNotDurable) {
		t.Fatalf("esperava o erro do produtor, deu %v", err)
	}
	if got, _ := os.ReadFile(p); !bytes.Equal(got, []byte("anterior")) {
		t.Fatalf("o arquivo anterior mudou: %q", got)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Fatalf("sobrou temporário: %v", entries)
	}
}

// O sync do diretório que falha depois do rename é ErrNotDurable também aqui: o conteúdo novo está no lugar.
func TestWriteAtomicStreamDevolveErrNotDurable(t *testing.T) {
	swapSyncDirectory(t, func(string) error { return errors.New("EIO simulado") })
	p := filepath.Join(t.TempDir(), "store.log")
	err := WriteAtomicStream(p, func(w io.Writer) error { _, err := io.WriteString(w, "novo"); return err })
	if !errors.Is(err, ErrNotDurable) {
		t.Fatalf("esperava ErrNotDurable, deu %v", err)
	}
	if got, _ := os.ReadFile(p); string(got) != "novo" {
		t.Fatalf("o conteúdo novo devia estar no lugar: %q", got)
	}
}
