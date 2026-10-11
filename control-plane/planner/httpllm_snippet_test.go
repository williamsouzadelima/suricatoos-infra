package planner

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"unicode/utf8"
)

// The StatusError snippet is what the planner's final error may carry of a
// provider's body: short (at most snippetMax runes), one line, printable, valid
// UTF-8, and without the key — ours or anything shaped like one.
func TestHTTPLLM_StatusErrorSnippetIsShortAndSanitized(t *testing.T) {
	const key = "sk-or-v1-SEGREDO-0123456789abcdef"
	body := "linha 1\r\nlinha\t2 \x1b[0m chave=" + key + " outra=sk-or-v1-OUTRA-9999 " + strings.Repeat("é", 300)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()
	req := chatReq(srv.URL)
	req.APIKey = key

	_, err := NewHTTPLLM().Chat(context.Background(), req)
	var se *StatusError
	if !errors.As(err, &se) || se.Code != http.StatusNotFound {
		t.Fatalf("esperava StatusError 404, veio %v", err)
	}
	s := se.Snippet
	if strings.Contains(s, key) || strings.Contains(s, "OUTRA-9999") {
		t.Fatalf("o trecho carrega uma chave: %q", s)
	}
	if strings.ContainsAny(s, "\r\n\t\x1b") || !utf8.ValidString(s) {
		t.Fatalf("o trecho deveria ser uma linha imprimível e UTF-8 válido: %q", s)
	}
	if n := utf8.RuneCountInString(s); n > snippetMax {
		t.Fatalf("o trecho deveria ter no máximo %d caracteres, tem %d", snippetMax, n)
	}
	if !strings.HasPrefix(s, "linha 1 linha 2 [0m chave=[chave] outra=[chave] é") {
		t.Fatalf("o trecho deveria manter o texto legível, só saneado: %q", s)
	}

	// A short body (not truncated) with invalid UTF-8: the bytes are dropped.
	if got := snippet([]byte("erro \xff\xfe\tfim\n"), key); got != "erro fim" {
		t.Fatalf("UTF-8 inválido deveria sair do trecho: %q", got)
	}

	// The request's own key is redacted even when it is not shaped like "sk-…"
	// (a router may issue keys in another format).
	const plain = "uno_SEGREDO_0123456789abcdef"
	if got := snippet([]byte(`{"error":"chave `+plain+` recusada"}`), plain); strings.Contains(got, plain) || !strings.Contains(got, "[chave]") {
		t.Fatalf("a chave do pedido deveria sair do trecho, qualquer que seja o formato: %q", got)
	}
}
