// Package sessiongate é a segunda camada (defesa em profundidade) das rotas de
// SESSÃO do control-plane: as que não têm bearer nem mTLS e só são seguras atrás do
// portão de sessão do nginx (auth_request → gsad).
//
// A fronteira primária continua sendo o nginx. Mas essas rotas não se defendem
// sozinhas: se uma location sem portão (ex.: um catch-all que repassa tudo ao
// control-plane) as alcançasse, o pedido chegaria a elas sem autenticação. Por isso:
//
//   - o nginx seta o header Header com o valor Value SÓ nas locations que têm o
//     portão de sessão, e LIMPA esse header em todas as outras (o que o cliente
//     mandar nunca chega ao control-plane);
//   - as rotas de sessão exigem a marca (Require) e recusam com 403 o pedido sem ela.
//
// A marca NÃO é segredo nem credencial e não autentica ninguém: ela só impede que
// uma location sem portão alcance uma rota de sessão. Quem fala direto com o
// control-plane está fora desse modelo (a porta é interna e não pode ser exposta).
package sessiongate

import (
	"log"
	"net/http"
)

const (
	// Header é o nome do header que o nginx seta nas locations com portão de sessão.
	Header = "X-Suricatoos-Gate"
	// Value é o único valor que abre o portão (comparação exata, sensível a maiúsculas).
	Value = "gsad-session"
)

// OK diz se o pedido traz a marca de portão de sessão: o header Header com o valor
// exato Value.
func OK(r *http.Request) bool {
	return r.Header.Get(Header) == Value
}

// Require envolve next e só o deixa executar quando OK(r). Sem a marca, responde 403
// (text/plain) e registra UMA linha de log com método e caminho. A query string fica
// fora do log, e o caminho vai escapado: o pedido recusado é de quem não passou pelo
// portão, então o caminho vem de fora e não pode forjar linhas de log.
func Require(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !OK(r) {
			log.Printf("sessiongate: negado %s %s", r.Method, r.URL.EscapedPath())
			http.Error(w, "rota de sessão sem portão", http.StatusForbidden)
			return
		}
		next(w, r)
	}
}
