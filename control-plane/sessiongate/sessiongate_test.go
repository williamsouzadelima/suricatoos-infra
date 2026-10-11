package sessiongate

import (
	"bytes"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// corpoRecusa é o corpo exato do 403 (text/plain) devolvido ao pedido sem marca.
const corpoRecusa = "rota de sessão sem portão"

// capturaLog desvia o logger padrão para um buffer, sem timestamp, até o fim do teste.
// Mexe em estado global do pacote log: os testes que a usam não podem ser paralelos.
func capturaLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	antesW, antesF := log.Writer(), log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	t.Cleanup(func() {
		log.SetOutput(antesW)
		log.SetFlags(antesF)
	})
	return &buf
}

// novaReq monta um POST de rota de sessão; envia=false deixa o header ausente.
func novaReq(envia bool, valor string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/agents/scan?id=agent-1", nil)
	if envia {
		r.Header.Set(Header, valor)
	}
	return r
}

// marcasInvalidas são todas as variações que NÃO podem abrir o portão: a comparação
// é exata e sensível a maiúsculas, sem aparar espaços nem aceitar prefixo/sufixo.
var marcasInvalidas = []struct {
	nome   string
	envia  bool
	valor  string
	motivo string
}{
	{"ausente", false, "", "sem header"},
	{"vazia", true, "", "header presente mas vazio"},
	{"valor 1", true, "1", "valor errado"},
	{"caixa diferente", true, "GSAD-SESSION", "case-sensitive"},
	{"espaço à esquerda", true, " gsad-session", "sem aparar espaços"},
	{"espaço à direita", true, "gsad-session ", "sem aparar espaços"},
	{"prefixo do valor", true, "gsad", "não é prefixo"},
	{"valor com sufixo", true, "gsad-session-x", "não é sufixo"},
}

// Os literais são contrato com o nginx, que seta a marca só nas locations com portão
// de sessão e a limpa nas demais: mudar um lado sem o outro derruba as rotas de sessão.
func TestContratoLiteral(t *testing.T) {
	if Header != "X-Suricatoos-Gate" {
		t.Errorf("Header = %q, want %q", Header, "X-Suricatoos-Gate")
	}
	if Value != "gsad-session" {
		t.Errorf("Value = %q, want %q", Value, "gsad-session")
	}
}

func TestOK(t *testing.T) {
	if !OK(novaReq(true, Value)) {
		t.Error("OK() = false com a marca exata")
	}
	for _, c := range marcasInvalidas {
		t.Run(c.nome, func(t *testing.T) {
			if OK(novaReq(c.envia, c.valor)) {
				t.Errorf("OK() = true (%s): envia=%v valor=%q", c.motivo, c.envia, c.valor)
			}
		})
	}
}

func TestRequire_Recusa(t *testing.T) {
	for _, c := range marcasInvalidas {
		t.Run(c.nome, func(t *testing.T) {
			capturaLog(t) // a recusa loga; mantém a saída do teste limpa
			chamou := false
			h := Require(func(http.ResponseWriter, *http.Request) { chamou = true })

			rec := httptest.NewRecorder()
			h(rec, novaReq(c.envia, c.valor))

			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403 (%s)", rec.Code, c.motivo)
			}
			if got := strings.TrimSpace(rec.Body.String()); got != corpoRecusa {
				t.Errorf("corpo = %q, want %q", got, corpoRecusa)
			}
			if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
				t.Errorf("Content-Type = %q, want text/plain", ct)
			}
			if chamou {
				t.Error("o handler protegido executou apesar da recusa")
			}
		})
	}
}

func TestRequire_PassaComMarcaExata(t *testing.T) {
	buf := capturaLog(t)
	chamadas := 0
	h := Require(func(w http.ResponseWriter, r *http.Request) {
		chamadas++
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte("ok"))
	})

	rec := httptest.NewRecorder()
	h(rec, novaReq(true, Value))

	if chamadas != 1 {
		t.Fatalf("handler protegido executou %d vezes, want 1", chamadas)
	}
	if rec.Code != http.StatusAccepted || rec.Body.String() != "ok" {
		t.Errorf("resposta do handler protegido alterada: %d %q", rec.Code, rec.Body.String())
	}
	if buf.Len() != 0 {
		t.Errorf("passagem não deve logar, got %q", buf.String())
	}
}

// A recusa deixa UMA linha de log no formato do contrato, só com método e caminho:
// a query string pode carregar dados do pedido (tenant, id) e não vai para o log.
func TestRequire_LogaUmaLinhaSemQuery(t *testing.T) {
	buf := capturaLog(t)
	h := Require(func(http.ResponseWriter, *http.Request) {})

	h(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/agents/scan?id=agent-1&tenant=acme", nil))

	const want = "sessiongate: negado POST /agents/scan\n"
	if got := buf.String(); got != want {
		t.Fatalf("log = %q, want %q", got, want)
	}
}

// O pedido recusado é, por definição, de quem não passou pelo portão: o caminho vem
// de fora e não pode forjar linhas de log. %0A/%0D chegam decodificados em URL.Path.
func TestRequire_LogEscapaCaracteresDeControle(t *testing.T) {
	buf := capturaLog(t)
	h := Require(func(http.ResponseWriter, *http.Request) {})

	h(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/ai/providers%0Asessiongate:%20falso%0D", nil))

	got := buf.String()
	if strings.Count(got, "\n") != 1 || strings.Contains(got, "\r") {
		t.Fatalf("log deve ser uma única linha, got %q", got)
	}
	const want = "sessiongate: negado GET /ai/providers%0Asessiongate:%20falso%0D\n"
	if got != want {
		t.Errorf("log = %q, want %q", got, want)
	}
}
