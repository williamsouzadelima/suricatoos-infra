package fleetops

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

// O próprio binário de teste faz o papel do fleet_ops.py: quando o primeiro argumento é fakeArg, TestMain roda o
// modo pedido em vez dos testes. Nenhum outro executável é compilado (o Smart App Control bloquearia um binário
// novo) e nenhum gvmd é necessário.
const fakeArg = "fake-fleet-ops"

func TestMain(m *testing.M) {
	if len(os.Args) > 2 && os.Args[1] == fakeArg {
		os.Exit(fake(os.Args[2], os.Args[3:]))
	}
	os.Exit(m.Run())
}

// fake é o fleet_ops falso. Os modos:
//
//	echo        devolve ok com o pedido recebido, o argv inteiro (menos o executável) e o ambiente do processo
//	error       devolve {"ok":false,"error":{code,message}} com os argumentos code e message, saída 0
//	exit1       a resposta de erro de uma falha inesperada, com saída 1
//	ok-exit1    ok com saída 1 (fora do protocolo)
//	garbage     texto que não é JSON, saída 0
//	traceback   texto que não é JSON, saída 1
//	two-values  dois objetos JSON
//	sleep       dorme um minuto sem responder
//	big N       escreve N bytes de espaço e não termina o JSON
//	padded N    ok com {} completado com espaços até N bytes no total
//	stderr      escreve a senha no stderr e responde ok
//	leak        erro cuja mensagem repete a senha e traz caracteres de controle
//	artifact    ok com output e artifact
//	raw TEXTO   escreve TEXTO como está, saída 0
func fake(mode string, args []string) int {
	in, _ := io.ReadAll(os.Stdin)
	out := os.Stdout
	switch mode {
	case "echo":
		env := os.Environ()
		sort.Strings(env)
		resp := map[string]any{"ok": true, "output": map[string]any{
			"request": json.RawMessage(in), "args": os.Args[1:], "env": env,
		}}
		b, _ := json.Marshal(resp)
		out.Write(append(b, '\n'))
	case "error":
		b, _ := json.Marshal(map[string]any{"ok": false, "error": map[string]string{"code": args[0], "message": args[1]}})
		out.Write(append(b, '\n'))
	case "exit1":
		out.WriteString(`{"ok":false,"error":{"code":"internal_error","message":"unexpected failure (KeyError)"}}` + "\n")
		return 1
	case "ok-exit1":
		out.WriteString(`{"ok":true,"output":{}}` + "\n")
		return 1
	case "garbage":
		out.WriteString("isto não é JSON\n")
	case "traceback":
		out.WriteString("Traceback (most recent call last):\n  File \"fleet_ops.py\"\n")
		return 1
	case "two-values":
		out.WriteString(`{"ok":true,"output":{}}{"ok":true,"output":{}}` + "\n")
	case "sleep":
		time.Sleep(time.Minute)
	case "big":
		n, _ := strconv.Atoi(args[0])
		out.WriteString(`{"ok":true,"output":{"x":"`)
		out.WriteString(strings.Repeat("a", n))
		time.Sleep(time.Minute) // nunca termina: quem para é o teto do leitor
	case "padded":
		n, _ := strconv.Atoi(args[0])
		body := `{"ok":true,"output":{}}`
		out.WriteString(body + strings.Repeat(" ", n-len(body)))
	case "stderr":
		fmt.Fprintf(os.Stderr, "debug: GMP_PASSWORD=%s\n", os.Getenv("GMP_PASSWORD"))
		out.WriteString(`{"ok":true,"output":{"a":1}}` + "\n")
	case "leak":
		msg := "gvmd refused authenticate: senha " + os.Getenv("GMP_PASSWORD") + "\x01 fim"
		b, _ := json.Marshal(map[string]any{"ok": false, "error": map[string]string{"code": "gvm_error", "message": msg}})
		out.Write(append(b, '\n'))
	case "artifact":
		out.WriteString(`{"ok":true,"output":{"report_id":"x"},"artifact":{"original_size":3}}` + "\n")
	case "raw":
		out.WriteString(args[0])
	default:
		fmt.Fprintln(os.Stderr, "modo desconhecido:", mode)
		return 2
	}
	return 0
}
