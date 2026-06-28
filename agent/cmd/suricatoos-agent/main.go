// Command suricatoos-agent is the Suricatoos endpoint agent: it collects local
// vulnerability posture and reports it outbound to the Suricatoos control plane.
//
// It is PASSIVE and LOCAL-ONLY — it never scans or probes other hosts. See
// docs/PLAN.md for the architecture and phase plan.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/williamsouzadelima/suricatoos-infra/agent/internal/collect"
	"github.com/williamsouzadelima/suricatoos-infra/agent/internal/version"
)

func main() {
	if len(os.Args) < 2 {
		usage(os.Stderr)
		os.Exit(2)
	}
	switch os.Args[1] {
	case "version", "-v", "--version":
		fmt.Println(version.String())
	case "inventory":
		runInventory()
	case "enroll":
		// Fase 1: gerar keypair + CSR e trocar o bootstrap token por cert mTLS.
		fmt.Fprintln(os.Stderr, "enroll: não implementado (Fase 1)")
		os.Exit(1)
	case "run":
		// Fase 1+: loop de coleta + heartbeat + fila offline (store-and-forward).
		fmt.Fprintln(os.Stderr, "run: não implementado (Fase 1)")
		os.Exit(1)
	case "help", "-h", "--help":
		usage(os.Stdout)
	default:
		fmt.Fprintf(os.Stderr, "subcomando desconhecido: %q\n\n", os.Args[1])
		usage(os.Stderr)
		os.Exit(2)
	}
}

// runInventory coleta o inventário local e o imprime como JSON (debug/validação).
func runInventory() {
	c, err := collect.New()
	if err != nil {
		fmt.Fprintln(os.Stderr, "inventory:", err)
		os.Exit(1)
	}
	inv, err := c.Collect()
	if err != nil {
		fmt.Fprintln(os.Stderr, "inventory:", err)
		os.Exit(1)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(inv); err != nil {
		fmt.Fprintln(os.Stderr, "inventory:", err)
		os.Exit(1)
	}
}

func usage(w io.Writer) {
	fmt.Fprint(w, `suricatoos-agent — agente de postura de vulnerabilidade (passivo/local)

uso:
  suricatoos-agent <comando>

comandos:
  inventory  coleta e imprime o inventário local (JSON)
  enroll     registra o agente no control plane (bootstrap token -> cert mTLS)   [Fase 1]
  run        executa o loop de coleta + reporte                                  [Fase 1]
  version    mostra a versão do agente
  help       mostra esta ajuda
`)
}
