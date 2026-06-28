// Command suricatoos-agent is the Suricatoos endpoint agent: it collects local
// vulnerability posture and reports it outbound to the Suricatoos control plane.
//
// It is PASSIVE and LOCAL-ONLY — it never scans or probes other hosts. See
// docs/PLAN.md for the architecture and phase plan.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/williamsouzadelima/suricatoos-infra/agent/internal/agentd"
	"github.com/williamsouzadelima/suricatoos-infra/agent/internal/collect"
	"github.com/williamsouzadelima/suricatoos-infra/agent/internal/enroll"
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
		runEnroll(os.Args[2:])
	case "run":
		runDaemon(os.Args[2:])
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

// runEnroll troca um bootstrap token por um certificado mTLS e grava a identidade.
func runEnroll(args []string) {
	fs := flag.NewFlagSet("enroll", flag.ExitOnError)
	server := fs.String("server", "", "URL base do control plane (ex.: https://cp.suricatoos)")
	token := fs.String("token", "", "bootstrap token")
	agentID := fs.String("agent-id", "", "id do agente (default: hostname)")
	stateDir := fs.String("state", "./suricatoos-agent", "diretório para gravar a identidade")
	caPin := fs.String("ca-pin", "", "fingerprint SHA-256 (hex) da CA esperada — recomendado (pin out-of-band)")
	_ = fs.Parse(args)

	if *server == "" || *token == "" {
		fmt.Fprintln(os.Stderr, "enroll: --server e --token são obrigatórios")
		os.Exit(2)
	}
	id := *agentID
	if id == "" {
		id, _ = os.Hostname()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	identity, err := enroll.Enroll(ctx, &http.Client{Timeout: 30 * time.Second}, *server, *token, id, *caPin)
	if err != nil {
		fmt.Fprintln(os.Stderr, "enroll:", err)
		os.Exit(1)
	}
	if err := enroll.Save(*stateDir, identity); err != nil {
		fmt.Fprintln(os.Stderr, "enroll: gravar identidade:", err)
		os.Exit(1)
	}
	fmt.Printf("enrolled: identidade de %q gravada em %s\n", id, *stateDir)
}

// runDaemon executa o loop de coleta + reporte até receber SIGINT/SIGTERM.
func runDaemon(args []string) {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	stateDir := fs.String("state", "./suricatoos-agent", "diretório da identidade (do enroll)")
	ingest := fs.String("ingest", "", "URL do ingest (ex.: https://ingest.suricatoos/v1/inventory)")
	queueDir := fs.String("queue", "./suricatoos-agent/queue", "diretório da fila offline")
	interval := fs.Duration("interval", 15*time.Minute, "intervalo entre coletas")
	maxQueue := fs.Int("max-queue", 1000, "máximo de itens na fila offline")
	_ = fs.Parse(args)

	if *ingest == "" {
		fmt.Fprintln(os.Stderr, "run: --ingest é obrigatório")
		os.Exit(2)
	}
	ag, err := agentd.New(agentd.Config{
		StateDir:  *stateDir,
		QueueDir:  *queueDir,
		IngestURL: *ingest,
		MaxQueue:  *maxQueue,
		Interval:  *interval,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "run:", err)
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	fmt.Printf("suricatoos-agent rodando (ingest=%s, intervalo=%s) — Ctrl-C para parar\n", *ingest, *interval)
	if err := ag.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintln(os.Stderr, "run:", err)
		os.Exit(1)
	}
}

func usage(w io.Writer) {
	fmt.Fprint(w, `suricatoos-agent — agente de postura de vulnerabilidade (passivo/local)

uso:
  suricatoos-agent <comando>

comandos:
  inventory  coleta e imprime o inventário local (JSON)
  enroll     registra o agente no control plane (--server, --token [, --agent-id, --state, --ca-pin])
  run        loop de coleta + reporte outbound (--ingest [, --state, --queue, --interval, --max-queue])
  version    mostra a versão do agente
  help       mostra esta ajuda
`)
}
