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
	"github.com/williamsouzadelima/suricatoos-infra/agent/internal/service"
	"github.com/williamsouzadelima/suricatoos-infra/agent/internal/version"
)

func main() {
	// When started by the Windows SCM, bypass normal CLI parsing and enter
	// the service control protocol immediately.
	if isWindowsService() {
		runWindowsSvc(os.Args[1:])
		return
	}

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
	case "install":
		runInstall(os.Args[2:])
	case "uninstall":
		runUninstall()
	case "service-status":
		runServiceStatus()
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

// buildAgent parses daemon flags and returns a ready-to-run Agent.
// Extracted so the Windows SCM path can reuse it without duplicating logic.
func buildAgent(args []string) (*agentd.Agent, error) {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	stateDir := fs.String("state", "./suricatoos-agent", "diretório da identidade (do enroll)")
	ingest := fs.String("ingest", "", "URL do ingest (ex.: https://ingest.suricatoos/v1/inventory)")
	queueDir := fs.String("queue", "./suricatoos-agent/queue", "diretório da fila offline")
	interval := fs.Duration("interval", 15*time.Minute, "intervalo entre coletas")
	maxQueue := fs.Int("max-queue", 1000, "máximo de itens na fila offline")
	updateInterval := fs.Duration("update-interval", 6*time.Hour, "intervalo de checagem de auto-update assinado (0 desliga)")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	ingestURL := resolveIngestURL(*ingest, *stateDir)
	if ingestURL == "" {
		return nil, errors.New("--ingest é obrigatório (ou enrole o agente para herdá-lo do control-plane)")
	}
	binPath, _ := os.Executable()
	return agentd.New(agentd.Config{
		StateDir:       *stateDir,
		QueueDir:       *queueDir,
		IngestURL:      ingestURL,
		MaxQueue:       *maxQueue,
		Interval:       *interval,
		UpdateInterval: *updateInterval,
		CurrentVersion: version.Version,
		BinaryPath:     binPath,
		Restart:        service.Restart,
	})
}

// resolveIngestURL returns the explicit --ingest flag, or falls back to the
// ingest URL the control-plane handed back at enrollment (persisted in stateDir).
// Returns "" when neither is available.
func resolveIngestURL(flagVal, stateDir string) string {
	if flagVal != "" {
		return flagVal
	}
	if stateDir == "" {
		return ""
	}
	if id, err := enroll.Load(stateDir); err == nil {
		return id.IngestURL
	}
	return ""
}

// runDaemon executa o loop de coleta + reporte até receber SIGINT/SIGTERM.
func runDaemon(args []string) {
	ag, err := buildAgent(args)
	if errors.Is(err, agentd.ErrRolledBack) {
		fmt.Println("update: rollback para a versão anterior — reiniciando o serviço")
		return
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "run:", err)
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	fmt.Printf("suricatoos-agent rodando — Ctrl-C para parar\n")
	if err := ag.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintln(os.Stderr, "run:", err)
		os.Exit(1)
	}
}

// runInstall installs the agent as a native system service.
func runInstall(args []string) {
	fs := flag.NewFlagSet("install", flag.ExitOnError)
	ingest := fs.String("ingest", "", "URL do ingest (obrigatório)")
	stateDir := fs.String("state", "", "diretório de estado (default: plataforma padrão)")
	queueDir := fs.String("queue", "", "diretório da fila (default: <state>/queue)")
	interval := fs.Duration("interval", 15*time.Minute, "intervalo entre coletas")
	maxQueue := fs.Int("max-queue", 1000, "máximo de itens na fila offline")
	_ = fs.Parse(args)

	ingestURL := resolveIngestURL(*ingest, *stateDir)
	if ingestURL == "" {
		fmt.Fprintln(os.Stderr, "install: --ingest é obrigatório (ou enrole o agente primeiro, com --state, para herdá-lo)")
		os.Exit(2)
	}
	cfg := service.Config{
		IngestURL: ingestURL,
		StateDir:  *stateDir,
		QueueDir:  *queueDir,
		Interval:  *interval,
		MaxQueue:  *maxQueue,
	}
	if err := service.Install(cfg); err != nil {
		fmt.Fprintln(os.Stderr, "install:", err)
		os.Exit(1)
	}
	fmt.Println("suricatoos-agent instalado e iniciado como serviço nativo.")
}

// runUninstall stops and removes the native service.
func runUninstall() {
	if err := service.Uninstall(); err != nil {
		fmt.Fprintln(os.Stderr, "uninstall:", err)
		os.Exit(1)
	}
	fmt.Println("suricatoos-agent removido.")
}

// runServiceStatus prints the native service status.
func runServiceStatus() {
	st, err := service.Status()
	if err != nil {
		fmt.Fprintln(os.Stderr, "service-status:", err)
		os.Exit(1)
	}
	fmt.Println(st)
}

func usage(w io.Writer) {
	fmt.Fprint(w, `suricatoos-agent — agente de postura de vulnerabilidade (passivo/local)

uso:
  suricatoos-agent <comando>

comandos:
  inventory       coleta e imprime o inventário local (JSON)
  enroll          registra o agente no control plane (--server, --token [, --agent-id, --state, --ca-pin])
  run             loop de coleta + reporte outbound ([--ingest herdado do enroll] [, --state, --queue, --interval, --max-queue])
  install         instala o agente como serviço nativo ([--ingest herdado do enroll] [, --state, --interval, --max-queue])
  uninstall       remove o serviço nativo
  service-status  mostra o estado do serviço nativo
  version         mostra a versão do agente
  help            mostra esta ajuda
`)
}
