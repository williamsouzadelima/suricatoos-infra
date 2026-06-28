# Suricatoos Agent

Agente de endpoint cross-platform (Windows, GNU/Linux, macOS) que coleta a postura de
vulnerabilidade **localmente** e a entrega ao plano central de forma autenticada e outbound.
**Passivo/local — nunca escaneia outros hosts.** Visão geral em [`docs/PLAN.md`](../docs/PLAN.md).

## Layout

```
cmd/suricatoos-agent/   entrypoint (CLI: enroll, run, version)
internal/
  inventory/            schema (fonte da verdade) + Collector; linux|darwin|windows
  enroll/               bootstrap token + CSR -> cert mTLS         [Fase 1]
  transport/            cliente outbound + fila offline            [Fase 1]
  service/              systemd / launchd / Windows SCM            [Fase 1/3]
  update/               auto-update assinado + rollback            [Fase 4]
  version/              metadata de build (via -ldflags)
```

O payload é definido por [`schema/inventory.schema.json`](../schema/inventory.schema.json),
espelhado por `internal/inventory` (Go). Mude os dois juntos.

## Desenvolvimento

```sh
cd agent
go build ./...
go test ./...
go vet ./...
gofmt -l .              # deve imprimir vazio
go run ./cmd/suricatoos-agent version
```

Cross-compile (binário estático único por SO/arch):

```sh
GOOS=linux   GOARCH=amd64 go build -o dist/suricatoos-agent-linux-amd64        ./cmd/suricatoos-agent
GOOS=windows GOARCH=amd64 go build -o dist/suricatoos-agent-windows-amd64.exe  ./cmd/suricatoos-agent
GOOS=darwin  GOARCH=arm64 go build -o dist/suricatoos-agent-darwin-arm64       ./cmd/suricatoos-agent
```

## Status

Fase 0 (fundações). Os comandos `enroll`/`run` ainda são stubs (Fase 1). CI cross-platform em
`.github/workflows/agent-ci.yml`.
