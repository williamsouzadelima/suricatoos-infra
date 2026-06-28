# 0003 — Linguagem do agente

- **Status:** ACEITO (C1 confirmado em 2026-06-28)
- **Data:** 2026-06-28
- **Deciders:** William (mantenedor), Claude Code
- **Relacionado:** [0001-modelo-de-coleta](0001-modelo-de-coleta.md), [0002-destino-dos-resultados](0002-destino-dos-resultados.md)

## Contexto e problema

O agente roda como serviço nativo em Windows, GNU/Linux e macOS (Intel + Apple Silicon), com footprint
baixo, distribuição assinada e instalação simples. A escolha de linguagem afeta entrega, manutenção e
interop futura com o stack Greenbone (que está sendo reescrito em Rust).

## Opções consideradas

- **C1 — Go.**
  - 👍 Binário estático único; cross-compilation trivial (GOOS/GOARCH) p/ os 3 SOs + arm64/amd64;
    ecossistema maduro p/ serviços de sistema (`kardianos/service` → systemd/launchd/Windows SCM;
    `golang.org/x/sys/windows/{registry,svc}`) e coleta (`shirou/gopsutil`); parsers de pacote do
    ecossistema Trivy (dpkg/rpm) reutilizáveis.
  - 👎 Não é a direção Rust do novo scanner da Greenbone (interop futura via API/REST, não via libs).
- **C2 — Rust.**
  - 👍 Alinhado ao novo stack Rust da Greenbone (openvasd); footprint/segurança excelentes.
  - 👎 Curva e velocidade de entrega maiores; tooling de serviço de SO menos "plug-and-play".

## Decisão

**C1 — Go** para o agente (entrega + manutenção cross-platform). A interop com o stack Greenbone se dá
por **API/protocolo** (GMP hoje, REST/openvasd amanhã), não por linkagem de bibliotecas — então a
direção Rust da Greenbone **não** obriga o agente a ser Rust.

**gmp-bridge em Python** (reusa `python-gvm` — ver [ADR-0002](0002-destino-dos-resultados.md)).
Control-plane e ingest em **Go** (um runtime a menos no plano de dados; reuso de libs do agente).

## Consequências

- 👍 Um binário por (SO, arch); pipeline de assinatura por SO bem suportado
  (codesign+notarytool no macOS, Authenticode/`signtool` no Windows, dpkg/rpm sign no Linux).
- 👍 Bibliotecas maduras para serviço, registro do Windows e fatos de host.
- 👎 Dois runtimes no servidor (Go p/ control-plane/ingest, Python p/ gmp-bridge) — aceitável; o
  Python fica confinado ao bridge.
- Reavaliar Rust só se a interop futura com o stack Greenbone pesar mais que a velocidade de entrega.
