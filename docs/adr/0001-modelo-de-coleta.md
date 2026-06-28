# 0001 — Modelo de coleta de vulnerabilidade

- **Status:** ACEITO (A1 + D1 confirmados em 2026-06-28)
- **Data:** 2026-06-28
- **Deciders:** William (mantenedor), Claude Code
- **Relacionado:** [0002-destino-dos-resultados](0002-destino-dos-resultados.md), [0003-linguagem-do-agente](0003-linguagem-do-agente.md)

## Contexto e problema

O agente precisa determinar a postura de vulnerabilidade de um endpoint **localmente**, sem
scanning de rede, com footprint mínimo e funcionando offline. Duas abordagens: correlação baseada
em pacote (modelo Notus) ou um mini-scanner local embarcado.

Fato verificado na stack viva: as advisories Notus são JSON em `/var/lib/notus/products/<produto>.notus`:
`{package_type:"rpm"|"deb", product_name, advisories:[{oid, fixed_packages:[{full_name, specifier}]}]}`.
O modelo Notus compara a lista de software instalado **direto** contra os pacotes vulneráveis — sem
rodar um VT por check ([Greenbone blog](https://www.greenbone.net/en/blog/notus/)).

## Opções consideradas

- **A1 — Correlação baseada em pacote (Notus).** Agente coleta inventário normalizado (`name-version-
  release.arch` + release do SO); correlação server-side compara com advisories.
  - 👍 Offline; footprint mínimo; reaproveita o feed Greenbone; alta fidelidade; sem probing.
  - 👎 Cobertura limitada a vulnerabilidades de pacote (não pega misconfig); **só há advisory Notus
    para Linux** (ver Decisão D).
- **A2 — Mini-scanner local embarcado.** Roda checks (config/CIS) no endpoint.
  - 👍 Mais cobertura (config).
  - 👎 Pesado; complexo de manter cross-platform; mais superfície de risco; mais perto de "scanner no
    endpoint" (tensão com o escopo passivo).

## Decisão

**A1** no núcleo da v1. Abrir um **gancho de plugin** para checks locais de config (CIS-like) como
extensão **opcional pós-v1**, mantendo o núcleo passivo e leve.

## Decisão D — Fonte de correlação cross-platform (descoberta na verificação)

As advisories Notus existem **só para distros Linux** (`rpm`/`deb`). Não há `.notus` para Windows nem
macOS. Logo:

- **D1 (recomendado):** v1 correlaciona **Linux via Notus**. Windows/macOS **coletam inventário**
  (Fase 3) mas a correlação fica **atrás da mesma interface**, plugando depois uma fonte adequada
  (CPE→NVD, ou os Local Security Checks de Windows do feed Greenbone). **Nunca fabricar achado** onde
  não há advisory.
- D2: correlação cross-platform via CPE→NVD/CVE já na v1 (engine maior, mais ruído, mais manutenção).
- D3: v1 Linux-only ponta-a-ponta (coleta Win/mac no roadmap).

## Consequências

- 👍 v1 entrega valor real e auditável no maior segmento (servidores Linux) reusando o feed.
- 👍 Não-fabricação preservada: achado ⇄ pacote coletado + OID da advisory.
- 👎 Cobertura Windows/macOS de **vulnerabilidade** fica para depois (a **coleta** vem na Fase 3).
- Interface de correlação isolada permite trocar/estender a fonte sem mexer no agente.

## A verificar antes da Fase 2 (per §13)

- Semântica de comparação de versão rpm vs deb (epoch, `~`, distro-specific) — fixar lib + vetores.
- Caminho OID → CVE/severity (metadata de VT no gvmd) — ver [ADR-0002](0002-destino-dos-resultados.md).
