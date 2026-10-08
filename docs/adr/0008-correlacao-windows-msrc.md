# 0008 — Correlação de vulnerabilidade no Windows (MSRC)

- **Status:** PROPOSTO (P0a — contrato de inventário — implementado)
- **Data:** 2026-10-08
- **Deciders:** William (mantenedor), Claude Code
- **Relacionado:** [0001-modelo-de-coleta](0001-modelo-de-coleta.md), [0002-destino-dos-resultados](0002-destino-dos-resultados.md), [0009-hardening-cis-l1](0009-hardening-cis-l1.md), [0010-executor-remediacao-windows](0010-executor-remediacao-windows.md)

## Contexto e problema

O [ADR-0001](0001-modelo-de-coleta.md) fixou correlação por pacote (Notus), mas **só há advisory
Notus para Linux** (deb/rpm). Hoje o agente no Windows coleta aplicativos do registro
(`HKLM\...\Uninstall`) e **nada correlaciona** → um host Windows não gera nenhum achado de
vulnerabilidade. Com o Windows eleito como primeiro alvo da gestão ponta-a-ponta
(detecção → correção → hardening), precisamos de uma **fonte de detecção Windows autoritativa**,
sem violar o princípio de não-fabricação (ADR-0001 D1: "sem evidência, o achado não existe").

## Decisão

1. **Fonte de achado = correlação MSRC server-side ("Notus para Windows").** O agente coleta o
   **nível exato de patch** (`os.build` + `os.ubr`, ex. `19045.4291`) e os **KBs instalados**; um
   novo `MSRCCorrelator` (server-side, implementando a mesma interface `Correlator` de
   `correlation/`) compara contra o feed **MSRC CVRF/CSAF** e emite o achado quando o KB que corrige
   o CVE (ou um supersedente) **não** está presente. **CVE e severidade vêm do MSRC**
   (`severity_origin: "msrc-cvrf"`), nunca do agente nem de IA.
2. **WUA como evidência corroborante e futuro motor de remediação.** O agente também coleta os
   **updates faltantes** pelo Windows Update Agent (`IUpdateSearcher.Search("IsInstalled=0")`):
   KB, título, severidade MSRC, se exige reboot, origem (Microsoft Update vs WSUS). Isso corrobora a
   correlação e, no [ADR-0010](0010-executor-remediacao-windows.md), vira o motor de instalação.
3. **Dispatch por família de SO.** Um multiplexador seleciona o correlator por `inv.OS.Family`:
   `windows` → `MSRCCorrelator`; `linux` → Notus (inalterado). Zero regressão no caminho deb/rpm.
4. **OID.** O `finding.schema.json` exige OID numérico. Mapeamos ao OID do NVT Windows LSC do feed
   Greenbone quando existir; senão cunhamos um OID estável no **arco privado já em uso**
   (`1.3.6.1.4.1.55683...`) e carregamos `cve[]`+`severity` no próprio report (plano defensivo do
   `docs/PLAN.md` §11), já que o gvmd não enriquece OID fora do feed.
5. **Contrato aditivo + compatibilidade.** O inventário sobe para `schema_version` **1.1.0**
   (MINOR): novos campos opcionais `os.build`, `os.ubr`, `facts.installed_kbs`,
   `facts.missing_updates`, `facts.management`. O `ingest` passa a aceitar **qualquer `1.x`**
   (`ingest.schemaCompatible`, match por major) — antes era igualdade exata, que quebraria a frota
   nos dois sentidos. O `ComputeCycleHash` passa a cobrir `os.build/ubr` e os `missing_updates`
   (senão um host que corrige deduplicaria e o achado nunca sumiria).

## Como chamar a WUA (restrição stdlib-only + CGO_ENABLED=0)

O agente só pode depender da stdlib + `golang.org/x/sys` ([ADR-0003](0003-linguagem-do-agente.md)) e
compila com `CGO_ENABLED=0`. Portanto **não** adotamos `go-ole` (dependência COM nova). A WUA é
chamada por um **wrapper PowerShell** via `os/exec`
(`powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand <script fixo>` →
`Microsoft.Update.Session` → `ConvertTo-Json`): puro-stdlib, sem CGO, trivial de mockar por
campo-função (estilo `enumKeys` em `inventory/windows/registry.go`). Processo-filho matável +
timeout de contexto + circuit-breaker, em cadência própria (nunca bloqueia o loop de coleta). A
migração para COM direto via `x/sys` fica documentada como opção futura (evasão de EDR/AMSI).

## Consequências

- 👍 Windows passa a ter detecção de vulnerabilidade real, ancorada em fonte autoritativa, sem
  fabricar nada e sem scanning de rede no endpoint.
- 👍 O bump é retrocompatível: a frota 1.0.0 segue aceita; agentes 1.1.0 coexistem.
- ⚠️ **Ordem de deploy:** o `ingest` (que aceita `1.x`) deve ser deployado **antes** de rolar
  agentes para 1.1.0 — senão um agente 1.1.0 bateria num ingest antigo (igualdade exata) e levaria
  400. Dentro deste PR as duas pontas já são consistentes.
- ⚠️ No upgrade para 1.1.0 o `cycle_hash` muda para **todo** host (a linha "os" ganhou dois campos),
  causando **exatamente um** re-import por host. Benigno e esperado.
- ⚠️ Exige estender o `feed-updater` para espelhar o feed MSRC CVRF/CSAF (fase seguinte).

## Opções rejeitadas

- **`winget upgrade` como fonte de achado.** "Desatualizado" ≠ "vulnerável" → viraria fabricação.
  `winget` fica só como *enriquecimento* de inventário (versão disponível) e, no ADR-0010, como
  *executor* de apps de terceiros — nunca origina achado sozinho.
- **`go-ole`/COM direto agora.** Dependência nova que contraria o ADR-0003; adiado.
- **Igualdade exata de `schema_version` mantida + sem bump.** Quebraria a frota ou barraria os campos
  novos; rejeitado em favor do match por major.

## Rollout

- **P0a (este PR):** contrato de inventário 1.1.0 (struct + schema + `ComputeCycleHash`) + `ingest`
  major-compatível + testes + LGPD (`data-inventory.md`). **Zero escrita, zero coleta nova ainda.**
- **P0b:** coletores Windows (WUA missing-updates, build/UBR, KBs, postura de gestão) com golden de
  parse; testes em `windows-latest` no CI.
- **P0c:** `MSRCCorrelator` + dispatch por SO + extensão MSRC do `feed-updater` + mapeamento no
  `gmp-bridge` → primeiros achados CVE Windows no gvmd.
