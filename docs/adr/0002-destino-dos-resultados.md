# 0002 — Destino e correlação dos resultados

- **Status:** ACEITO (B1 confirmado em 2026-06-28)
- **Data:** 2026-06-28
- **Deciders:** William (mantenedor), Claude Code
- **Relacionado:** [0001-modelo-de-coleta](0001-modelo-de-coleta.md), [0003-linguagem-do-agente](0003-linguagem-do-agente.md)

## Contexto e problema

Os achados correlacionados precisam aparecer para o operador. Caminho de integração imediata: importar
no gvmd e exibir na GSA. Caminho de produto: collector próprio.

**Verificado contra fonte oficial** (não de memória):

- O método é **`import_report(report, task_id, *, in_assets=None)`** — `report` é o XML como string,
  `task_id` a UUID da task. **`create_report` NÃO existe** no python-gvm
  ([python-gvm gmpv224](https://greenbone.github.io/python-gvm/api/gmpv224.html)).
- Reports importados vão para uma **container task** ("a 'meta' task to import and view reports from
  other systems"), criada por **`create_container_task(name, comment)`**.
- Estrutura do report (código real do
  [gvm-tools/create-consolidated-report.gmp.py](https://github.com/greenbone/gvm-tools/blob/main/scripts/create-consolidated-report.gmp.py)):
  `<report><report id="uuid"><ports start max/><results start max><result>…</result></results></report></report>`;
  cada `<result>` carrega host/port/nvt(oid)/threat/severity/description.
- Chamada real: `gmp.import_report(combined_report, task_id=task_id, in_assets=True)`.
- gvmd deployado: **26.31.1**, GMP **v22.x**.

**Roadmap (verificado):** [openvasd](https://community.greenbone.net/blog/introducing-openvasd-and-a-performance-enhanced-notus-engine/)
(Rust) substitui ospd-openvas (OSP/XML → **REST HTTP**); GOS 24.10 já usa openvasd para local checks.

## Opções consideradas

- **B1 — Bridge GMP → gvmd.** Achados → report XML → `import_report` na container task → GSA.
  - 👍 Caminho mais curto até valor; aparece nos relatórios/GSA existentes; mecanismo **verificado**.
  - 👎 Acoplado ao GMP/gvmd; o stack do scanner está migrando p/ openvasd (REST).
- **B2 — Collector/ingest próprio.** Recebe inventários, correlaciona server-side, store próprio,
  opcionalmente sincroniza com gvmd.
  - 👍 Flexível, alinhado a produto/multi-tenant MSSP.
  - 👎 Mais código para manter; não reusa a GSA de imediato.

## Decisão

**B1** para a v1, com a **correlação e o landing isolados atrás de uma interface `ResultSink`**
(`Publish(findings) error`). Implementação inicial: `GmpReportSink` (Python + `python-gvm`:
`create_container_task` → `import_report`). Assim:

- v1 entrega valor rápido na GSA;
- **B2** (collector próprio) e **openvasd (REST)** viram implementações alternativas do `ResultSink`
  **sem reescrever o agente**.

**Linguagem do bridge:** Python (reusa `python-gvm` diretamente). O resto (agent, control-plane,
ingest) em Go — ver [ADR-0003](0003-linguagem-do-agente.md).

## Consequências

- 👍 Achados visíveis na GSA desde a Fase 2; reaproveita relatórios/assets/exports existentes.
- 👍 Troca de destino (B2/openvasd) sem tocar no agente.
- 👎 Uma container task por agente/grupo a gerenciar; mapear escopo↔task.
- 👎 Depende do enriquecimento OID→CVE/severity do gvmd (ver "A verificar").

## A verificar antes de codar o bridge (per §13)

1. DTD exato do `<result>` aceito por `import_report` na GMP 22.x (campos obrigatórios; formato de
   `port` `nnn/proto`; `threat` vs `severity`; `qod`).
2. Se o gvmd enriquece CVE/CVSS a partir do OID (metadata de VT do feed) ou se o report deve carregar
   `severity`/`cvss_base`. Plano: carregar ambos (defensivo).
3. Mapear o endpoint REST do openvasd como alvo futuro do `ResultSink`.
