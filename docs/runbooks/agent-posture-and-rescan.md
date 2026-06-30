# Runbook — Postura do endpoint (agente) e re-scan on-demand

Como responder, na GSA, "**este endpoint está vulnerável?**" e como "**rodar um
teste sempre que precisar**" para um host coberto pelo Suricatoos Agent.

## TL;DR

- **Postura do host** = página **Ativos → Hosts** (cada host tem severidade própria).
  O **Painéis** (Main Dashboard) também mostra, no topo, **"Hosts por Classe de
  Severidade"** + **"Hosts mais vulneráveis"**.
- **NÃO** use a página **Varreduras → Tarefas** para julgar a postura do agente:
  os achados do agente entram como **container task**, e o gvmd **não calcula
  severidade no nível da task** para container tasks → a task aparece como **N/D**.
  Isso é esperado, **não** é perda de dado (o report e o host têm a severidade).
- **Re-scan on-demand** = canal de comando `scan_now` (control-plane → agente faz
  poll mTLS → re-coleta e re-reporta em ≤ ~60s → a severidade do host atualiza).

## Por que a página "Tarefas" mostra N/D

O agente é **passivo/local**: ele coleta inventário e reporta *outbound*. Os
achados (correlação Notus) são importados no gvmd numa **container task**
`suricatoos-agent-<id>` (`config id=""`, `target id=""`). O gvmd só calcula a
severidade exibida na lista/donut de **Tarefas** para tarefas de scan reais; para
container tasks o campo `task.severity` fica **vazio** → a task cai em **N/D** no
donut "Tarefas por Classe de Severidade".

A severidade real continua presente:

| Objeto | Onde ver | Mostra |
|---|---|---|
| **Host asset** | Ativos → Hosts | severidade do host (ex.: `ubuntu2404-prod` = 9.8) |
| **Report** | Varreduras → Relatórios | severidade do report + breakdown (crítico/alto/médio) |
| **Resultados** | Varreduras → Resultados (filtre por `host=<id>`) | cada achado (NVT, CVSS, QoD, CVEs) |

Forçar a coluna/donut de **Tarefas** a mostrar severidade exigiria patchar o
`task_severity` do gvmd — fora de escopo. Use Hosts/Relatórios/Resultados.

## Ler a postura

1. **Painéis** (landing): a primeira row mostra **Hosts por Classe de Severidade**
   (donut) e **Hosts mais vulneráveis** (barras). Um agente com achados críticos
   aparece em **Crítico**.
   - Config persistida na user-setting `Main Dashboard Configuration`
     (`d97eca9f-0386-4e5d-88f2-0ed7f60c0646`); displays `host-by-severity-class`
     e `host-by-most-vulnerable`. Após mudar a setting, **recarregue** a página.
2. **Ativos → Hosts**: lista cada host com a severidade. Clique no host para o
   detalhe (identificadores, melhor SO, últimos resultados).
3. Detalhe dos achados: **Resultados** com filtro `host=<agent-id>` (ou abra o
   report mais recente do host).

> Mantenha a view de Hosts limpa: remova host assets de **teste/smoke**
> (`delete_host` via GMP) para que só agentes reais apareçam no painel.

## Re-scan on-demand ("rodar um teste agora")

O botão **play** do gvmd **não** dirige um agente passivo (ele re-escaneia a rede
do alvo, não o endpoint). O re-scan do agente é via **canal de comando**:

```bash
# Enfileira um scan_now para o agente <agent-id> (admin Bearer).
curl -H "Authorization: Bearer $ADMIN_SECRET" -X POST \
  https://scanner.suricatoos.com/agent/api/v1/agents/<agent-id>/commands
```

Fluxo: o agente faz **poll** do seu canal mTLS a cada `command-interval`
(default **60s**) → ao ver o `scan_now`, roda uma **re-coleta + report imediatos**
→ a correlação re-importa no gvmd → a **severidade do host asset atualiza**
(checar em Ativos → Hosts / abrir o novo report).

- `<agent-id>` = CN do certificado enrolado (ex.: `ubuntu2404-prod`), o mesmo nome
  que aparece como host/task no gvmd.
- Sem o comando, o agente já reporta no ciclo periódico (`--interval`, default
  **15min**); o `scan_now` apenas antecipa.
- O comando é **transiente** (fila em memória no control-plane): se o
  control-plane reiniciar antes do agente fazer poll, basta re-acionar.
- Identidade vem do cert mTLS (header `X-Client-Cert-DN` setado pelo nginx); um
  agente só vê/acka o **próprio** comando.

> Disponível a partir do merge+deploy do canal de comando (PR #36). Antes disso,
> o re-scan é o ciclo periódico de 15min (ou re-enroll/restart do serviço).

## Referências

- Deploy do control-plane/nginx: [`deploy-pipeline.md`](./deploy-pipeline.md)
- Spec do agente e do canal de comando: [`../PLAN.md`](../PLAN.md)
