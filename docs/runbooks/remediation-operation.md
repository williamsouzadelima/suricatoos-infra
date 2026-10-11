# Runbook — Operar a remediação (patch + hardening sob aprovação)

Como **ligar**, **aprovar por ação**, **verificar** e **reverter** uma remediação de endpoint
(ADR-0010). O princípio é inegociável: **nada automático** — o agente só aplica uma correção que um
humano aprovou, numa janela, com rollback. (Histórico `autoRun` + Lei 12.737.)

## ⚠️ Estado atual (ler primeiro)

A remediação nasce **DARK** e em fatias. No momento deste runbook:

- **No ar (código):** backbone na nuvem (fila assinada, aprovação, CRL), gate nginx dark, e o agente
  **recebe/verifica/transaciona** jobs (verificação de assinatura + cliente poll/ack/report) e tem o
  **núcleo do executor** (3 portões). Tudo **desligado** por flag.
- **Ainda NÃO no ar:** os **handlers que ESCREVEM** no SO (WUA/winget/registro) e o **loop no agentd**
  que amarra poll→verify→executor→report. Essa é a fatia seguinte, validada **só em VM de LAB
  descartável**.

→ Ou seja: ligar as flags hoje **monta as rotas** mas **nenhuma correção é aplicada** até a fatia do
executor entrar. Este runbook é a **referência de operação do canário** — use-o quando o executor
estiver no LAB.

## TL;DR do ciclo

```
Finding ATESTADO ──(rascunho de IA opcional, Fase 4)──► job PENDING_APPROVAL
   └─ operador APROVA (por ação) ──► control-plane ASSINA ──► APPROVED
        └─ agente faz poll (mTLS) ──► VERIFICA assinatura+janela ──► EXECUTOR aplica (rollback capturado)
             └─ reporta APPLIED ──► nuvem re-scaneia ──► Ticket Open→Fixed→Fix Verified ──► VERIFIED
```

Nunca há salto de etapa: sem assinatura (sem aprovação) o agente não age; `APPLIED` **não** é o fim —
quem declara `VERIFIED` é a nuvem, após re-scan.

## 1. Ligar (dark → on) no host

Tudo mora no `.env` do control-plane no host (`/var/lib/suricatoos-cp/control-plane.env`) + a location
nginx já aplicada. **O dono roda isto no host** (merge/deploy = William).

1. **Chave de assinatura** (4ª chave, separada de CA/feed/update): gerada no 1º boot em
   `REMEDIATION_SIGN_KEY_FILE` (`/data/remediation-sign.key`, 0600). A pubkey vai ao agente no enroll
   (`remediation_pubkey`) — agentes já inscritos a recebem no próximo renew.
2. **Flags** no `.env` (nascem ausentes = desligado):
   ```
   REMEDIATION_ENABLED=true
   # REMEDIATION_JOBS_FILE=/data/remediation-jobs.json   # trocar o nome = perder a fila
   ```
3. **nginx**: garanta que o `default.conf` com a location `/agent/v1/remediation-jobs` (mTLS) está no
   volume e recarregado (`nginx -t && nginx -s reload`, ou recreate do container).
4. **Por tenant**: a remediação só vale para tenant com consentimento ligado (default off; só admin).

Recarregue o control-plane (`docker compose up -d --no-deps control-plane`). O log deve dizer
`remediation: fila de jobs HABILITADA (ADR-0010)`.

## 2. Enfileirar + aprovar (canário via admin-bearer)

Na Fase 3 (canário) o operador usa a **admin-API** (bearer). A UI `/remediation` vem na Fase 4. As
rotas de operador chegam pelo nginx em `/agent/api/v1/remediation/...` (reescreve para `/api/...` no
control-plane); o bearer é o `ADMIN_SECRET`.

> **Segredo:** leia o bearer de uma var/arquivo — **nunca** cole o valor literal em terminal/ticket/log.

**Enfileirar** um job (nasce `PENDING_APPROVAL`, **sem assinatura**, não-entregável):

```bash
curl -sS -X POST https://scanner.suricatoos.com/agent/api/v1/remediation/jobs \
  -H "Authorization: Bearer $ADMIN_SECRET" -H 'Content-Type: application/json' \
  -d '{
        "tenant":"<tenant>", "agent_id":"<cn-do-cert-do-host>",
        "type":"package_patch",
        "payload": {"source":"wua","id":"<UpdateID>","kb":"KB5041580"},
        "not_before":"2026-10-10T02:00:00Z", "not_after":"2026-10-10T04:00:00Z",
        "ttl":"24h"
      }'
```

**Aprovar** (é o portão humano — só aqui o job é **assinado** e vira `APPROVED`). Como o nginx **remove**
qualquer `X-Operator` do cliente, o aprovador vai no **corpo** (`approved_by`):

```bash
curl -sS -X POST https://scanner.suricatoos.com/agent/api/v1/remediation/jobs/<job_id>/approve \
  -H "Authorization: Bearer $ADMIN_SECRET" -H 'Content-Type: application/json' \
  -d '{"approved_by":"<operador>"}'
```

**Rejeitar** (descarta — **só antes da entrega**): vale para `PENDING_APPROVAL` e `APPROVED`, quando o agente
ainda não recebeu o job e nada aconteceu em nenhum host. Mesmo bearer e, pelo mesmo motivo (o nginx remove o
`X-Operator`), o operador vai no **corpo**, no campo `rejected_by` (`approved_by` continua aceito por
compatibilidade). Sem operador — nem `X-Operator` nem corpo — a resposta é `400`. O job vira `REJECTED` com
`rejected_by`/`rejected_at`; o aprovador (`approved_by`/`approved_at`) **não é alterado**. Id inexistente é
`404`. Rejeitar um job que **já está `REJECTED`** responde `204` sem mudar nada (ficam o primeiro
`rejected_by`/`rejected_at` e nada é logado: clique duplo ou reenvio não viram erro). **Qualquer outro
estado** — já entregue ao agente (`DELIVERED`, `ACKED`, `APPLIED`, `FAILED`) ou já final (`VERIFIED`,
`EXPIRED`, `CLOSED`) — é `409` e o job fica como está. Para um job já entregue use o `close` (§3).

```bash
curl -sS -X POST https://scanner.suricatoos.com/agent/api/v1/remediation/jobs/<job_id>/reject \
  -H "Authorization: Bearer $ADMIN_SECRET" -H 'Content-Type: application/json' \
  -d '{"rejected_by":"<operador>"}'
```

Depois de `APPROVED`, o agente do host-alvo (e **só** ele — escopo `CN==agent_id` + `O==tenant`) pega o
job no próximo poll, verifica a assinatura/janela e aplica **dentro da janela** (`not_before`/
`not_after`): antes da janela ele **adia**; depois dela, **recusa** (a aprovação não vale mais).

## 3. Verificar (fechar o ciclo)

- O agente reporta `APPLIED`/`FAILED` + `before`/`after` + `rollback_token`.
- Force o fechamento: dispare `scan_now` (runbook [agent-posture-and-rescan](agent-posture-and-rescan.md))
  → a correlação re-roda → o achado some → o **Ticket** do gvmd anda `Open → Fixed → Fix Verified`.
- `correlation_id` costura **job → finding → ticket**. `VERIFIED` é marcado **server-side** só após o
  re-scan; o agente nunca se auto-declara verificado.
- **Acompanhar:** `GET .../remediation/jobs` (bearer) lista os jobs do mais novo para o mais antigo, com o
  resultado reportado pelo agente (`result`). Filtros opcionais: `state` (ex.: `APPLIED`, `FAILED`),
  `tenant`, `agent_id`; `limit` (padrão 200, máximo 1000). O `payload` e o `nonce` **não** são
  devolvidos (só o `payload_sha256`): a listagem é um resumo técnico e enxuto, **não** uma fronteira de
  confidencialidade — quem tem o bearer já vê o payload nas respostas de enqueue/approve, e o `result`
  do agente (`detail`/`before`/`after`) pode repetir valores técnicos dele.

  ```bash
  curl -sS "https://scanner.suricatoos.com/agent/api/v1/remediation/jobs?state=APPLIED&tenant=<tenant>" \
    -H "Authorization: Bearer $ADMIN_SECRET"
  ```
- **Fechar:** com o re-scan confirmando o fix, marque o job `VERIFIED`. O operador vai no corpo
  (`verified_by`; o nginx remove o `X-Operator`) e o control-plane registra quem verificou no log:

  ```bash
  curl -sS -X POST https://scanner.suricatoos.com/agent/api/v1/remediation/jobs/<job_id>/verified \
    -H "Authorization: Bearer $ADMIN_SECRET" -H 'Content-Type: application/json' \
    -d '{"verified_by":"<operador>"}'
  ```

  Só um job `APPLIED` vira `VERIFIED`: outro estado → `409`, id inexistente → `404`, sem operador → `400`.
- **Expiração e limpeza:** o `expires_at` só vale **até o agente assumir o job** (`PENDING_APPROVAL`,
  `APPROVED` ou `DELIVERED` sem ack viram `EXPIRED`). `ACKED` e `APPLIED` **não expiram**: o relatório
  do agente ainda é aceito depois do prazo e um job aplicado segue verificável. Jobs terminais
  (`VERIFIED`/`FAILED`/`EXPIRED`/`REJECTED`/`CLOSED`) saem da fila no próximo enfileiramento quando o
  **último evento** deles tem mais de 7 dias — o último entre criação, rejeição, fechamento, resultado do
  agente e último relatório recusado: fechar um job antigo, ou um relatório que chega tarde, reinicia a
  contagem — **levando junto o `result` e os `late_reports`** (`before`/`rollback_token`), então anote o que
  precisar antes; um job `ACKED`/`APPLIED` parado **não** é limpo sozinho — feche-o você, com cuidado:
  - `APPLIED`: **prefira `verified`** (preserva o aprovador e o resultado). Use `close` só se o job não vai
    ser verificado (ex.: o fix foi revertido à mão, ou o host saiu de operação).
  - `ACKED` (o agente recebeu e sumiu): hoje o agente dá o `ack` **depois** de aplicar, então um `ACKED`
    parado costuma já ter sido aplicado, com só o relatório perdido. **Antes de fechar, confira no
    host do agente o `remediation.journal.json`** (no diretório de estado do agente, o mesmo da
    identidade do enroll): uma entrada com o `job_id` e `"status":"applied"` significa que o fix **já
    foi aplicado** — fechar só tira o job da fila, não desfaz nada. Sem entrada (ou com `failed`) não há
    registro de aplicação bem-sucedida, mas o journal é best-effort: na dúvida, confira o estado real do host.
  - `DELIVERED` sem ack: a fila reentrega até o `expires_at`. Se o agente não responde e você não quer
    esperar o prazo, `close`.
- **Rejeitar × fechar — qual usar:** o `reject` é para o job que o agente **ainda não recebeu**; o `close`,
  para o que ele **já recebeu** (ele pode estar aplicando, ou já ter aplicado, uma mudança — "rejeitado" seria
  falso). Nenhum dos dois mexe no host nem confirma o que o agente fez (só tiram o job da fila) e **nenhum
  apaga o aprovador** de uma mudança que foi assinada:

  | | `reject` (§2) | `close` |
  |---|---|---|
  | Estados aceitos | `PENDING_APPROVAL`, `APPROVED` | `DELIVERED`, `ACKED`, `APPLIED`, `FAILED` |
  | Estado final | `REJECTED` | `CLOSED` |
  | Quem / quando / por quê | `rejected_by`, `rejected_at` | `closed_by`, `closed_at`, `closed_reason` |
  | `approved_by` / `approved_at` | preservados | preservados |
  | `result` do agente (`before`, `rollback_token`) | não existe (nada foi entregue) | preservado |
  | Qualquer outro estado | `409`, o job fica como está (já `REJECTED`: `204` sem efeito) | `409`, o job fica como está |
  | Log do control-plane | uma linha por rejeição efetiva | uma linha por fechamento efetivo |

  **Fechar** — `POST …/remediation/jobs/<job_id>/close`, mesmo bearer. O operador vai no **corpo**
  (`closed_by`, obrigatório; o nginx remove o `X-Operator`) e, de preferência, o motivo (`reason`):

  ```bash
  curl -sS -X POST https://scanner.suricatoos.com/agent/api/v1/remediation/jobs/<job_id>/close \
    -H "Authorization: Bearer $ADMIN_SECRET" -H 'Content-Type: application/json' \
    -d '{"closed_by":"<operador>","reason":"<motivo>"}'
  ```

  Respostas: `200` com o job fechado — inclusive o `result` do agente, com `before`/`rollback_token`:
  **anote-os** —, `400` sem operador ou com `reason` acima de **1 KiB** (1024 bytes, contados depois de
  aparar), `401` sem o bearer, `404` id inexistente e `409` se o estado não permite
  (um job ainda não entregue é do `reject`; um job já final, `CLOSED` inclusive, não tem o que fechar). O
  control-plane grava **uma linha** por fechamento efetivo, com o estado anterior e o aprovador:
  `remediation: job <id> fechado por "<quem>" (estado anterior …; aprovador "<aprovador>" em …; motivo "…"; tenant="…" agent="…")`.
  `GET …/remediation/jobs?state=CLOSED` lista os fechados (com `closed_by`/`closed_at`/`closed_reason`). O
  `close` **não recolhe** o que o agente possa estar aplicando: para impedir um agente de agir, revogue o cert
  (§5); para desfazer o efeito, §4.
- **Relatório do agente que o job não aceita mais (`409`):** quando o job que o agente recebeu já tem o
  `result` dele — final (`VERIFIED`, `FAILED`, `CLOSED`) ou `APPLIED` — ou já está encerrado sem ele (`EXPIRED`
  depois da entrega, `CLOSED` antes do relatório, `REJECTED` de registro antigo), um relatório que **não é
  igual** ao gravado **nunca sobrescreve** o `result`: o control-plane responde `409` ao agente (no log do
  agente: `report respondeu 409`), deixa **uma linha** no log e **guarda o relatório inteiro no job**. Um
  **reenvio idêntico** do que já está gravado (mesmos `status`, `detail`, `before`, `after`,
  `rollback_token` e `reboot_pending`; o `reported_at` não conta) é `204` e não loga nem guarda nada. A linha
  de log — é assim que o operador fica sabendo — traz só o status, o estado e o número do relatório:

  ```
  remediation: relatório tardio recusado: job <id> está <ESTADO> e o agente reportou "<applied|failed>" (late_report #<n>; tenant="…" agent="…")
  ```

  **Onde está o relatório:** no próprio job, em `late_reports` — a listagem (`GET …/remediation/jobs`, com o
  bearer) e as respostas de `close`/`verified` o trazem com **tudo** que o agente mandou (`status`, `detail`,
  `before`, `after`, `rollback_token`, `reboot_pending`; `reported_at` é a hora em que o servidor o recebeu;
  nada é truncado, o corpo do relatório já é limitado a 256 KiB). O job guarda **no máximo 3**: o **primeiro**
  relatório recusado, **fixo** — costuma ser o `applied` de verdade, com o `rollback_token`/`before` reais —,
  e os **2 mais recentes**, que rodam (o mais antigo dos dois sai). `late_reports_total` diz quantos foram
  guardados, e daí sai o `#n` da linha de log: o primeiro é sempre o **`#1`**, o mais novo é o
  **`#late_reports_total`** e o do meio, quando há 3, é o `#late_reports_total − 1`. Um relatório **igual a um
  dos guardados** não é guardado de novo nem logado de novo: o agente recebe o mesmo `409`, que cita o número do
  que já está guardado — então um agente que reenvia sem parar não empurra os relatórios de verdade para fora.
  Um que já saiu da lista e volta é tratado como novo.

  **Atenção ao `#n` depois de uma queda:** se o control-plane cair entre um relatório recusado e a próxima
  gravação que dê certo, a linha de log saiu mas o relatório não chegou ao disco, e o seguinte reaproveita o
  número. Se o mesmo `#n` aparecer em duas linhas, o **horário** da linha de log e o `reported_at` do
  relatório guardado dizem de qual é cada um.

  ```bash
  curl -sS "https://scanner.suricatoos.com/agent/api/v1/remediation/jobs?tenant=<tenant>&agent_id=<cn-do-host>" \
    -H "Authorization: Bearer $ADMIN_SECRET"      # procure "late_reports" no job
  ```

  Um `applied` nessa linha quer dizer que o agente **aplicou uma mudança num job que a fila já dera por
  encerrado** — por exemplo, o job foi fechado enquanto o agente ainda aplicava, ou venceu (`EXPIRED`) antes de
  o `ack`/relatório dele chegar (o `ack` só vem depois de aplicar). **O que fazer:** (1) leia o
  `late_reports` do job: o `before`, o `after` e o `rollback_token` que o agente informou; (2) confira o host
  (o `remediation.journal.json`, no diretório de estado do agente, tem `"status":"applied"` para o `job_id` se a
  mudança foi feita — mas guarda só status e horário, nada de `before`); (3) decida se a mudança fica; (4) se
  não deve ficar, reverta **à mão** (§4) com esse `before`/`rollback_token`. O `result` do job continua sendo o
  do primeiro relatório. Num `APPLIED` o relatório diferente também é recusado e guardado, e o job continua
  `APPLIED` e verificável.

  **Relatório de um job que o agente nunca recebeu** (ainda `PENDING_APPROVAL`/`APPROVED`, ou `REJECTED`/
  `EXPIRED` antes de o poll entregá-lo): é `404`, **não** é um relatório tardio e **nada é guardado**. Mas o
  agente está reportando algo que nunca lhe foi dado — cert comprometido ou bug —, então o control-plane deixa
  uma linha **própria** (diferente da de cima), que vale uma investigação:

  ```
  remediation: relatório de job nunca entregue: job <id> está <ESTADO> e o agente reportou "<applied|failed>" (tenant="…" agent="…")
  ```

## 4. Reverter (rollback)

- O executor **captura o estado anterior** antes de aplicar (`Checkpoint-Computer` / valor de registro
  anterior) e devolve `rollback_token` + `before` no resultado.
- Reversão hoje é **assistida/manual** (restaurar o valor `before` / usar o System Restore do lote);
  desinstalação de KB é documentada, não automática.
- `before`/`rollback_token` só existem na nuvem no `result` do job ou, se o relatório foi recusado com `409`
  (§3), em `late_reports` (a listagem e a resposta do `close` mostram os dois); o journal do agente guarda só
  status e horário. Saem da fila com o job terminal, 7 dias depois do último evento dele (§3): anote o que
  precisar antes.
- Config sob **GPO/Intune/WSUS** (`HKLM\SOFTWARE\Policies`) **não** é corrigida localmente (o domínio
  reverteria) — o achado recomenda mudar a **política**. Isso evita o fix "que não cola".

## 5. Kill switches (parar tudo)

| Alcance | Como | Efeito |
|---|---|---|
| Global | `REMEDIATION_ENABLED=` (remover/false) + recreate | rotas de remediação não montam |
| Por tenant | desligar consentimento do tenant | nenhum job novo para aquele tenant |
| Por host/cert | **revogar o cert** (CRL) | o agente perde poll/ack/report (CRL fail-closed) |
| Por job | não aprovar / `reject` **antes da entrega** | sem assinatura, o agente não age; o `reject` recusa (`409`) um job já entregue, e o `close` (§3) o tira da fila e impede a reentrega, mas **não recolhe** o que o agente já esteja aplicando |

Nada é irreversível por acidente: um job vazado **sem aprovação** é inerte (não tem assinatura), expira
(`expires_at`) e o reaper o limpa.

## Checklist de segurança (antes de ligar em algo que não seja LAB)

- [ ] Alvo é **VM de LAB descartável** (canário) — **nunca** host de cliente na primeira vez.
- [ ] Janela de manutenção definida (`not_before`/`not_after`).
- [ ] Item de **alto raio** (SMBv1/NTLM/LSA/UAC/RDP) tem confirmação extra e rollback claro.
- [ ] `ADMIN_SECRET` lido de var/arquivo, nunca ecoado.
- [ ] Sabe reverter (`before`/`rollback_token`) antes de aprovar.
