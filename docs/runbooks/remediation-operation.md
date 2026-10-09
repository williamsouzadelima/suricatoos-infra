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

**Rejeitar** (descarta): `POST .../remediation/jobs/<job_id>/reject` (mesmo bearer; aprovador no corpo).

Depois de `APPROVED`, o agente do host-alvo (e **só** ele — escopo `CN==agent_id` + `O==tenant`) pega o
job no próximo poll, verifica a assinatura/janela e aplica **dentro da janela** (`not_before`/
`not_after`): antes da janela ele **adia**; depois dela, **recusa** (a aprovação não vale mais).

## 3. Verificar (fechar o ciclo)

- O agente reporta `APPLIED`/`FAILED` + `before`/`after` + `rollback_token`.
- Force o fechamento: dispare `scan_now` (runbook [agent-posture-and-rescan](agent-posture-and-rescan.md))
  → a correlação re-roda → o achado some → o **Ticket** do gvmd anda `Open → Fixed → Fix Verified`.
- `correlation_id` costura **job → finding → ticket**. `VERIFIED` é marcado **server-side** só após o
  re-scan; o agente nunca se auto-declara verificado.

## 4. Reverter (rollback)

- O executor **captura o estado anterior** antes de aplicar (`Checkpoint-Computer` / valor de registro
  anterior) e devolve `rollback_token` + `before` no resultado.
- Reversão hoje é **assistida/manual** (restaurar o valor `before` / usar o System Restore do lote);
  desinstalação de KB é documentada, não automática.
- Config sob **GPO/Intune/WSUS** (`HKLM\SOFTWARE\Policies`) **não** é corrigida localmente (o domínio
  reverteria) — o achado recomenda mudar a **política**. Isso evita o fix "que não cola".

## 5. Kill switches (parar tudo)

| Alcance | Como | Efeito |
|---|---|---|
| Global | `REMEDIATION_ENABLED=` (remover/false) + recreate | rotas de remediação não montam |
| Por tenant | desligar consentimento do tenant | nenhum job novo para aquele tenant |
| Por host/cert | **revogar o cert** (CRL) | o agente perde poll/ack/report (CRL fail-closed) |
| Por job | não aprovar / `reject` | sem assinatura, o agente não age |

Nada é irreversível por acidente: um job vazado **sem aprovação** é inerte (não tem assinatura), expira
(`expires_at`) e o reaper o limpa.

## Checklist de segurança (antes de ligar em algo que não seja LAB)

- [ ] Alvo é **VM de LAB descartável** (canário) — **nunca** host de cliente na primeira vez.
- [ ] Janela de manutenção definida (`not_before`/`not_after`).
- [ ] Item de **alto raio** (SMBv1/NTLM/LSA/UAC/RDP) tem confirmação extra e rollback claro.
- [ ] `ADMIN_SECRET` lido de var/arquivo, nunca ecoado.
- [ ] Sabe reverter (`before`/`rollback_token`) antes de aprovar.
