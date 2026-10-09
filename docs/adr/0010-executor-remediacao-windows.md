# 0010 — Executor de remediação no endpoint (patch + hardening Windows, job assinado)

- **Status:** PROPOSTO (F2 backbone + F3a/b/c verificação, cliente e núcleo do executor implementados — tudo DARK; handlers que ESCREVEM no SO + canário em LAB pendentes)
- **Data:** 2026-10-09
- **Deciders:** William (mantenedor), Claude Code
- **Relacionado:** [0001-modelo-de-coleta](0001-modelo-de-coleta.md), [0003-linguagem-do-agente](0003-linguagem-do-agente.md), [0004-bootstrap-token](0004-bootstrap-token.md), [0007-sensor-scanner-interno](0007-sensor-scanner-interno.md), [0008-correlacao-windows-msrc](0008-correlacao-windows-msrc.md), [0009-hardening-cis-l1](0009-hardening-cis-l1.md)

## Contexto e problema

A plataforma **detecta** (Notus por pacote, MSRC por patch [ADR-0008], CIS L1 por misconfiguração
[ADR-0009]) mas o ciclo **não fecha**: o agente é passivo e o único comando que aceita é `scan_now`.
O dono quer gestão de vulnerabilidade **até a correção e a hardenização**, com a correção **aplicada
pelo agente**, assistida por IA — virar MSSP de ponta.

Isso **contradiz de propósito** o pilar do [ADR-0001](0001-modelo-de-coleta.md)/[0003](0003-linguagem-do-agente.md):
"endpoint passivo, só coleta; nunca executa". Um agente que **escreve** no SO é uma mudança de
postura de risco — por isso precisa de um ADR próprio e de guarda-corpos proporcionais. Dois fatos
pesam no desenho:

- **Histórico `autoRun`:** sondagem ativa sem consentimento já causou incidente. Nada pode ser
  automático.
- **Lei 12.737 (Brasil):** acesso/alteração não autorizada de sistema é crime. Toda escrita precisa
  de autorização explícita, por ação, rastreável.

## Decisão

1. **Aprovação por AÇÃO; nada automático.** Um job de remediação nasce `PENDING_APPROVAL` e só é
   **assinado quando um humano aprova** — a fila vazada sem aprovação é inerte (sem assinatura, o
   agente não age). Cada job roda numa **janela de manutenção**, grava **estado anterior para
   rollback** e reporta resultado. Itens de alto raio (SMBv1/NTLM/LSA/UAC/RDP) exigem confirmação
   extra. **A IA nunca decide, aprova, assina, nem origina achado/severidade** (ver §6).

2. **Job assinado, amarrado a UM agente (não-transplantável, não-replayável).** 4ª chave de
   assinatura por-propósito `suricatoos-remediation-v1` (separada de CA/feed/update). O *canonical*
   é **length-prefixed** (`chave=<len>:<valor>\n`, não um join por separador que não escapa campos) e
   cobre `schema_version|job_id|correlation_id|tenant|agent_id|type|approved_by|issued_at|not_before|
   not_after|expires_at|nonce|sha256(payload)`. Amarrar a `agent_id`+`tenant` mata uso cross-host;
   `nonce` single-use + `expires_at` matam replay; o payload entra só por SHA-256 (free-text não
   quebra o framing). A pubkey vai ao agente **no enroll** (`remediation_pubkey`), que a verifica com
   chave **separada da CA** — vazar uma não concede a outra. **Golden byte-a-byte CP↔agente** impede
   as duas implementações de divergirem.

3. **Fila durável na nuvem, com portão de aprovação e CRL fail-closed.** Estados super-set do
   `sensorjobs` ([ADR-0007]): `PENDING_APPROVAL→APPROVED→DELIVERED→ACKED→APPLIED→VERIFIED` (+`FAILED`/
   `EXPIRED`/`REJECTED`). **`APPLIED` NÃO é terminal** — a nuvem confirma por re-scan e só então marca
   **`VERIFIED` (server-side)**; o agente nunca se auto-declara verificado. Todo poll/ack/report é
   escopado à identidade do cert: **`CN == agent_id` E `O == tenant`** (um agente só vê o job dele;
   fora do escopo → 404). `revoked == nil` → nega (fail-closed). Reaper expira/limpa e impõe a janela.

4. **Executor ISOLADO no endpoint, com 3 portões antes de qualquer escrita.** O `agentd` continua
   poller/verificador: **verifica assinatura + janela de frescor (`VerifyAt`) ANTES de tudo**. A
   aplicação roda sob três portões de política — **single-flight** (nunca duas ao mesmo tempo),
   **janela de manutenção** (`not_before`/`not_after`), **idempotência** (journal em disco; só
   `APPLIED` suprime reaplicação) — e despacha por tipo: `package_patch` (WUA/`winget`) e
   `config_hardening` (registro/`secedit`/`auditpol`). Cada handler é **idempotente**, **captura o
   estado anterior** para rollback (`Checkpoint-Computer` antes do lote), **detecta reboot** e
   **não briga com GPO**: se a chave é gerida por política (WSUS/Intune/domínio), **recusa o fix
   local** e recomenda mudança de política. A escrita roda num **processo efêmero isolado**, não
   inline no serviço LocalSystem — afrouxar o unit principal transformaria um RCE no `agentd` em
   mutação arbitrária do SO.

5. **Transporte com gate dedicado; nasce DARK.** nginx expõe `/agent/v1/remediation-jobs` com **mTLS
   obrigatório**, encaminhando `X-Client-Cert-{DN,Verify,Serial}` (→ authz CN+O e CRL no
   control-plane) e **limpando qualquer `X-Operator`** forjado pelo cliente; as rotas de **operador**
   (enqueue/approve/reject) são admin-bearer e, na UI, sessão gsad (`auth_request`). Tudo nasce
   desligado: `REMEDIATION_ENABLED` global (dark), consentimento por tenant (só admin liga), kill
   switch por-cert (CRL).

6. **IA governada pelo padrão "reports", sem poder de decisão.** A partir de um `Finding` **já
   atestado**, a IA redige **apenas** rascunho de plano/explicação/priorização — entra **entre** o
   achado atestado e o `PENDING_APPROVAL`, e o humano revisa. **Nunca** origina achado/severidade,
   **nunca** aprova/assina. O serviço de IA **não tem acesso às chaves**. Pseudonimização do
   inventário/config antes de enviar, ZDR, região UE, orçamento mensal, consentimento por finalidade
   (default off).

7. **Verificação por re-scan (Tickets nativos).** `correlation_id` costura job→finding→ticket.
   Aplica → grava resultado **antes** de qualquer reboot → re-coleta + `scan_now` → a correlação
   re-roda → o achado some → Ticket do gvmd **Open→Fixed→Fix Verified**.

8. **LGPD.** O canal de remediação carrega apenas **estado técnico**: `job_id`/`correlation_id`,
   payload técnico (`kb`/`update_id`/`rule_ref`/`key`/`value`) e o resultado (`before`/`after`
   técnicos, `rollback_token` opaco). **Nenhum dado pessoal.** A redação de SID do [ADR-0009] já cobre
   a coleta de postura que origina os achados. Registrado em `docs/data-inventory.md`.

## Consequências

- 👍 Fecha o ciclo detecção→correção→hardenização: um achado Windows (CVE via MSRC ou desvio CIS L1)
  vira job assinado, aprovado por humano, aplicado por executor isolado, atestado por re-scan.
- 👍 A superfície de escrita é mínima e auditável: um job só aplica se **assinado + aprovado + dentro
  da janela + para este cert + não-replay + idempotente**; IA e operador têm papéis separados do
  signer.
- ⚠️ **É o primeiro código que ESCREVE no endpoint** — contradiz o ADR-0001 de propósito. Risco de
  quebrar serviço do cliente: mitigado por `rollback_token`+backup por item, health-check pós-apply,
  janela, **LAB primeiro**, allowlist de itens e confirmação extra em alto raio.
- ⚠️ **Signer comprometido = RCE de frota** (pior caso). Mitigado por amarração job↔agent+nonce+
  `CN==agent_id`, assinatura só pós-aprovação, chave do planner isolada, janela+rollback+CRL. Signer
  dentro do control-plane permanece como **residual aceito**.
- ⚠️ Operação multi-passo para ligar (flag global + consentimento por tenant + location nginx
  aplicada): de propósito, para não acender por engano.

## Opções rejeitadas

- **Aplicar automaticamente (autoRun).** Viola a decisão do dono, o histórico de incidente e a Lei
  12.737. Rejeitado: aprovação humana por ação, sempre.
- **A IA decidir/aprovar/originar achado.** Fabricação + decisão sem responsável. Rejeitado: IA só
  redige rascunho a partir de dado atestado; humano aprova; severidade vem da fonte.
- **O endpoint decidir o que aplicar.** Poria política de remediação na máquina do cliente (mesmo
  erro que o ADR-0009 evita no hardening). Rejeitado: a nuvem decide e assina; o endpoint só
  verifica e executa o que foi aprovado.
- **Reusar a chave da CA/update para assinar jobs.** Um vazamento cruzaria propósitos. Rejeitado: 4ª
  chave dedicada, com domínio de assinatura próprio.
- **Aplicar inline no serviço `agentd` (LocalSystem).** Transformaria um RCE no poller em mutação
  arbitrária do SO. Rejeitado: executor em processo efêmero isolado.
- **Join por separador no canonical (como update/feed).** Não escapa campos → ambiguidade de
  framing. Rejeitado: length-prefixed.

## Rollout

- **Fase 2 — backbone (CÓDIGO, dark):** fila durável `control-plane/remediation/` (job assinado,
  portão de aprovação, isolamento CN+O, reaper) — PRs #103/#105 + revisão adversarial #107 (na main);
  wiring Go dark + 4ª chave no enroll (#108) e gate nginx/compose dark (#109). **Zero prod.**
- **Fase 3a/3b — agente recebe + verifica + transaciona (SEM escrita):** `agent/internal/enroll`
  persiste `remediation_pubkey`; `agent/internal/remediate` com canonical/`Verify`/`VerifyAt`
  (golden CP↔agente) e cliente `PollJob`/`AckJob`/`ReportJob` que verifica inline (fail-closed) —
  PR #110.
- **Fase 3c — núcleo do executor (SEM escrita):** payloads tipados, journal de idempotência e o
  `Executor` com os 3 portões atrás da interface `Handler` — PR #111 (empilhado em #110).
- **Fase 3 (handlers) — primeira ESCRITA, gated por LAB:** handlers OS reais (WUA/`winget`/registro)
  idempotentes com captura de estado p/ rollback, processo isolado, lock cross-process vs self-update,
  reboot guard, e wiring no `agentd` (loop poll→verify→executor→report). **Canário em VM Windows de
  LAB descartável — NUNCA host de cliente.** Exige CI verde + LAB + revisão adversarial antes.
- **Fase 4 — IA governada + UI + endurecimento:** `remediation-planner` (OpenRouter, sem chaves),
  página GSA `/remediation` (aprovar por ação), Authenticode do MSI/binário, dual-control como
  evolução.
