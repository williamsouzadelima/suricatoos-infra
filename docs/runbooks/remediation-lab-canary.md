# Runbook — Validar o executor de remediação em LAB (canário e2e)

Como **preparar uma VM Windows descartável**, **semear achados reais**, **ligar a remediação dark**,
rodar a **matriz de teste do executor** e dirigir o **canário ponta-a-ponta** (detecção → aprovação →
aplicação → re-scan → `Fix Verified`).

> **Público-alvo:** quem **constrói/valida** a fatia do executor (os handlers que ESCREVEM no SO —
> WUA/winget/registro — e o loop no `agentd`). Para **operar** em produção veja
> [`remediation-operation.md`](remediation-operation.md). O contrato de job/assinatura está no
> **ADR-0010** e nos schemas `schema/remediation-*.schema.json`.

## ⚠️ Antes de tudo (inegociável)

- **Só VM de LAB descartável.** NUNCA um host de cliente, nunca a rede de cliente, nunca prod. A
  aplicação de patch/hardening **escreve no SO** — testá-la fora de um laboratório isolado e
  autorizado é exatamente o risco que a Lei 12.737 endereça.
- **Rede isolada.** A VM fica numa rede de laboratório sem rota para ativos de cliente. O único
  destino externo é o control-plane de LAB (ou um túnel dedicado), nunca o de produção.
- **Snapshot/checkpoint é a rede de segurança.** Tire um checkpoint **antes de cada corrida** e
  reverta ao fim. O rollback do próprio agente (`Checkpoint-Computer`) é testado AQUI justamente
  porque a VM é sacrificável.
- **Nada de credencial/segredo de prod.** Enrole com um bootstrap token de LAB; o `ADMIN_SECRET`
  é o do control-plane de LAB. Nunca cole tokens no terminal nem em arquivo versionado.

## 0. Pré-condições

| Item | Estado |
|---|---|
| PRs #108–#112 mergeados (backbone + wiring + agente verifica/transaciona + núcleo do executor) | necessário |
| **Handlers do executor** (WUA/winget/registro) + loop `poll→verify→executor→report` no `agentd` | **é o que este canário valida** — construir no LAB |
| VM Windows (edição com WUA/winget disponíveis; Server Core degrada winget — ver ADR-0010) | provisionar |
| Control-plane de LAB no ar com a 4ª chave (`REMEDIATION_SIGN_KEY_FILE`) | necessário |

## 1. Provisionar a VM e o baseline

1. Criar VM Windows na rede de LAB isolada. Instalar o agente pelo MSI (mesmo fluxo de enroll de
   produção, mas contra o control-plane **de LAB**).
2. Confirmar o enroll: o diretório de estado tem `remediation.pub` (PKIX PEM da 4ª chave,
   distribuída no enroll). **Sem `remediation.pub` o agente nunca age** — a feature fica inerte.
3. **Checkpoint `baseline-limpo`.** É para cá que você reverte entre corridas.

## 2. Semear achados reais (sem achado, nada a remediar)

O executor só tem o que exercitar se a detecção (Fase 0/1) produzir findings atestados. Semeie os dois
tipos, **deliberadamente**:

- **`package_patch` (MSRC/WUA):** deixe a VM com **um update faltando** — não rode o Windows Update
  até o fim, ou segure uma KB específica. O coletor WUA (`IsInstalled=0`) reporta `missing_updates[]`;
  a correlação MSRC gera um Finding de CVE com **severidade verbatim do MSRC** (nunca da IA).
- **`config_hardening` (CIS L1):** introduza **um** desvio que o ruleset **autoral** do servidor
  sinaliza — ex.: reabilitar SMBv1 no servidor
  (`Set-SmbServerConfiguration -EnableSMB1Protocol $true`). O coletor de postura reporta o
  `current_value`; o servidor compara com o `expected` e emite o Finding citando **só o número** da
  regra CIS L1 (ADR-0009). Não reproduza a prosa do benchmark.

Rode um ciclo de coleta e confirme no gvmd: um achado Windows de CVE **e** um de hardening, cada um
com evidência rastreável. **Anote o `correlation_id` de cada** — ele costura job→finding→ticket.

## 3. Ligar a remediação (dark → on), só no LAB

No `.env` do control-plane de LAB (as flags nascem `:-false`):

```
REMEDIATION_ENABLED=true
# REMEDIATION_SIGN_KEY_FILE=/data/remediation-sign.key   (4a chave; gerada no 1o boot, 0600)
# REMEDIATION_JOBS_FILE=/data/remediation-jobs.json       (fila 0600)
```

Recreate do control-plane + copiar o `default.conf` com a location `/agent/v1/remediation-jobs` para o
volume do nginx e recreate. **Fumaça do gate** (antes de qualquer job):

- `GET https://<lab-host>/agent/v1/remediation-jobs` **sem** cert cliente → **403** (mTLS exige
  `ssl_client_verify == SUCCESS`).
- Com o cert do agente de LAB → **200** com fila vazia. Confirma que o nginx **tira** `X-Operator`
  do cliente (`proxy_set_header X-Operator ""`).

## 4. Matriz de teste do executor (invariantes)

Cada linha é uma corrida a partir de um checkpoint limpo. **Reverter entre linhas.** O executor
retorna um `Outcome` ∈ {`Applied`, `Failed`, `Deferred`, `Skipped`} e **nunca** se auto-declara
`VERIFIED`.

| # | Handler | Estímulo | Resultado esperado |
|---|---|---|---|
| 1 | package_patch (WUA) | KB aprovada ainda não instalada | `Applied`; KB presente; reporta `APPLIED` |
| 2 | package_patch (WUA) | **re-entregar o mesmo job** (idempotência) | `Skipped` via journal; nenhuma 2a instalação |
| 3 | package_patch (winget) | `winget` ausente (Server Core) | degrada (`Failed`/`Skipped` claro); **nunca** dep dura |
| 4 | config_hardening (registro) | desvio sob `HKLM\SOFTWARE` não-política | `Applied`; valor corrigido; **estado anterior capturado** |
| 5 | config_hardening | chave sob `HKLM\SOFTWARE\Policies` (GPO/Intune/WSUS) | **recusa** (`Skipped`) + achado recomendando mudar a **política** — não brigar com `gpupdate` |
| 6 | qualquer | `now < not_before` | `Deferred` (fora da janela) — não aplica |
| 7 | qualquer | `now > not_after` ou `expires_at` vencido | recusa — não aplica |
| 8 | qualquer | assinatura adulterada / `agent_id` ou `tenant` trocado | **rejeita na verificação** (fail-closed), não chega ao handler |
| 9 | qualquer | `nonce` já visto (replay) | rejeita |
| 10 | qualquer | tipo desconhecido (`supported_types`) | **NACK explícito** (`FAILED`), nunca drop silencioso |
| 11 | qualquer | job durante self-update/reboot do agente | lock cruzado segura — **nunca** patch no meio do update |
| 12 | package_patch | update exige reboot | grava resultado **antes** do reboot; verificação **adiada** até o próximo collect; `BeginBoot`/`CommitIfHealthy` com auto-rollback por boot-count |

Portão: todas as linhas verdes (goldens de parse + idempotência no CI; e2e no LAB). Linhas 8–11 são
as de segurança — sem elas, o executor não sobe.

## 5. Canário ponta-a-ponta (caminho feliz)

Use o `correlation_id` do achado de CVE da §2. Operador usa o bearer `ADMIN_SECRET` do LAB
(`Authorization: Bearer $ADMIN_SECRET`, nunca materializado no terminal).

```
# 1. Enfileirar (nasce PENDING_APPROVAL, SEM assinatura)
POST /api/v1/remediation/jobs            {tenant, agent_id, type:"package_patch", payload{...}, correlation_id}

# 2. Aprovar por acao -> o control-plane ASSINA -> APPROVED  (X-Operator gravado p/ auditoria)
POST /api/v1/remediation/jobs/{id}/approve

# 3. Agente faz poll (mTLS) -> VERIFICA assinatura+janela+nonce -> ACK
GET  /agent/v1/remediation-jobs
POST /agent/v1/remediation-jobs/{id}/ack

# 4. EXECUTOR aplica (captura estado anterior p/ rollback) -> reporta
POST /agent/v1/remediation-jobs/{id}/report   {status:"applied", before, after}

# 5. Re-atestar: operador dispara re-scan; correlacao re-roda; o achado some
POST (command channel, admin)            {type:"scan_now"}
```

Transição esperada de estado:
`PENDING_APPROVAL → APPROVED → DELIVERED → ACKED → APPLIED → VERIFIED`.
No gvmd o Ticket vai **Open → Fixed → Fix Verified**. **`VERIFIED` é server-side**, só após o re-scan
confirmar — o agente para em `APPLIED`. Confirme também que, **sem** o passo 2 (aprovação), o poll do
passo 3 devolve fila vazia: sem assinatura o agente não age.

## 6. Exercício de rollback (obrigatório)

A partir de um checkpoint limpo, force uma falha de aplicação (ex.: KB que falha a instalar, ou um
`config_hardening` que quebra um serviço de teste):

- O handler captura o estado anterior **antes** de escrever; na falha, restaura (setting) ou aciona o
  `Checkpoint-Computer`/System Restore tirado antes do lote (patch).
- O agente reporta **`FAILED`** com evidência. O servidor **nunca** marca `VERIFIED`.
- Confirme que a VM volta ao estado pré-job e que um novo poll não re-tenta sozinho.

## 7. Teardown

1. Reverter ao checkpoint `baseline-limpo`.
2. **Revogar o cert do agente de LAB** (CRL) e confirmar que um poll subsequente falha fechado
   (`CRL fail-closed`) — valida o kill switch por-cert.
3. Destruir a VM. Não reaproveitar cert/estado de LAB em outra máquina.

## 8. Critérios de saída (antes de propor o executor para fora do LAB)

- [ ] Matriz da §4 **inteira** verde, com destaque para 8–11 (segurança) e 5 (recusa GPO).
- [ ] Canário da §5 fecha `Fix Verified` para **os dois** tipos (patch e hardening).
- [ ] Rollback da §6 restaura e reporta `FAILED` sem jamais `VERIFIED`.
- [ ] Gate da §3 nega sem cert e tira `X-Operator` do cliente.
- [ ] CRL corta jobs novos após revogação (§7).
- [ ] Revisão adversarial da fatia do executor (corretude, segurança, efeito real) registrada.
- [ ] Nenhum dado de cliente/empresa tocou o LAB; nada versionado ganhou IP/host/segredo real.

> Só depois disto a fatia do executor pode ser proposta para um piloto controlado — e ainda assim
> **dark, por-tenant, aprovação por ação**, como manda o ADR-0010.
