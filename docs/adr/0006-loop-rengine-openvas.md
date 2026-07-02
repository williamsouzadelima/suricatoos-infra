# 0006 — Loop reNgine (score) ↔ OpenVAS/GSA (scanner)

- **Status:** PROPOSTO (2026-07-01)
- **Deciders:** William (mantenedor), Claude Code
- **Relacionado:** [0002-destino-dos-resultados](0002-destino-dos-resultados.md), [0004-bootstrap-token](0004-bootstrap-token.md)

## Contexto e problema

Temos duas caixas de produção, ambas públicas em `:443` e endurecidas:

- **score** = `172.233.13.124` = `score.suricatoos.com` = fork do reNgine (`suricatoos-scan`,
  on-box `/root/suricatoos`). Faz **recon/superfície de ataque** (subdomínios → IPs → portas → endpoints,
  nuclei). Django + celery.
- **scanner** = `172.233.11.97` = `scanner.suricatoos.com` = stack Greenbone/GVM (gvmd 22.7) +
  `suricatoos-infra` (control-plane, ingest, gmp-bridge). Faz **scan de vulnerabilidade de rede
  profundo** (OpenVAS).

**Objetivo (decidido pelo mantenedor):** loop **bidirecional completo, disparado automaticamente ao
concluir o scan de recon**. O reNgine termina a recon → empurra os hosts/portas vivos para o scanner →
o GSA lança um scan OpenVAS real → os achados voltam para o reNgine como `Vulnerability`, alimentando o
score em `score.suricatoos.com`.

Hoje **não existe** integração em nenhuma direção (a menção a "OpenVAS (Nessus)" no `tasks.py` do reNgine
é um stub morto do parser de vulscan). O `gmp-bridge` atual só **importa achados** no gvmd
(`create_container_task` + `import_report`); ele **não lança scans**.

O problema difícil não é a plumbing — é a **segurança**. A premissa é adversária: **o alvo é dono do
próprio DNS**, então os "hosts vivos" que o reNgine descobre são **influenciáveis pelo atacante**. Um
alvo pode apontar um hostname (ou `*.evil.com`) para **qualquer IP** e induzir o scanner a atacar
ativamente uma vítima terceira (abuso/responsabilidade legal partindo do IP público do Suricatoos), o
metadata da Linode (`169.254.169.254`), as caixas irmãs (`.89`/`.124`) ou vizinhos RFC1918.

## Opções consideradas

### Onde vive o endpoint de lançamento

- **Reusar o container `ingest` existente (escolhido).** Ele já carrega `python-gvm`, `bridge.py`,
  `GVM_PASSWORD` (via `ingest.env`), o mount do socket `gvmd.sock`, o volume persistente
  `ingest_state:/data`, e fica atrás da location `/ingest/` **mTLS** (que já encaminha
  `X-Client-Cert-DN`/`X-Client-Cert-Verify`).
  - 👍 **Zero serviço novo**; uma imagem para rebuildar + `save/load`; menor superfície de rollback;
    menos ações autorizadas em prod.
  - 👎 Concentra scan-ativo + ingest-passivo no mesmo processo (mitigado isolando o código).
- **Novo serviço `scan-orchestrator` dedicado.** Arquiteturalmente mais limpo, isola blast radius.
  - 👎 **Dobra o foothold gvmd-admin** (2º container com senha + socket), exige novo pacote GHCR + CI +
    **nova location nginx na caixa pública** (um reload ruim = outage do scanner inteiro, inclusive GSA).

### Modelo de controle

- **Caminho de request fino + 1 reconciler serializado (escolhido).** O `POST` só **persiste um job**;
  uma única goroutine reconciladora é dona de launch/status/fetch/estado.
  - 👍 Mata as corridas TOCTOU (contar-então-iniciar, achar-então-criar); state machine explícita;
    caminho DELETE de kill; `request_id` inforjável (fecha IDOR); cooldown de rescan por alvo.
- **Lançar síncrono no handler HTTP.** Mais simples, porém tem corrida de duplo-launch e estouro de
  concorrência.

### Identidade gvmd nos lançamentos

- **Usuário dedicado `suricatoos-scan` (role=User) + admin enxerga tudo (escolhido).** Cria um usuário de
  baixo privilégio só para gerenciar targets/tasks/reports, **não** admin (não mexe em feeds/usuários).
  Concede ao admin uma **permissão `Super`** sobre esse usuário para que as tasks **apareçam na GSA**.
  - 👍 Menor foothold de credencial (pedido do revisor adversário) **e** visibilidade unificada na GSA.
  - 👎 Um passo extra de config no gvmd (criar usuário + permissão).
- Rodar como `admin`: visível na GSA de graça, mas reusa a credencial admin no caminho de scan ativo
  (foothold maior).

### Caminho de retorno (scanner → score)

- **PULL pelo reNgine (escolhido).** O reNgine (celery-beat) faz poll do estado do job pelo mesmo canal
  mTLS; o `ingest` devolve os achados já parseados/cacheados quando `COMPLETED`. Mantém o reNgine como
  orquestrador; não exige expor endpoint inbound no reNgine; GET fica rápido (sem round-trip no gvmd).
- **PUSH/callback do GSA para o reNgine.** Mais peças (endpoint no reNgine + auth + cert GSA→reNgine).

## Decisão

**Híbrido:** footprint do "menor blast radius" (reusar o `ingest`) + modelo de controle "produto limpo"
(request fino + reconciler serializado + state machine + kill switch), com os controles transversais que
nenhum dos dois cravou sozinho. O código de scan-ativo fica **isolado** num CLI Python novo
(`scan_bridge.py`) e num pacote Go distinto (`ingest/scanlaunch/`) compilado no **mesmo** binário do
ingest — recuperando a modularidade **sem** um segundo deployable e **sem** um segundo foothold admin.
`bridge.py` e a máquina de enroll/CA ficam **inalterados**.

**Chave de correlação** = `scan_history_id` do reNgine, embutida no **nome da task** GVM
`suricatoos-rengine-{id}` (gvmd = fonte da verdade; sobrevive a restart do ingest). O id **externo** é um
`request_id` (UUID) inforjável — nunca o inteiro — fechando IDOR.

### Arquitetura — trace ponta a ponta

```
 score .124 (reNgine)                          scanner .97 (GVM)
 ────────────────────                          ─────────────────
 task report (scan concluído)
   └─ push_to_scanner ──POST /ingest/v1/scan-request──▶ nginx (mTLS)
        (cert cliente mTLS)                        └─▶ ingest:scanlaunch
                                                        · verify SUCCESS + O=score-hub/OU=scan-requester
                                                        · checagem de serial na CRL (fail-closed)
                                                        · allowlist de IP DEFAULT-DENY
                                                        · persiste job (PENDING), retorna {request_id}
                                                            │
                                              reconciler (1 goroutine, serializada)
                                                → scan_bridge.py launch (create_target→create_task→start_task)
                                                → status… → em Done: fetch+parse 1x → cacheia, COMPLETED
 poll_scanner_jobs (beat */2m)
   └─ GET /ingest/v1/scan-request/{id} ◀────── retorna estado (+achados quando COMPLETED)
        └─ import_openvas_findings → Vulnerability(source="openvas") → score
```

1. Na **score**, a task terminal do chord — **`report`** (`web/Suricatoos/tasks.py` L441) — roda com
   `scan_id`/`engine_id`/`subscan`/`status` no contexto e chama `send_scan_notif.delay(...)`.
2. Guardado por `not subscan and status == SUCCESS_TASK and Domain.send_to_scanner and tem-hosts-e-portas`,
   dispara `push_to_scanner.delay(scan_id, engine_id)` (não-bloqueante).
3. `push_to_scanner` monta o payload de `ScanHistory → Subdomain.ip_addresses → IpAddress.address →
   ports → Port.number`, **mantendo só IP-literais públicos** (dropa CDN/privados/fora de escopo), faz
   `ScanBridgeJob.get_or_create(scan_history=…)` e faz `POST` com o cert mTLS.
4. **nginx** exige `ssl_client_verify==SUCCESS`, encaminha `$ssl_client_s_dn`, `$ssl_client_verify` e
   **`$ssl_client_serial`** (novo), limpa `X-Suricatoos-UI`, proxya para `ingest:9090`.
5. **ingest** `scanlaunch`: valida verify + DN exato (`O=score-hub` **e** `OU=scan-requester`) + serial
   ∉ CRL (fail-closed) + todo host é IP-literal na allowlist + caps + cooldown; **find-or-create**
   idempotente do job por `(tenant, scan_history_id)`; persiste `PENDING`; devolve `201 {request_id}`.
6. A **reconciler serializada** pega o `PENDING`, e havendo slot livre (`SCAN_MAX_CONCURRENT`), roda
   `scan_bridge.py launch`: `create_target` (IPs, `port_range="T:<portas>"`, `alive_test`) →
   `create_task` (Full-and-fast, OpenVAS Default) → `start_task`. Job → `RUNNING`.
7. OpenVAS roda o scan real contra os hosts/portas descobertos.
8. A reconciler faz `status` (`get_tasks`); em `Done` roda `fetch` (`get_report details=True`) **1 vez**,
   normaliza, cacheia em `/data/findings/{request_id}.json`, job → `COMPLETED`.
9. Na **score**, o beat `poll_scanner_jobs` (a cada 2 min, single-flight no redis) faz `GET
   /ingest/v1/scan-request/{request_id}`; o ingest devolve o estado cacheado (+ `findings` inline quando
   `COMPLETED`) — **rápido**, sem round-trip no gvmd no caminho de request.
10. `import_openvas_findings` mapeia CVSS→severity, host→`Subdomain`/`target_domain` (**só hosts em
    escopo**), NVT→`CveId`; faz `update_or_create` de `Vulnerability`; marca `imported=True`.
11. Esses `Vulnerability` alimentam o score exatamente como as vulns nativas do reNgine. Loop fechado.

### Postura de segurança (a parte que sustenta o risco)

Todos os controles são **do lado scanner** e **default-deny**:

| Ameaça | Controle |
|---|---|
| Scan de vítima arbitrária / metadata `169.254.169.254` / prod irmã (.89/.124) / RFC1918 | **Só IP-literais** (`net.ParseIP`; hostname → `422`), então o gvmd **nunca re-resolve** (mata DNS rebinding em tempo de scan) + **deny-list** (loopback/link-local/metadata/RFC1918/multicast/self+irmãs, incl. IPv6) + **allowlist nasce vazia = deny-all** (/32s por engagement, adicionados explicitamente) |
| Cert vazado/comprometido | nginx encaminha `$ssl_client_serial` → ingest checa a **CRL do control-plane, fail-closed** (revoke = kill de verdade, o que hoje **não** é enforced) + cert de TTL curto na P5 |
| Cert de agente de baixo privilégio reusado como launcher (CA compartilhada) | match **exato** `O=score-hub` **E** `OU=scan-requester` (parse RFC2253, não substring) + `X-Client-Cert-Verify==SUCCESS` |
| DoS do scanner por tempestade de auto-trigger | 1 reconciler serializada, `SCAN_MAX_CONCURRENT=2`, **cooldown de rescan 6h** por alvo, rate-limit nginx `12 r/m`, `SCAN_MAX_DURATION=6h` → auto-stop |
| Corrida de duplo-launch (TOCTOU) | `POST` só persiste; **só a reconciler** lança; find-before-create + reserva atômica de slot |
| Envenenamento do score (achado fora de escopo atribuído à vítima) | import atribui um achado **só se o host mapeia para um `IpAddress` daquela `ScanHistory`**; senão quarentena (nunca atribuição em bloco) |
| Blast radius do gvmd | usuário dedicado **`suricatoos-scan` role=User** (não admin) nos lançamentos; admin recebe **permissão `Super`** sobre ele → visível na GSA |

## Plano de implementação (mudanças por repo)

### `suricatoos-infra` → scanner (.97)

- **NOVO `gmp-bridge/scan_bridge.py`** (irmão do `bridge.py`, reusa `_assert_ok`/`_extract_id`/
  `_esc_filter`/`_find_task_id`): CLI `launch|status|fetch|stop`, lê um **arquivo JSON de request**
  (nunca um arg gigante de `--hosts`), re-valida IP-literal com `ipaddress`, todo XML GVM via objetos de
  request do python-gvm (`Targets`/`Tasks`/`Reports`/`Tags`) — nunca `send_command` com string. +
  `test_scan_bridge.py`.
- **NOVO pacote Go `ingest/scanlaunch/`** (compilado no binário do ingest): `service.go` (rotas, fino),
  `authz.go` (parse DN exato), `allowlist.go` (default-deny), `crl.go` (ticker CRL 5min, fail-closed),
  `registry.go` (`/data/scan-requests.json`, escrita atômica temp+rename), `reconciler.go` (1 goroutine:
  launch/status/fetch/state machine), `exec.go` (runner temp-JSON + arg-vector) + `*_test.go`.
- **Editado (pouco):** `ingest/server.go` (~6 linhas: `*scanlaunch.Service` opcional),
  `ingest/cmd/ingest/main.go` (lê env `SCAN_*`, sobe reconciler+CRL), `ingest/Dockerfile` (COPY do
  `scan_bridge.py`), `compose/nginx/default.conf` (nova `location /ingest/v1/scan-request` **acima** de
  `/ingest/`, encaminha `$ssl_client_serial`; a `/ingest/` atual fica **intacta**),
  `compose/docker-compose.override.yml` (env `SCAN_*` no ingest; `ingest_state:/data` já montado).
- **control-plane:** sem mudança de código no MVP (o token `score-hub`/`scan-requester` é mintado
  operacionalmente). TTL curto por policy = P5.
- **Docs:** este ADR + runbook `docs/runbooks/loop-rengine-openvas.md` (criar usuário gvmd + permissão
  Super, kill switch, rollout/rollback, rotação de cert).

### `suricatoos-scan` (reNgine) → score (.124)

- `web/startScan/models.py` — novo `ScanBridgeJob` (OneToOne `ScanHistory`; `request_id`, `gvm_task_id`,
  `state`, `submitted_at`, `completed_at`, `imported`, `error`, `hosts_sent`) + `Domain.send_to_scanner`
  (bool) + migração (ambos **aditivos**).
- `web/Suricatoos/tasks.py` — novas tasks `push_to_scanner`, `poll_scanner_jobs`,
  `import_openvas_findings`; hook guardado na `report` (L441).
- `web/Suricatoos/scanner_bridge.py` — cliente mTLS (`requests`, `cert=(crt,key)`, `verify=ca`), builder
  de payload (filtro de IP público), `cvss_to_rengine`, matcher host→subdomain.
- settings — `CELERY_BEAT_SCHEDULE["poll-scanner-jobs"]` + `SURICATOOS_SCANNER_*`; `startScan/admin.py`
  registra `ScanBridgeJob`; `management/commands/openvas_enroll.py` (keygen+CSR → `/agent/v1/enroll` →
  escreve `secrets/score-hub.{crt,key,ca}`); `docker-compose.yml` monta `./secrets:/certs:ro` **só** em
  celery + celery-beat.

### Contrato do endpoint mTLS

- `POST /ingest/v1/scan-request` — body `{schema_version, rengine_scan_history_id, target, engagement,
  hosts:[{ip, ports[]}]}` → `201 {request_id, state:"PENDING", poll_after_seconds:120}` (replay
  idempotente → `200`, mesmo id). `ip` deve ser literal → senão `422`.
- `GET /ingest/v1/scan-request/{request_id}` — escopo por dono (tenant estrangeiro → `404`) →
  `{state, progress, findings[] quando COMPLETED}`.
- `DELETE /ingest/v1/scan-request/{request_id}` — kill por dono → `stop_task`.

### Sequência GMP (`scan_bridge.py`, dentro da reconciler serializada → sem corrida)

`Full-and-fast = daba56c8-73ec-11df-a475-002264764cea`, `OpenVAS Default =
08b69003-5fc2-4037-a479-93b440211c73`. `authenticate(suricatoos-scan)` → find-or-create **target**
(`hosts=[IP-literais]`, `port_range="T:<portas abertas>"`, `alive_test`) → find-or-create **task** (nome
`suricatoos-rengine-{id}`, Full-and-fast, OpenVAS Default) → `start_task` **só se ocioso** → tag com
`scan_history_id`. `fetch` = `get_report(details=True)` 1x em `Done`, normaliza
(severity/CVE/host/port/solution), cacheia.

### Mapeamento do import no reNgine

`cvss_base`→`cvss_score`; banda → `severity` (≥9→4, ≥7→3, ≥4→2, >0→1, senão 0); nome NVT→`name`;
OID→`type`; CVEs→`cve_ids`; `host:port`→`http_url`; `source="openvas"`. **Chave de dedupe**
`update_or_create(scan_history, source, type=oid, http_url, name)`, once-only via `ScanBridgeJob.imported`.
Host→`Subdomain`/`target_domain` só se estiver na `ScanHistory`, senão quarentena.

### Rollout faseado (respeitando as restrições: build+`save/load`, `--no-deps`, autorização por-ação)

- **P0 — só código.** Os dois repos, branches + PRs, CI verde. Build da imagem ingest, `docker save`.
  **Nenhuma mutação em prod.**
- **P1 — scanner, no escuro.** retag `:stable`→`:stable-prev`; `load` da imagem nova; env `SCAN_*`
  (`SCAN_LAUNCH_ENABLED=false`, allowlist vazia); `up -d --no-deps --force-recreate ingest`; bloco nginx
  (`nginx -t` → `up -d --no-deps nginx`); cria usuário gvmd `suricatoos-scan` + permissão Super p/ admin.
  *(cada = 1 ação autorizada)* Verificar: 403 sem cert, 503 com cert enquanto desabilitado; `/ingest/`,
  GSA e agentes intactos.
- **P2 — score, enroll + plumbing.** minta token, roda `openvas_enroll`; deploy reNgine com
  `PUSH_ENABLED=False`; recria **celery** e depois **celery-beat** (`--no-deps`). Verificar handshake +
  round-trip do poll, sem scan ativo.
- **P3 — habilita launch (canário).** adiciona **um /32 nosso** na allowlist, `SCAN_LAUNCH_ENABLED=true`;
  dispara um scan real → acompanha launch→Done→findings→`Vulnerability`.
- **P4 — habilita auto (um engagement).** `PUSH_ENABLED=True` + opt-in de um `Domain`; recon E2E
  completo; expande gradualmente.
- **P5 — hardening.** cert launcher de TTL curto + alerta de expiração.

**Rollback** = flag primeiro (instantâneo); imagem = recria `:stable-prev` com `--no-deps`; nginx =
restaura conf boa; schema do reNgine é aditivo.

### Testes

Units Go (parse DN, allowlist default-deny incl. metadata/RFC1918/irmãs/IPv6, replay idempotente, cap de
concorrência, reject por CRL, IDOR por escopo, cooldown); units Python (IP-literal, port_range, parse de
report, find-before-create); units reNgine (bandas de severity, quarentena de host não-casado, dedupe);
contrato `schema/scan-request.schema.json` round-trip; E2E seguro contra um host autorizado.

## Consequências

- 👍 Loop fechado com **um** deployable novo por caixa, mTLS reusado, e o scanner **autoritativo** sobre
  o que pode ser escaneado (o reNgine nunca é confiado sobre alvos).
- 👍 Scans visíveis na GSA (permissão Super) **e** foothold de credencial mínimo (usuário role=User).
- 👍 Kill switch real em 5 níveis (flag reNgine → flag ingest → DELETE → revoke/CRL → max-duration).
- 👎 Superfície nova em caixa pública (endpoint de scan ativo) — mitigada por default-deny + allowlist
  vazia + autorização por-ação no rollout.
- 👎 Um passo manual de config no gvmd (usuário + permissão) e curadoria da allowlist por engagement.
- Decisão **reversível**: se o blast radius pedir isolamento, o `scan-orchestrator` dedicado continua
  possível reusando o mesmo `scan_bridge.py`.

## Questão aberta (necessária na P3, não agora)

**Qual host/IP nós temos e estamos autorizados a escanear ativamente com OpenVAS** para o canário P3 +
smoke E2E? O IP exato vira o `/32` semente da allowlist. (Uma VM descartável é ideal; o plano nega
explicitamente as próprias caixas de prod.)
