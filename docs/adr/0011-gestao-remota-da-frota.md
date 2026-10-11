# 0011 — Gestão remota da frota (conector de saída + comandos assinados)

- **Status:** PROPOSTO (contrato only, 2026-10-11 — nenhum código; implementação nas fatias F2.1–F2.8, tudo DARK)
- **Data:** 2026-10-11
- **Deciders:** William (mantenedor), Claude Code
- **Relacionado:** [0004-bootstrap-token](0004-bootstrap-token.md), [0006-loop-rengine-openvas](0006-loop-rengine-openvas.md), [0007-sensor-scanner-interno](0007-sensor-scanner-interno.md), [0010-executor-remediacao-windows](0010-executor-remediacao-windows.md); schemas `schema/fleet-{enroll,heartbeat,state,event,command,result}.schema.json`; [inventário LGPD](../data-inventory.md#canal-de-gestão-da-frota-adr-0011)

O **commandcenter** é um console central da frota (app web + API próprios, construído **depois**, num
projeto separado). Este ADR fixa o **contrato** entre ele (o **hub**) e cada scanner da frota (o **nó**):
identidade, transporte, envelope assinado, catálogo de comandos, estado, eventos, resultados, auditoria e
LGPD. É **design only**: nenhuma linha de Go/Python, nenhuma mutação em produção, nenhum push.

## Contexto e problema

O mantenedor quer administrar os scanners **remotamente** a partir do commandcenter: jobs, agentes,
tarefas, agendamentos, relatórios e demais itens. A **frota são vários nós**: o scanner central, scanners
**standalone** dentro da rede de clientes (perfil `compose/docker-compose.standalone.yml`) e os **sensores**
do [ADR-0007](0007-sensor-scanner-interno.md) — muitos atrás de **NAT/firewall** de cliente. Logo o hub
**não alcança** os nós: cada nó precisa abrir conexão de **saída** e **puxar** o que fazer, sem ganhar porta
nova exposta.

O problema difícil **não é o transporte** (o sensor do ADR-0007 já faz phone-home mTLS): é dar a um
console remoto poder **de escrita** sobre scanners de terceiros sem transformar o hub num ponto único de
comprometimento de toda a frota. Um hub invadido não pode virar: varredura fora do escopo autorizado,
apagamento definitivo de histórico, criação de usuário ou credencial no gvmd, nem exfiltração silenciosa e
sem limite de achados — o que sai do nó é contado, orçado e auditado localmente.

Decisões fixas do plano aprovado pelo mantenedor (11/10/2026), que este ADR **não reabre**:

- **D1** — o nó roda um **conector** (módulo Go novo `fleet/`, no molde do `sensor/`); operações GVM via
  `gmp-bridge/fleet_ops.py` (python-gvm, **um exec por comando**, **allowlist** de operações, **filtro sempre
  explícito**); **sem passthrough GMP genérico**.
- **D2** — o **escopo de varredura é autoridade LOCAL** do nó e **nunca** é alterado remotamente no v1 (o hub
  só lê). Alvo criado remotamente = só IP/CIDR literal ⊆ escopo do tenant (nó central: registro
  `control-plane/tenants`; standalone/sensor: `FLEET_SCAN_SCOPE` local), reaproveitando
  `sensor/internal/scope/scope.go` (deny absoluto de loopback/link-local/metadata/multicast/self).
- **D3** — remediação ([ADR-0010](0010-executor-remediacao-windows.md)): só **leitura** remota no v1;
  aprovar/rejeitar remotamente é v2, atrás de política local.
- **D4** — do nó sai só **metadado operacional e contagens**; achado detalhado só por `report.export`
  explícito.
- **D5** — transporte HTTPS de saída com mTLS, URL configurável; o 1º canário usa o **hub de referência**
  alcançado por rede privada (**tailnet**), hub fora da internet.
- **D6** — leitura e operação (start/stop/export) com o **usuário gvmd atual** do nó; criação/alteração sob o
  **usuário gvmd do TENANT** (partição do ADR-0007); tenant sem registro → comando rejeitado.
- Tudo nasce **DARK**: `FLEET_ENABLED=false` e serviço no profile `fleet` do compose.

O que já existe e é reusado (verificado, read-only):

- `control-plane/remediation/canonical.go` — *canonical* **length-prefixed** (`chave=<len>:<valor>\n`), domínio
  na 1ª linha, ordem fixa, tempos RFC 3339 UTC em segundos, payload ligado por `sha256` hex; `Verify` confere
  o hash do payload + Ed25519; `VerifyAt` acrescenta a janela `[issued_at − skew, expires_at + skew]`. O agente
  usa `skew = 2 min` (`agent/internal/agentd/agentd.go`). **Golden byte-a-byte** nos dois lados
  (`TestCanonicalGolden`).
- `control-plane/signkeys/signkeys.go` — chave Ed25519 **por propósito**, PKCS#8 `0600`, pubkey PKIX PEM
  distribuída e **pinada** no enroll — separada da chave que emite certificados.
- `sensor/internal/cloud/cloud.go` + `sensor/internal/supervisor/supervisor.go` — cliente mTLS **só de saída**
  que **recarrega o certificado a cada handshake** (`GetClientCertificate` → o renew vale sem restart), poll com
  `204` = nada a fazer, heartbeat em ticker separado. Lição registrada no supervisor: **não perder trabalho
  num crash** (lá, ack só depois do push).
- `sensor/internal/scope/scope.go` — `CheckHost`: só **IP/CIDR literal** (hostname recusado → sem DNS
  rebinding), CIDR tem de caber **inteiro** numa faixa autorizada, deny absoluto de espaço degenerado
  (loopback, link-local/metadata, multicast, não-especificado) **e** sobreposição de CIDR com ele. Os IPs
  próprios (`SCAN_SELF_DENY_IPS`) só são negados quando o alvo é **um IP**: um CIDR que contém um IP próprio
  passa (ramo CIDR do `CheckHost`). A frota fecha essa lacuna no contrato (regra de escopo do Catálogo) e a
  F2.4 a corrige na extração do pacote.
- `control-plane/tenants/tenants.go` — registro `{name, scope, gmp_user, enabled}`; `Known` (habilitado),
  `ScopeSpec`, `GmpUser`; arquivo `TENANTS_FILE` (não-secreto). As senhas gvmd por tenant ficam à parte, em
  `SENSOR_TENANT_SECRETS` (`{tenant: senha}`, host-only `0600`, `compose/docker-compose.override.yml`).
- `control-plane/api/api.go` — `POST/GET/DELETE /api/v1/tokens` (admin-bearer); o token é opaco
  `st_<id>.<secret>` ([ADR-0004](0004-bootstrap-token.md)) e `DELETE` revoga **também todos os certificados**
  emitidos por ele (kill switch). `control-plane/ca/ca.go` `Fingerprint` = `sha256:<hex>` (o `--ca-pin`).
- `control-plane/commands` — `POST /api/v1/agents/{id}/commands` enfileira `scan_now`, que **re-coleta o
  inventário local** do agente (não é varredura de rede; agente passivo do ADR-0001).
- `control-plane/sensorjobs` — `POST /api/v1/tenants/{t}/scan-jobs` (admin-bearer), com portão de escopo.
- `compose/feed-updater/feed_updater.py` — `POST /sync` dispara o sync de feeds (`202`; `409` se já roda).
- `gmp-bridge/scan_bridge.py` — o molde de bridge: **um exec por operação**, imprime **um** JSON no stdout,
  XML GMP só via objetos de request do python-gvm (nunca string formatada). Atenção: o `_alive_test` de lá
  **cai em silêncio** para o padrão da scan config quando o valor é desconhecido — a frota **não** pode fazer
  isso (ver fallback documentado no Catálogo).
- `ingest/server.go` — `online` do agente = último check-in em até **35 min**.

## Opções consideradas

### Canal de gestão (o eixo decisivo)

- **Push direto pela API pública do nó, descartado.** O hub chamaria a API admin (ou o GMP) de cada nó.
  - 👍 Simples para o hub; resposta imediata.
  - 👎 Exige porta **inbound** no nó — impossível atrás de NAT de cliente e contrário ao phone-home do
    ADR-0007. O hub viraria um **cofre com o admin-bearer/senha gvmd de toda a frota** (alvo de valor
    máximo). Um bearer não amarra a ação a um nó nem a um instante: replay trivial e nenhum ponto de
    verificação **por comando** no nó. **Rejeitado.**
- **Conector de saída que puxa comandos assinados (escolhido).** Cada nó abre HTTPS+mTLS de saída, puxa
  por long-poll envelopes assinados com uma chave **separada** da CA e decide **localmente** se executa.
  - 👍 Funciona atrás de NAT (só saída `:443`); o nó não ganha porta. O hub **não guarda credencial de nó**.
    Autenticidade **fim-a-fim por comando** (nem um terminador TLS forja um comando), amarrada a um nó, a um
    tenant, a uma janela e a um nonce. Política, escopo e tenant continuam **locais**; catálogo fechado;
    auditoria local. Reusa padrões já testados (phone-home do sensor, canonical length-prefixed, `signkeys`,
    `scope`).
  - 👎 Latência de long-poll (até ~25 s); estado **eventual** (coleta a cada 60 s + resync); mais código no
    nó (conector + `fleet_ops.py`); a chave de comando vira ativo crítico do hub (rotação só no v2).
- **Passthrough GMP via gsad (túnel reverso até a GSA/gvmd do nó), descartado.**
  - 👍 Cobertura total do GMP sem catálogo; GSA remota "de graça".
  - 👎 Superfície **máxima**: qualquer comando GMP — usuários, permissões, credenciais, `delete … ultimate`,
    settings, scan configs — é controle total do nó. Escopo e tenant **não** são verificáveis por comando;
    impossível minimizar dado (um `get_reports` completo sai inteiro); o túnel reverso é, na prática, uma
    porta exposta. Contraria D1. **Rejeitado.**

### Autenticidade do comando

- **Só mTLS (o hub autenticado basta), descartado.** 👎 Quem controla o terminador TLS do hub (ou o
  processo do hub) fala como o hub; nada no nó distingue "o hub decidiu" de "algo no caminho injetou".
- **Assinatura Ed25519 por comando com chave própria, pinada no enroll (escolhido).** 👍 Mesmo raciocínio
  do ADR-0010: separar propósitos (CA da frota ≠ chave de comando ≠ CA de enroll do scanner) limita o raio
  de cada vazamento; o *canonical* length-prefixed é injetivo e já tem disciplina de golden no repo.

### Onde mora o escopo e a política

- **No hub, descartado.** 👎 Um hub comprometido ampliaria escopo e liberaria escrita em toda a frota de uma
  vez. **No nó (escolhido, D2):** o hub só **lê** o escopo; a política (quais tipos o nó aceita) é um arquivo
  local que **nenhum comando** altera.

## Decisão

**Conector de SAÍDA em cada nó + comandos ASSINADOS puxados por long-poll**, com:

1. **Três domínios de confiança separados.** (a) **CA da frota** (no hub) emite o certificado do nó
   `CN=<node_id>, O=<org>, OU=fleet-node` — separada da CA de enroll do scanner, que continua emitindo para
   agentes e sensores; (b) **chave de comando** Ed25519, separada da CA da frota (molde `signkeys`), com a
   pubkey **pinada** no enroll; (c) o TLS do servidor do hub, pinado por `FLEET_HUB_PIN`. Vazar um não concede
   os outros.
2. **Envelope assinado com domínio `suricatoos-fleet-command-v1`**, *canonical* length-prefixed idêntico em
   disciplina ao da remediação, amarrando `node_id`, `tenant`, `type`, `issued_by`, janela, `nonce` e o
   `sha256` do payload.
3. **Verificação local fail-closed, em ordem fixa** (forma → hash do payload → assinatura → reentrega →
   janela → nó → nonce e `command_id` → tenant → catálogo/política/orçamento → payload → escopo), com motivo
   tipado e decisão **persistida antes** de qualquer efeito.
4. **Catálogo fechado v1** (22 tipos), cada um com payload e saída em schema; escrita **opt-in por nó**;
   delete **sempre para a lixeira**; nada de escopo, tenant, usuários/RBAC do gvmd, credenciais de alvo,
   aprovação de remediação ou passthrough GMP; `report.summary` só devolve contagens.
5. **D1–D6 como acima**; estado e eventos **minimizados** (D4); **auditoria local** JSONL encadeada por hash,
   com a cauda enviada ao hub como testemunha.
6. **DARK**: `FLEET_ENABLED=false` + profile `fleet`; ligar exige o profile, a flag, o bundle de enroll com
   pins e — para qualquer escrita — editar a política local.

## Arquitetura

### Componentes

**Novos no NÓ (central, standalone, sensor):**

| Componente | Papel |
|---|---|
| `fleet/` (módulo Go) → `fleet-connector` | serviço no profile `fleet`; só conexões de **saída**; nenhuma porta publicada |
| `fleet/contract` | tipos dos 6 schemas, `Canonical`/`Verify`/`VerifyAt`, validação por tipo, golden vectors (`fleet/contract/testdata/`) |
| cliente do hub | HTTPS ≥ TLS 1.3 + mTLS, certificado recarregado a cada handshake (molde `sensor/internal/cloud`) |
| verificador + store anti-replay/journal | ordem fixa de checagens; nonce, decisão e resultado persistidos (escrita atômica, `fsync`, `0600`) |
| política local | `FLEET_STATE_DIR/policy.json` (`allow`, `sensitive_per_hour`, `total_per_hour`); só o operador local edita |
| portão de escopo | lógica de `sensor/internal/scope` extraída para pacote compartilhado (F2.4) |
| coletores de estado + outbox de eventos | hash por kind; outbox durável, entrega ≥ 1 vez |
| auditoria local | dois fluxos append-only encadeados por hash, com rotação própria: `FLEET_STATE_DIR/audit-exec.jsonl` e `audit-reject.jsonl` |
| executor serial | um comando por vez; despacha para `fleet_ops.py`, API admin local ou feed-updater |
| `gmp-bridge/fleet_ops.py` | python-gvm; um subcomando por operação do catálogo + leituras de estado; filtro explícito; checagem de dono |

**Reusados no nó:** gvmd local (socket do compose), `control-plane` (API admin + bearer **dedicado** da frota,
F2.2), `ingest` (online dos agentes), `feed-updater` (`POST /sync`), registro de tenants.

**No HUB (projeto commandcenter; aqui só o contrato e, na F2.7, um hub de referência para E2E):** CA da frota +
revogação, signer de comando, fila por nó, store de estado/eventos (dedup por `event_id`), store de
artefatos, rotas `/fleet/v1/*`.

```
┌─ HUB (commandcenter — projeto separado) ──────────────────────────────────────────────────┐
│ CA da frota (OU=fleet-node) + revogação · signer de comando (Ed25519, chave própria)      │
│ fila por nó · estado/eventos (dedup event_id) · artefatos · rotas /fleet/v1/* (mTLS)      │
└───────────────────────────────────────────────────────────▲───────────────────────────────┘
                                                            │ HTTPS de SAÍDA + mTLS, iniciado pelo nó (canário: só tailnet)
┌─ NÓ (central | standalone | sensor) ──────────────────────┴───────────────────────────────┐
│ fleet-connector (profile `fleet`, FLEET_ENABLED=false, nenhuma porta publicada)           │
│   cliente mTLS · verificador (chave de comando PINADA) · anti-replay/journal              │
│   política local · portão de escopo · coletores de estado (hash) · outbox de eventos      │
│   auditoria JSONL encadeada · executor serial (um comando por vez)                        │
│       │ exec 1x/comando          │ HTTP, rede do compose          │ HTTP, rede do compose │
│   gmp-bridge/fleet_ops.py    control-plane API admin           feed-updater               │
│       │ socket                   (bearer dedicado da frota)       (POST /sync)            │
│     gvmd local                                                                            │
└───────────────────────────────────────────────────────────────────────────────────────────┘
```

### Configuração do nó (`fleet-connector`)

| Variável | Padrão | Uso |
|---|---|---|
| `FLEET_ENABLED` | `false` | chave mestra; `false` → o conector não abre conexão nenhuma |
| `FLEET_HUB_URL` | — | URL base `https://` do hub (D5) |
| `FLEET_HUB_CA_FILE` | vazio | PEM da CA que emitiu o certificado de **servidor** do hub (hub privado); vazio = trust store do sistema. Hostname sempre verificado |
| `FLEET_HUB_PIN` | — | `sha256:<hex>` do SPKI do certificado de servidor do hub **ou** de uma CA da cadeia dele — **obrigatório**; aceita **lista** separada por vírgula (rotação do certificado do hub: atual + próximo), e basta casar um; conferido em **todo** handshake, enroll inclusive, além da validação da cadeia (redes de cliente com CA de interceptação) |
| `FLEET_ENROLL_TOKEN` | — | token `ft_<id>.<secret>` de uso único; só até o enroll, depois ignorado |
| `FLEET_CA_PIN` | — | `sha256:<hex>` do DER da CA da frota — **obrigatório** para o enroll |
| `FLEET_COMMAND_KEY_PIN` | — | `sha256:<hex>` do SPKI DER da chave de comando — **obrigatório** para o enroll |
| `FLEET_NODE_ID` | `node-<uuid>` gerado e persistido | CN do certificado; `^[a-z0-9][a-z0-9-]{2,63}$` |
| `FLEET_NODE_KIND` | — | `central` \| `standalone` \| `sensor` |
| `FLEET_STATE_DIR` | `/var/lib/suricatoos-fleet` | chave/cert (`0600`), pins, anti-replay/journal, outbox, auditoria, política |
| `FLEET_GMP_USER`, `FLEET_GMP_PASSWORD_FILE` | usuário gvmd atual do nó | leitura e operação (D6); precisa de permissão **Super** sobre os usuários gvmd dos tenants, ou ser admin (ver Catálogo) |
| `FLEET_TENANT`, `FLEET_SCAN_SCOPE`, `FLEET_TENANT_GMP_USER`, `FLEET_TENANT_GMP_PASSWORD_FILE` | — | standalone/sensor: o **único** tenant local, seu escopo e seu usuário gvmd de escrita (D2/D6) |
| `TENANTS_FILE`, `SENSOR_TENANT_SECRETS` | os do compose | central: registro de tenants e senhas por tenant, montados **read-only** |
| `FLEET_SELF_DENY_IPS` | — | IPs do próprio nó: nunca alvo (como `SCAN_SELF_DENY_IPS`); os IPs do hub o conector acrescenta sozinho (regra de escopo do Catálogo) |
| `FLEET_CP_TOKEN_FILE` | — | central: bearer **dedicado** da frota para a API admin local (o control-plane o recebe em `FLEET_CP_TOKEN`) |
| `FLEET_CLOCK_SKEW` | `2m` | tolerância de relógio (a mesma da remediação); máximo `10m` — acima disso o conector não sobe |
| `FLEET_STATE_INTERVAL` | `60s` | período de coleta de estado (mínimo 30 s) |
| `FLEET_FEED_STALE_HOURS` | `72` | limiar do evento `feed.stale` |

Intervalo de heartbeat e `wait` do long-poll vêm do hub (`heartbeat_interval_s` 15–600, padrão 60;
`poll_wait_s` 5–30, padrão 25), no enroll e em cada heartbeat; o nó nunca faz poll mais de uma vez a cada 5 s.

### Trace ponta a ponta (enroll → heartbeat → state → comando → verificação → execução → artefato → resultado)

O artefato sobe **antes** do resultado que o lista, para o hub nunca receber resultado que aponte para um
artefato ausente.

```
NÓ (só SAÍDA :443 mTLS)                                        HUB (commandcenter; canário: só via tailnet)
──────────────────────────────────────────────────────         ─────────────────────────────────────────────
 0. operador do hub cadastra o nó → bundle OUT-OF-BAND:
      FLEET_HUB_URL, FLEET_HUB_PIN=sha256:…, FLEET_ENROLL_TOKEN=ft_…, FLEET_CA_PIN=sha256:…, FLEET_COMMAND_KEY_PIN=sha256:…
 1. operador do nó grava o bundle no env do host, FLEET_ENABLED=true, sobe o profile `fleet`
 2. enroll ── POST /fleet/v1/enroll {token, node_id, node_kind, csr(CN=node_id), connector_version, schema_versions}
        (TLS autentica o HUB e casa FLEET_HUB_PIN; o nó ainda não tem cert) ─▶
        ◀── 200 {certificate CN=node_id O=<org> OU=fleet-node, ca_cert, command_pubkey, schema_versions, …}
        → sha256(ca_cert DER)==FLEET_CA_PIN e sha256(command_pubkey SPKI)==FLEET_COMMAND_KEY_PIN, senão aborta;
          pina ambos; esquece o token; auditoria: identity_changed
 3. heartbeat ── POST /fleet/v1/heartbeat {schema_versions, replay_floor, state_hashes{kind:sha},
        unauthenticated_rejections, redeliveries, …} ─▶   (depois de (re)enroll ou reset do store: antes do 1º poll)
        ◀── 200 {server_time, resync:[kinds], heartbeat_interval_s, poll_wait_s, schema_versions}
 4. state ── PUT /fleet/v1/state/{kind} {content_sha256, data} — só kinds com hash novo ou em resync ─▶ ◀── 204
 5. no hub, um operador pede "iniciar a tarefa T do tenant acme no nó N": o hub monta e ASSINA o envelope
 6. poll ── GET /fleet/v1/commands?wait=25 ─▶ ◀── 200 {commands:[envelope…]}  |  204 ao fim do wait
 7. verificação LOCAL em ordem: forma → sha256(payload) → Ed25519 (chave PINADA) → já gravado? (reenvia a decisão)
        → janela ±skew → node_id → nonce → tenant → catálogo/node_kind/política/orçamento → payload → escopo
        ⇒ decisão gravada (nonce + command_id, fsync), menos bad_window/expired (finais, não gravados)
        auditoria: exec(received → executed) | reject(rejected/deferred + motivo); não autenticado: só contado
 8. ack ── POST /fleet/v1/commands/{id}/ack {decision: accepted|rejected|deferred, reason?} ─▶ ◀── 204
        (rejeição de comando AUTÊNTICO também vira o evento command.rejected_by_policy)
 9. execução serial: fleet_ops.py task-start (python-gvm, 1 exec, socket gvmd local, filtro explícito,
        dono do objeto == usuário gvmd do tenant) | API admin local | feed-updater POST /sync
10. artefato (só report.export) ── PUT /fleet/v1/artifacts/{command_id}/report.pdf.gz (gzip + sha256) ─▶ ◀── 201
11. resultado ── POST /fleet/v1/commands/{id}/result {status, output|error, artifacts[], contains_secret} ─▶ ◀── 204
        auditoria: result
12. eventos ── POST /fleet/v1/events {events:[task.status_changed, report.completed, …]} (outbox, ≥ 1 vez) ─▶ ◀── 204
13. renew ── POST /fleet/v1/renew {node_id, csr, schema_versions} com o cert ATUAL, 7 dias antes de expirar ─▶
        ◀── 200 (mesmo formato; command_pubkey tem de ser IDÊNTICA à pinada)
```

Cada hop é **saída do nó**; nenhuma porta inbound é aberta, nem no cliente, nem no nó central.

## Contrato

Os seis schemas (JSON Schema Draft 2020-12, `$id` `https://suricatoos.dev/schema/fleet-*.schema.json`) são a
fonte da verdade dos corpos; este capítulo fixa a semântica. Os **primitivos compartilhados** (`uuid`,
`node_id`, `tenant`, `utc_time`, `sha256_hex`, `ip_or_cidr`, `alive_test`, `command_type`…) vivem em
`fleet-command.schema.json#/$defs` e são referenciados pelos demais. Os exemplos válidos e inválidos de
`schema/examples/fleet/` (índice em `index.json`) são o teste de contrato executável: o
`schema/examples/validate_fleet_examples.py` roda no CI, confere hash e assinatura dos envelopes, o
`content_sha256` dos retratos de estado sobre os bytes crus (os exemplos são compactos, como no fio) e as cadeias
do `audit_tail` (a mesma conferência que o hub faz como testemunha), e reproduz o exemplo trabalhado deste ADR
byte a byte.

### Versões e evolução

- **Semântica MAJOR.MINOR.** MINOR acrescenta campo, valor de enum ou tipo; MAJOR quebra. O PATCH é só
  editorial (descrição, exemplo) e **nunca vai ao fio**: o `schema_version` de todo corpo versionado (todos,
  menos o do `426`) e de todo envelope é sempre `MAJOR.MINOR.0` — no v1, `1.0.0`, o valor que entra na forma
  canônica assinada.
- **Anúncio em todo contato.** O nó manda `schema_versions` (lista de `MAJOR.MINOR`) no enroll, no renew e em
  **todo** heartbeat; o hub manda as dele na resposta do enroll e do renew e em **toda** resposta de heartbeat.
  **Nenhum lado envia corpo acima da maior versão comum** ao último anúncio do outro — um nó novo fala `1.0`
  com um hub `1.0`, e vice-versa.
- **Serializa no envio.** O nó guarda os itens da fila (ack, resultado, estado, eventos) em forma interna e só
  os serializa **ao enviar**: cada envio sai na versão negociada mais recente, e um item que esperava na fila
  sai na versão nova. O hash de estado é sempre o da serialização na versão do envio. A idempotência do hub
  (`204` × `409`) compara valores, não bytes, para que re-serializar não vire conflito.
- **Enroll e renew** saem na **maior** versão do nó, com o anúncio; o hub responde na maior versão comum.
- **Versão não suportada ⇒ `426`.** O hub lê o `schema_version` — membro de **nível superior** do corpo, em
  qualquer posição entre os membros, porque objeto JSON não tem ordem — de todo corpo do nó antes da validação
  completa. A forma tem nome, `fleet-command.schema.json#/$defs/schema_version_wire`:
  `^(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})\.0$`, isto é, `MAJOR.MINOR.0` com MAJOR e MINOR em decimal **sem
  zero à esquerda** (`01.0.0` e `1.00.0` estão fora).
  - ausente no nível superior, não string ou fora dessa forma ⇒ `400`;
  - na forma, mas de uma versão que o hub não suporta ⇒ `426` com o corpo
    `fleet-heartbeat.schema.json#/$defs/version_unsupported` (`{"schema_versions": [...]}`, as do hub), sem
    consumir o token do enroll.

  São **invariantes** — nunca mudam, nem num MAJOR novo — a forma desse corpo, o membro `schema_versions` dos
  corpos de enroll, renew e heartbeat, e o nome e a forma do `schema_version`, com ele como membro de nível
  superior de todo corpo versionado (todos, menos o do `426`, que não tem versão) e de todo envelope: é o que o
  receptor lê antes da validação completa.
  Reação do nó ao `426`:
  - recalcula a maior versão comum com esse anúncio; se existir, adota-a e reenvia o mesmo item
    re-serializado, no máximo uma vez por item;
  - se não existir, ou se o reenvio também receber `426`, entra em **`blocked_version`**. Para de enviar o tipo
    de mensagem recusado (a versão vale para o contrato inteiro, então na prática todos) e de fazer poll, e
    mantém só o heartbeat a cada 10 min, na sua maior versão e com o anúncio. Audita `version_mismatch` (fluxo
    `reject`) e sai sozinho quando um heartbeat mostra versão comum.
  - antes do enroll não há certificado, logo não há heartbeat: em `blocked_version`, o nó re-tenta o **enroll**
    a cada 60 min, e cada tentativa grava uma linha `version_mismatch`. O token continua valendo pelo TTL dele,
    porque o `426` não o consome; vencido o TTL, o hub responde `403` e o nó só volta com token novo.
- **Rollback do hub.** O anúncio cobre esse caso: o hub rebaixado responde `426` ao primeiro corpo acima das
  versões dele, ou anuncia a lista nova na resposta do heartbeat. O nó rebaixa na hora, e os itens da fila saem
  na versão nova no próximo envio. O hub só entrega comando cuja versão está no último anúncio do nó; um
  comando pendente que ficou fora dele não é entregue nem re-assinado e termina `expired_undelivered` no hub
  (ver "Anti-replay").
- **Estrito na mesma versão.** O envelope de comando é sempre estrito, e todo corpo numa versão (MAJOR.MINOR)
  que o receptor suporta também é validado estrito: campo desconhecido é erro, não é ignorado. A **única
  exceção** é o `resync` da resposta do heartbeat. Os itens dele só casam o padrão de kind
  (`fleet-state.schema.json#/$defs/state_kind_any`), e o nó ignora o kind que não conhece (com alerta local)
  sem descartar a resposta.
- **Valor de enum desconhecido** só aparece se alguém violar a negociação; o destino é fixo. Tipo de comando
  desconhecido no nó ⇒ `unsupported` (final). No hub, motivo, código de erro, tipo de evento ou kind
  desconhecido ⇒ `400` + alerta, e o nó guarda o item como não entregável, visível ao operador local.
- Os schemas deste ADR são a versão `1.0` (`schema_version` `1.0.0`).

### Codificação JSON (normativo)

As regras abaixo valem para os dois lados. O nó em Go (F2.1) as impõe, e o `validate_fleet_examples.py` confere as
mesmas nos exemplos, para Python e Go darem o mesmo veredito.

- **UTF-8** válido, sem BOM; **um único valor JSON** por corpo — depois dele, só espaço em branco (dado extra ⇒
  inválido; no envelope, `bad_envelope`).
- **Sem chave duplicada**, em nível nenhum (inclusive dentro de `payload` e de `data`), e **caixa exata**: chave
  que só difere na caixa (`"Node_ID"`) é chave desconhecida, nunca um apelido de `node_id`. Atenção: o
  `encoding/json` do Go casa chave sem diferenciar caixa e aceita duplicata — o lado Go faz uma passada por
  tokens antes do decode.
- **Aninhamento ≤ 32 níveis** de objeto e array, com o valor do topo no nível 1; acima disso, JSON inválido (no
  envelope, `bad_envelope`).
- **Sem surrogate desemparelhado** em string nenhuma (escape `\uD800`–`\uDFFF` sem o par): JSON inválido (no
  envelope, `bad_envelope`). É regra do parser: o `encoding/json` do Go troca esse escape por U+FFFD em silêncio,
  então o lado Go confere os tokens.
- **Inteiros sem fração nem expoente** (`100`, nunca `100.0` nem `1e2`). A recusa é **léxica**, no JSON cru: o
  JSON Schema aceita `100.0` como `integer`, então validar o schema não basta. É obrigação do parser (F2.1) nos
  dois sentidos: o nó no envelope (`bad_envelope`) e o hub nos corpos nó→hub (`400`). O
  `validate_fleet_examples.py` confere isso nos exemplos (checagem `integer_lexical`). No **envelope** não existe
  campo `number`: **todo** número dele, inclusive dentro de um payload de tipo desconhecido ou num membro que o
  schema não conhece, é inteiro, e uma fração ou expoente é `bad_envelope` antes de olhar o schema.
- **base64 canônico.** A `signature` é base64 padrão na forma **canônica**: exatamente 88 caracteres do alfabeto
  padrão, terminando em `==`, com o caractere antes do padding com os 4 bits baixos zerados (`A`, `Q`, `g` ou
  `w`). Espaço, alfabeto URL-safe, padding omitido ou bits de padding diferentes de zero ⇒ `bad_envelope`. O
  schema codifica isso no padrão `^[A-Za-z0-9+/]{85}[AQgw]==$`.
- **Instantes reais.** Todo tempo RFC 3339 é um instante que existe no calendário: sem 30/02, sem hora 24 e sem
  segundo 60. O v1 não precisa de segundo bissexto, e o `time` do Go não o representa. O padrão de `utc_time`
  fixa a faixa de cada campo, e o dia do mês é conferido como `format: date-time` (no envelope, `bad_envelope`).
- **Sem caractere de controle** nos textos do contrato, em especial nenhum `\n` final. No Python, o `$` de um
  padrão casa antes de uma quebra de linha final; no RE2 do Go, não. É o `no_control` do schema, que vale também
  para `token_id`, para o tipo como recebido (`command_type_any`) e para o kind como recebido (`state_kind_any`).
- **Caracteres XML 1.0** nos textos que chegam ao gvmd (nomes, `comment`, iCalendar, filtro): sem U+FFFE/U+FFFF e
  sem controle C0 além do que o campo já permite (o iCalendar aceita TAB, CR e LF). O `no_control` e o
  `icalendar` do schema recusam esses caracteres; o surrogate desemparelhado sai pela regra do parser acima.
- **Bytes verbatim:** `payload_sha256` (comando) e `content_sha256` (estado) são sobre os bytes do valor **como
  transmitidos**. Quem verifica hasheia o trecho cru (num hub JS/TS, com parser que preserve o trecho —
  `JSON.stringify` de novo não serve).
- **Payload embutido sem re-codificar.** O emissor serializa o payload compacto e **sem escape de HTML** (`<`,
  `>`, `&` e U+2028/U+2029 vão literais), calcula o hash sobre esses bytes e monta o envelope **concatenando esses
  mesmos bytes** no lugar do valor de `payload`. Nenhum re-codificador JSON toca o payload depois do hash.
  - Em Go, use o `fleet/contract` (o `Sign` monta o envelope assim; há também o `MarshalCompact`) ou monte os
    bytes à mão.
  - **Não** confie em `json.RawMessage` com `SetEscapeHTML(false)`: no go1.27, com o núcleo json/v2, o
    `encoding/json` escapa U+2028/U+2029 até dentro de um `json.RawMessage`, e todo nó responderia
    `payload_mismatch`.
  - O mesmo vale para o `data` do estado.
  - Travam isso o `valid/command/task-create-html-chars.json`, o
    `invalid/command/payload-html-escaped-after-hashing.json` e os vetores golden equivalentes (lista abaixo).
- O `fleet_ops.py` recebe **exatamente** os valores que passaram na validação (hosts na forma canônica do
  portão de escopo), nunca o JSON cru do hub.

### Identidade do nó e CA da frota

- O nó gera o par de chaves **localmente** (Ed25519; ECDSA P-256 aceito) — a privada nunca sai do nó
  (`0600` em `FLEET_STATE_DIR`) — e um CSR com `CN = node_id`.
- **Enroll** (`POST /fleet/v1/enroll`, `fleet-enroll.schema.json#/$defs/enroll_request`): token **opaco de uso
  único** emitido pelo hub, no formato do ADR-0004 com prefixo próprio — `ft_<id>.<secret>` — para nunca ser
  confundido com um token `st_` do scanner. TTL curto (recomendado ≤ 24 h). O hub **atribui** `O=<org>`
  (a organização dona do nó no hub) e `OU=fleet-node`; o nó não os escolhe.
- **Três pins out-of-band, todos obrigatórios.** O bundle do hub traz `FLEET_HUB_PIN`, `FLEET_CA_PIN` e
  `FLEET_COMMAND_KEY_PIN`. `FLEET_HUB_PIN` (SPKI do certificado de servidor do hub ou de uma CA da cadeia) é
  conferido em **todo** handshake, enroll inclusive, além da validação normal — redes de cliente costumam ter
  CA de interceptação no trust store. Ele aceita uma lista separada por vírgula (basta casar um), para o hub
  trocar de certificado sem quebrar a frota: o env leva o pin atual e o próximo, e o antigo sai depois da
  troca. No enroll, o nó **recusa** a resposta (`fleet-enroll.schema.json#/$defs/enroll_response`) se
  `sha256(DER da CA)` ou `sha256(SPKI da chave de comando)` não bater. Assim um MITM no enroll não planta a
  sua chave de comando. O conector também recusa pinar a chave de **teste** dos golden vectors (abaixo).
- **Renew** (`POST /fleet/v1/renew`, `fleet-enroll.schema.json#/$defs/renew_request`): autenticado pelo
  certificado **atual** (mTLS); o CSR mantém `CN = node_id`; o hub recusa certificado revogado (fail-closed,
  como `enroll.Renew`). TTL recomendado de 30 dias, renovação 7 dias antes do fim; o cliente recarrega o
  certificado a cada handshake. A resposta tem o mesmo formato do enroll, e o nó **só instala** o certificado
  novo se a `command_pubkey` for **idêntica** à pinada e o `ca_cert` for a CA da frota pinada; senão mantém o
  certificado atual, recusa a resposta e audita (`identity_changed`, detalhe `command_key_mismatch` ou
  `ca_mismatch`) — no v1 nada rotaciona.
- **Re-enroll.** Certificado vencido não renova. Re-enrolar o **mesmo** `node_id` exige um token que o hub
  **amarrou** a esse `node_id` (sem isso, `409`); o store local (anti-replay, journal, auditoria) é
  reaproveitado e os três pins são reaplicados a partir do ambiente. Em **todo** (re)enroll, com ou sem o
  `FLEET_STATE_DIR` apagado, o nó grava um piso de replay = agora (ver "Anti-replay"). O hub descarta os comandos
  **nunca entregues** daquele `node_id` (a identidade é nova). Um comando já entregue e sem desfecho vira
  **`unknown_outcome`**, para revisão do operador, e um ack ou resultado que ainda chegue o resolve. Se for um
  `enroll_token.create`, o hub trata o token como possivelmente vivo e orienta revogá-lo pela variante "só o
  token".
- **Obrigações do hub em toda rota mTLS:** certificado da CA da frota, `OU == fleet-node` **exato**,
  `CN == node_id`, revogação checada **fail-closed** — certificado revogado ou desconhecido ⇒ `403`, backend de
  revogação indisponível ⇒ `503` (transitório; nunca `403`, que poria a frota inteira em `blocked`); `node_id`
  do corpo ≠ CN → `403`; recurso de outro nó (comando, ack, resultado, artefato) → `404`, sem distinguir de
  inexistente.

### Chave de comando

Ed25519 dedicada, gerada e guardada só no hub (molde `control-plane/signkeys`: PKCS#8, `0600`, pubkey PKIX
PEM). A pubkey chega ao nó no enroll e fica **pinada**; o v1 **não rotaciona** (questão aberta). Nenhum nó
possui chave de assinatura: um nó comprometido não forja comando para outro.

### Envelope assinado e forma canônica

O envelope (`fleet-command.schema.json`) tem 12 campos: os 10 assinados abaixo + `payload` (objeto JSON) +
`signature` (base64 padrão, em forma canônica, dos 64 bytes Ed25519). `fleet-command.schema.json#/$defs/envelope`
é o mesmo envelope na forma que a linha 0 confere (`type` = `command_type_any`, `payload` = qualquer objeto). A
mensagem assinada é a **forma canônica**:

```
suricatoos-fleet-command-v1\n
schema_version=<len>:<valor>\n
command_id=<len>:<valor>\n
node_id=<len>:<valor>\n
tenant=<len>:<valor>\n
type=<len>:<valor>\n
issued_by=<len>:<valor>\n
issued_at=<len>:<valor>\n
not_after=<len>:<valor>\n
nonce=<len>:<valor>\n
payload_sha256=<len>:<valor>\n
```

Regras (copiadas da disciplina de `control-plane/remediation/canonical.go`):

- domínio na **1ª linha**; campos **nesta ordem**; cada linha `chave=<len>:<valor>\n`, com `<len>` = tamanho do
  valor em **bytes** UTF-8, decimal sem zeros à esquerda — nenhum valor, nem um com `\n` ou `:`, desloca a
  fronteira de um campo.
- `issued_at` e `not_after` em RFC 3339 **UTC, segundos inteiros, sufixo `Z`** (`2026-10-11T12:00:00Z`). O
  envelope JSON carrega **exatamente** essa forma (o schema exige 20 caracteres); fração de segundo ou offset
  ⇒ `bad_envelope`. Cada um é um instante real (ver "Codificação JSON"). Diferente da remediação, os dois são
  **obrigatórios** (vazio ⇒ `bad_envelope`).
- `schema_version` = `MAJOR.MINOR.0` de uma versão que o nó suporta (`1.0.0` no v1; o PATCH nunca vai ao fio);
  `command_id` = UUID minúsculo; `nonce` = 32 bytes de CSPRNG em hex minúsculo
  (64 caracteres); `issued_by` = identificador **pseudônimo** do operador do hub, obrigatório (ex. `op-7f3a`;
  o schema recusa `@` e espaço; ver LGPD).
- `payload_sha256` = sha256 hex minúsculo dos **bytes exatos do valor `payload` como transmitidos**. O hub DEVE
  serializar o payload **compacto** (sem espaço insignificante) e hashear exatamente esses bytes; o nó hasheia
  os bytes crus recebidos (`json.RawMessage`), **nunca** uma re-serialização.

**Exemplo verificável** (chave de **teste** pública dos golden vectors — ver abaixo). Envelope como o hub o
envia:

```json
{"schema_version":"1.0.0","command_id":"6f1c2a9e-3b7d-4c8a-9e21-5d4f0a7b3c18","node_id":"node-lab-0001","tenant":"acme","type":"task.start","issued_by":"op-7f3a","issued_at":"2026-10-11T12:00:00Z","not_after":"2026-10-11T13:00:00Z","nonce":"750113b701a52bd32b0fdca1342ddd2d74add6f219ddacef4cede043dfadca02","payload_sha256":"202e584626515573d531f5508c9094f8d6b705e0fc0fe6fbf29c76969fef313f","payload":{"task_id":"2d5b8f0e-1c4a-4e6b-9a3d-7f0c5e1b2a49"},"signature":"6XVZpdCuyN9EZ86zy0kVdNqmfLDrI4QVrPmDs6vv5wdW4HLdEBz2xRI5qSvwmNvmY/eRQ4E3xUdocjIDOyWGCw=="}
```

Bytes assinados (`sha256` = `a9a4d1759628b5708691988ce1512e3cbfa6881f90dfc0000d3fea08edcb7d74`):

```
suricatoos-fleet-command-v1
schema_version=5:1.0.0
command_id=36:6f1c2a9e-3b7d-4c8a-9e21-5d4f0a7b3c18
node_id=13:node-lab-0001
tenant=4:acme
type=10:task.start
issued_by=7:op-7f3a
issued_at=20:2026-10-11T12:00:00Z
not_after=20:2026-10-11T13:00:00Z
nonce=64:750113b701a52bd32b0fdca1342ddd2d74add6f219ddacef4cede043dfadca02
payload_sha256=64:202e584626515573d531f5508c9094f8d6b705e0fc0fe6fbf29c76969fef313f
```

(cada linha termina em `\n`, inclusive a última). `payload_sha256` é o sha256 dos 50 bytes
`{"task_id":"2d5b8f0e-1c4a-4e6b-9a3d-7f0c5e1b2a49"}`.

### Verificação no nó (ordem fixa, fail-closed)

O nó para na **primeira** falha. A linha 2a não é falha: é o atalho da reentrega, consultado logo depois da
autenticação. Os motivos são `fleet-result.schema.json#/$defs/reject_reason`; a coluna **Decisão** diz o
destino do comando (ack em `fleet-result.schema.json#/$defs/ack`).

| # | Checagem | Motivo se falhar | Decisão |
|---|---|---|---|
| 0 | forma (`#/$defs/envelope`): JSON estrito (ver "Codificação JSON"), `schema_version` = `MAJOR.MINOR.0` de uma versão que o nó suporta, formatos exatos (tempos como instantes reais, nonce, assinatura em base64 canônico), aninhamento, tamanhos | `bad_envelope` | sem ack (só contado) |
| 1 | `sha256(bytes crus de payload) == payload_sha256` | `payload_mismatch` | sem ack (só contado) |
| 2 | Ed25519 sobre a forma canônica com a chave **pinada** (1 + 2 = `Verify`) | `bad_signature` | sem ack (só contado) |
| 2a | reentrega: a forma canônica (que inclui o nonce) já está **gravada** no store, inclusive como `replay` ⇒ reenvia o ack e o resultado gravados, sem reavaliar as linhas 3–9 e sem executar de novo. Não grava linha `received`: conta em `redeliveries` (heartbeat) e numa linha agregada periódica `redelivered` (fluxo `reject`); fica fora do orçamento, mas um poll sem comando **novo** aceito entra no backoff | — | a decisão gravada |
| 3 | `issued_at < not_after ≤ issued_at + 24 h` | `bad_window` | `rejected`, final, **não gravado** |
| 3 | `t ≥ issued_at − skew` | `not_yet_valid` | `deferred` |
| 3 | `t ≤ not_after + skew` (3 = `VerifyAt`; `t` = relógio de verificação, abaixo; skew = `FLEET_CLOCK_SKEW`, 2 min, máx. 10 min) | `expired` | `rejected`, final, **não gravado** |
| 4 | `node_id == CN do próprio certificado` | `wrong_node` | `rejected`, final |
| 5 | nonce **ou** `command_id` já gravado com **outra** forma canônica (a mesma forma já saiu na 2a) | `replay` | `rejected`, final |
| 6 | `tenant` conhecido **e habilitado** no nó (central: `TENANTS_FILE`; standalone/sensor: `== FLEET_TENANT`); escrita exige também usuário gvmd + segredo do tenant | `tenant_unknown` | `rejected`, final |
| 7 | tipo no catálogo v1 e suportado por este `node_kind` | `unsupported` | `rejected`, final |
| 7 | tipo presente em `allow` da política local | `type_not_allowed` | `rejected`, final |
| 7 | aceitar este comando não estoura nenhum dos dois orçamentos locais: o global de aceitos (`total_per_hour`, qualquer tipo) e o de sensíveis (opt-in + `report.export` + `report.summary`) | `rate_limited` | `rejected`, final |
| 8 | payload válido para o tipo (schema estrito + regras semânticas, como o filtro explícito do `report.export`) | `bad_payload` | `rejected`, final |
| 8 | `report.export`: a combinação (`format`, `lang`, `variant`) está em `capabilities.report_formats` do estado `node` | `unsupported_report_variant` | `rejected`, final |
| 9 | escopo: os hosts de `target.create` e os resultantes de `target.modify` (os atuais, lidos no gvmd, se o payload não traz `hosts`); os alvos de `sensor_job.enqueue`; os hosts do target de `task.start/resume` e de `task.create/modify` com `target_id`; e os dos targets das tarefas que o comando liga a uma agenda ou cuja agenda ele altera (`schedule.create` com `task_ids`, `task.modify` com `schedule_id` não vazio, `task.clone` de tarefa com agenda, `schedule.modify`). Tudo lido no gvmd antes da decisão; tem de ser IP/CIDR literal ⊆ escopo do tenant, fora do espaço degenerado e **sem conter** IP próprio nem do hub | `scope_denied` | `rejected`, final |
| — | o store anti-replay/journal não pôde ser gravado, ou a leitura no gvmd da linha 9 falhou | `unavailable` | `deferred` |

Na linha 0, `type` só precisa casar `^[a-z][a-z_]*\.[a-z][a-z_]*$` (`command_type_any`, como em
`fleet-command.schema.json#/$defs/envelope`): um tipo fora do catálogo é `unsupported` (linha 7), não
`bad_envelope` — um hub conforme ao schema v1 nunca o envia. Passou em tudo ⇒ `accepted`. Três destinos:

- **Sem ack (linhas 0–2).** Envelope não autenticado não gera ack ligado ao `command_id` — quem não tem a chave
  não pode finalizar um comando legítimo pendente — nem linha própria de auditoria: o nó só **conta**, em
  linhas periódicas do fluxo `reject` (evento `unauthenticated`), e informa o total em
  `unauthenticated_rejections` no heartbeat.
- **`rejected` = final (linhas 3–9).** Os das linhas 4–9 são gravados com o nonce **e** o `command_id` antes
  do ack; a reentrega do mesmo envelope recebe o mesmo ack (linha 2a), também depois de `not_after`, enquanto a
  entrada viver. Os da linha 3 (`bad_window`, `expired`) são finais mas **não são gravados**: dependem só do
  envelope e do relógio de verificação (que não volta), então a reentrega recalcula a mesma decisão. O hub não
  reentrega um `rejected` por conta própria. Corrigida a causa local, o hub emite **outro** comando (novo id,
  novo nonce). Os das linhas 6–9 também viram o evento `command.rejected_by_policy`.
- **`deferred` = retentável (`not_yet_valid`, `unavailable`).** Nada é gravado; o hub pode reentregar o
  **mesmo** envelope, byte a byte, até `not_after`, e uma decisão final posterior substitui o `deferred`. Um
  `deferred` que chega ao hub **depois** de uma decisão final é ignorado: a final vence.

`accepted` também é decisão final: gravada com o nonce e o `command_id` antes do ack e de qualquer efeito.

### Anti-replay, idempotência e entrega

- **Store persistido** (`FLEET_STATE_DIR`, escrita atômica temp+rename com `fsync`, `0600`), chaveado pela
  forma canônica e com dois índices — **nonce** e **`command_id`** → `{sha256(forma canônica), decisão,
  motivo, resultado sem segredo}`. Toda decisão final é gravada **antes** do ack, menos as da linha 3
  (`bad_window`, `expired`), que nada acrescentam ao store. Um `replay` fica gravado pela própria forma
  canônica, e os índices continuam apontando para a primeira. Cada entrada vive até
  `min(not_after, issued_at + 24 h)` + 7 dias; o journal do resultado, idem. Como só entra no store envelope que
  passou da linha 3, toda entrada tem `issued_at ≤ t + skew` (senão seria `not_yet_valid`, adiado e não gravado)
  e `not_after ≤ issued_at + 24 h` (senão `bad_window`). Logo a vida de qualquer entrada termina antes de
  `t` + skew + 24 h + 7 dias, com `t` o instante da gravação: um hub não consegue manter entrada no store além
  disso. O prazo é `not_after` + 7 dias, ≥ `not_after` + skew (o mínimo do anti-replay).
  - A vida é limitada; o tamanho, não. Com um hub comprometido, o pior caso é ~2·10⁵ entradas e ~0,6 GB de
    journal. A F2.4 dimensiona o store, põe teto e alerta. No teto, a gravação falha e vale a linha `unavailable`
    (`deferred`, fail-closed).
- **Chave de idempotência (normativo).** O hub reentrega o envelope **byte a byte** idêntico e **nunca**
  re-assina um `command_id` — nem para renovar a janela: vencido, ele emite outro comando. No nó, forma
  canônica diferente sob nonce **ou** `command_id` já gravados ⇒ `replay`. A F2.1 cria o vetor golden disso.
  - **Lápide da linha 3.** Como `bad_window` e `expired` não são gravados, o nó **não consegue** impor essa regra
    para esses desfechos: não sobra registro com que comparar um `command_id` re-assinado. Ali ela é
    **normativa para o hub**: reemitir é sempre `command_id` e nonce novos. A F2.4 testa que o store fica
    inalterado depois de uma decisão da linha 3.
- **Reentrega ≠ replay.** O hub reentrega um comando entregue e sem ack após 60 s, até `not_after` (entrega
  ≥ 1 vez), e também um `deferred`. Mesma forma canônica já gravada ⇒ o nó **não executa de novo** nem
  reavalia janela e política (linha 2a, logo depois da assinatura): reenvia o ack e, se houver, o resultado
  gravados — menos o do `enroll_token.create` (abaixo). Uma reentrega depois de `not_after` recebe a decisão
  gravada, e não `expired`, enquanto a entrada viver (até `not_after` + 7 dias); depois disso a mesma reentrega
  cai na linha 3 e volta `expired`, que o hub responde com `409` sem efeito. Uma entrada gravada nunca é
  sobrescrita.
- **Fim no hub.** Um comando vira **`expired_undelivered`** no hub quando passa de `not_after` + skew + 5 min
  só com `deferred`, ou sem ack nenhum. O skew aqui é o teto (10 min), porque o hub não conhece o do nó. Ficam
  sem ack: as linhas 0–2, que não geram ack, e os comandos que o hub não entrega (fora do último anúncio de
  versões do nó, ou abaixo de `replay_floor` + 10 min).
  - O estado é terminal só para a **entrega**: o hub não o reentrega nem o re-assina.
  - Ack ou resultado que chegue depois, até 7 dias após `not_after`, ainda leva o comando ao estado real, e o
    hub registra a chegada tardia. O mesmo vale para `unknown_outcome` (ver "Re-enroll").
  - O hub **nunca** re-emite sozinho a mesma intenção: reemitir exige confirmação do operador, para não
    executar duas vezes.
- **Só grava envelope autenticado e de janela válida** (decisões das linhas 4–9 e `accepted`): gravar nonce de
  envelope não autenticado deixaria um MITM "queimar" nonces legítimos, e gravar `bad_window` ou `expired` não
  acrescenta nada.
- **Relógio de verificação.** `t = max(agora, marca)`, em que a **marca d'água** é o maior instante já visto,
  persistido a cada minuto e a cada decisão: um relógio que volte no reboot não reabre janela vencida.
  `FLEET_CLOCK_SKEW` vale no máximo 10 min (acima disso o conector não sobe). O `server_time` do hub serve
  **só** para relatar `clock_offset_s` e alertar: o nó nunca ajusta `t` pelo relógio do hub.
- **Store ilegível — ou ausente com o certificado do nó presente — no boot, e em todo (re)enroll** ⇒ o nó grava
  um **piso de replay** = `t` e rejeita (`replay`, detalhe `cache reiniciado`) todo comando com
  `issued_at < piso + skew`; depois de 24 h + skew o piso deixa de importar (janela máxima). Sem store
  gravável, nenhum comando é aceito (`deferred` com `unavailable`).
  - O nó publica o piso como `replay_floor` (UTC) no heartbeat e no estado `node`, **arredondado para cima** ao
    segundo inteiro, e compara em segundos inteiros. A referência é o **heartbeat**; como o estado `node` pode
    atrasar até 60 s (um ciclo de coleta) e o piso só avança, o hub usa o maior dos dois valores que viu.
  - Depois de (re)enroll ou de reset do store no boot, o nó **DEVE** mandar um heartbeat antes do primeiro
    poll: é ele que leva o piso novo ao hub antes de qualquer comando.
  - **Normativo para o hub:** nunca emitir comando para o nó com `issued_at < replay_floor + 10 min` (o teto de
    `FLEET_CLOCK_SKEW`, já que o hub não conhece o skew do nó), nem emitir antes de ver o `replay_floor` de
    depois de um (re)enroll. Pendente abaixo desse limite não é entregue.
  - Resultado: uma janela de silêncio explícita de ≤ 10 min depois de (re)enroll ou reset do store, sem
    comando legítimo recusado como `replay`.
- **Ack antes, resultado depois.** O ack é a **decisão**; o resultado, o **desfecho**. Crash entre o ack e o
  resultado ⇒ no boot o nó **não re-executa**: reporta `failed` com `error.code = interrupted` (o estado
  seguinte mostra o que de fato aconteceu).
- **Execução serial** (um comando por vez, na ordem recebida). Timeouts: 120 s; `report.summary` 5 min;
  `report.export` 15 min. `timeout` **não prova** ausência de efeito.
- **Idempotência do ack (normativo).** Ack idêntico = mesmos (`command_id`, `decision`, `reason`);
  `received_at`, `detail` e os demais campos não contam. Uma repetição com outro `received_at` recebe `204`,
  nunca `409`; `409` é só para outra decisão final (outro `decision` ou outro `reason`).
- **Resultado e artefato ≥ 1 vez.** Artefatos sobem **antes** do resultado que os lista; o resultado é
  reenviado com backoff até `2xx`; o hub responde `204` a repetição idêntica e `409` a conteúdo diferente, e
  aceita resultados de comando entregue por **≥ 7 dias** após `not_after` (a ação aconteceu dentro da janela).
- **Segredo (`enroll_token.create`).** O token fica **só em memória** até o hub aceitar o resultado (`2xx`);
  nunca vai a disco, log ou auditoria. Na reentrega desse comando o nó reenvia **só o ack** (o journal não tem
  o segredo). Reinício antes do `2xx` do resultado ⇒ no boot o nó **revoga só o token**, pela rota da F2.2
  que não toca certificados (a mesma do `enroll_token.revoke`), e reporta `failed` com `secret_lost`. O hub
  trata um `secret_lost` como **revogação autoritativa**, mesmo que já tenha recebido o segredo (corrida
  "entregue sem confirmação + reinício").

### Golden vectors (gerados na F2.1)

Procedimento:

1. `fleet/contract` implementa `Canonical`, `Verify`, `VerifyAt` e as checagens 0–4 em Go, no molde de
   `control-plane/remediation/canonical.go`, com o domínio `suricatoos-fleet-command-v1`.
2. Um gerador determinístico (`go test ./fleet/contract -run TestGolden -update`) escreve
   `fleet/contract/testdata/golden-v1.json`; sem `-update`, o teste regenera em memória e **falha** em qualquer
   byte de diferença (mesma trava de drift de `TestCanonicalGolden`).
3. **Chave de teste determinística e pública:** seed Ed25519 = SHA-256 do texto ASCII
   `suricatoos-fleet-command-v1/golden-test-key`; pubkey `MCowBQYDK2VwAyEAB9q67lsE3i3PULOubuP+pQXTCUwAye7O14Zsa5+EqWw=`
   (SPKI base64), pin `sha256:a35dc29cebfbe26dff2e840afc6550f291e734caba174011c56b7a8de353b6b1`. É a chave do
   exemplo acima. O conector **recusa pinar** essa pubkey no enroll; o hub nunca assina produção com ela.
4. O commandcenter consome o **mesmo arquivo** (cópia com sha256 pinado) e tem de passar em todos os vetores
   antes de falar com um nó real.

Formato do arquivo (`golden-v1.json`, UTF-8, um objeto JSON):

| Campo | Conteúdo |
|---|---|
| `format` | `"suricatoos-fleet-golden/1"` |
| `domain` | `"suricatoos-fleet-command-v1"` |
| `skew_seconds` | `120` |
| `test_key` | `{seed_derivation, public_key_pem, pin}` com os valores do item 3 |
| `vectors[]` | um objeto por vetor, campos abaixo |
| `vectors[].name` | identificador estável, ex. `accept/task.start`, `bad_signature/tenant` |
| `vectors[].own_node_id` | `node_id` do nó que verifica |
| `vectors[].verify_at` | o "agora" da verificação (`utc_time`) |
| `vectors[].command_json` | os bytes **exatos** do envelope como o hub os envia (string) |
| `vectors[].canonical` | a forma canônica exata (string, com os `\n`) |
| `vectors[].canonical_sha256` | sha256 hex de `canonical` |
| `vectors[].payload_sha256` | sha256 hex dos bytes crus de `payload` |
| `vectors[].seen` | opcional: sha256 das formas canônicas já **gravadas** no store (decisão final) sob o mesmo nonce/`command_id` (vetores das linhas 2a e 5) |
| `vectors[].expect` | `accept`, `redelivery` (a forma já está em `seen`: o nó reenvia a decisão gravada, sem reavaliar) ou um `reject_reason` |

O vetor `accept/task.start` é o exemplo acima: `command_json` = o envelope, `canonical` = os bytes assinados,
`canonical_sha256` = `a9a4d1759628b5708691988ce1512e3cbfa6881f90dfc0000d3fea08edcb7d74`,
`own_node_id` = `node-lab-0001`, `verify_at` = `2026-10-11T12:30:00Z`.

Vetores obrigatórios:

- `accept`: um por formato de payload, e um payload com UTF-8 (acentos) hasheado sobre os bytes crus.
- `payload_mismatch`: payload trocado.
- `bad_signature`: cada um dos 10 campos alterado após assinar; outra chave; mensagem assinada com o domínio
  da remediação.
- `not_yet_valid`/`expired` **nas bordas**: `issued_at − skew` e `not_after + skew` aceitos; ±1 s rejeitado.
- `bad_window`: `not_after ≤ issued_at`; janela > 24 h.
- `wrong_node`.
- `replay`: mesmo `command_id` — ou mesmo nonce — com outra forma canônica (o hub re-assinou); o vetor traz em
  `seen` as formas canônicas já gravadas.
- `redelivery`: a própria forma em `seen`, com `verify_at` depois de `not_after` + skew e antes de
  `not_after` + 7 dias — a decisão gravada, não `expired`.
- `bad_envelope`: fração de segundo, offset, nonce maiúsculo, campo faltando, campo desconhecido,
  `schema_version` que o nó não suporta (`1.1.0` num nó só `1.0`) ou com PATCH, `1.0.1`.
- Vetores **só-canonical** com valores contendo `\n`, `=` e `:` (que o envelope v1 recusa por formato) provam
  que o framing é injetivo mesmo assim — e que um *join* ingênuo colidiria.
- Da "Codificação JSON": payload com `<`, `>`, `&` e U+2028 literais (`accept`) e o mesmo payload re-escapado
  em HTML depois do hash (`payload_mismatch`); chave duplicada no envelope e no payload, chave com caixa
  diferente (`"Node_ID"`), dado depois do valor e inteiro com fração ou expoente, `70.0` e `7e1`
  (`bad_envelope`, recusa léxica).
- Das regras estritas: `signature` em base64 não canônico, instante inexistente (30/02), hora 24,
  segundo 60, aninhamento de 33 níveis e surrogate desemparelhado (`bad_envelope`); `\n` final no tipo
  (`bad_envelope`); U+FFFE num nome de payload ou `\n` final num `token_id` (`bad_payload`).

### Rotas do hub

Todas iniciadas pelo nó. JSON com `Content-Type: application/json`; `User-Agent:
suricatoos-fleet-connector/<versão>`. O corpo de **erro** é `text/plain` curto e **não-contratual** (≤ 2 KiB, só
para log, como os `http.Error` do repo): o nó decide **só pelo status**. A exceção é o `426`, cujo corpo é JSON
contratual (`fleet-heartbeat.schema.json#/$defs/version_unsupported`).

| Rota | Autenticação | Pedido | Sucesso | Erros esperados |
|---|---|---|---|---|
| `POST /fleet/v1/enroll` | TLS que autentica o hub (cadeia + `FLEET_HUB_PIN`) + token `ft_` no corpo | `fleet-enroll.schema.json#/$defs/enroll_request` | `200` + `fleet-enroll.schema.json#/$defs/enroll_response` | `400` corpo/CSR inválido, prova de posse falhou, CN ≠ `node_id`; `403` token inválido, expirado, usado ou revogado (mensagem genérica); `409` `node_id` já registrado; `413`; `429` |
| `POST /fleet/v1/renew` | mTLS (certificado atual) | `fleet-enroll.schema.json#/$defs/renew_request` | `200` + `fleet-enroll.schema.json#/$defs/enroll_response` | `400` CSR inválido ou CN ≠ certificado; `403` certificado revogado/desconhecido; `413`; `429` |
| `POST /fleet/v1/heartbeat` | mTLS | `fleet-heartbeat.schema.json#/$defs/heartbeat_request` | `200` + `fleet-heartbeat.schema.json#/$defs/heartbeat_response` | `400`; `403`; `413`; `429` |
| `PUT /fleet/v1/state/{kind}` | mTLS | `fleet-state.schema.json` (`kind` == `{kind}`) | `204` sem corpo | `400` schema, `kind` ≠ caminho, `content_sha256` ≠ sha256 dos bytes de `data`; `403`; `404` kind desconhecido; `413` > 16 MiB **descomprimido** (com gzip, o hub descomprime em streaming e aborta no teto); `429` |
| `POST /fleet/v1/events` | mTLS | `fleet-event.schema.json` | `204` sem corpo (também com `event_id` repetido) | `400`; `403`; `413`; `429` |
| `GET /fleet/v1/commands?wait=25` | mTLS | sem corpo; `wait` inteiro 5–30 (s) | `200` + `fleet-command.schema.json#/$defs/poll_response` (1–10 comandos, mais antigo primeiro); `204` sem corpo se nada chegou até o fim do `wait` | `400` `wait` inválido; `403`; `429` |
| `POST /fleet/v1/commands/{id}/ack` | mTLS | `fleet-result.schema.json#/$defs/ack` | `204` sem corpo (ack idêntico — mesmos `command_id`, `decision` e `reason` — repetido também; ack tardio, até 7 dias após `not_after`, de comando `expired_undelivered` ou `unknown_outcome` também, e o hub registra o atraso) | `400`; `403`; `404` comando inexistente ou de outro nó; `409` decisão **final** diferente já registrada; um `deferred` anterior é substituído pela final, e um `deferred` que chega **depois** de uma final é ignorado com `204` (a final vence); `429` |
| `POST /fleet/v1/commands/{id}/result` | mTLS | `fleet-result.schema.json` (`command_id` == `{id}`) | `204` sem corpo (resultado idêntico repetido também; resultado tardio, até 7 dias após `not_after`, também para comando `expired_undelivered` ou `unknown_outcome`) | `400` schema, id ≠ caminho, artefato listado e não recebido; `403`; `404`; `409` resultado diferente já registrado; `413` > 256 KiB; `429` |
| `PUT /fleet/v1/artifacts/{command_id}/{name}` | mTLS | corpo **binário gzip** + cabeçalhos abaixo | `201` sem corpo (reenvio idêntico também) | `400` sha256 do corpo ≠ cabeçalho, cabeçalho faltando ou `name` inválido; `403`; `404` comando inexistente, de outro nó ou de tipo ≠ `report.export`; `409` outro conteúdo com o mesmo nome; `411` sem `Content-Length`; `413` > 64 MiB; `415` `Content-Type` ≠ `application/gzip`; `429` |

Em todas: `5xx`/`503` = falha transitória — inclusive `503` quando o backend de revogação do hub está
indisponível. Em todas as rotas com corpo JSON (enroll, renew, heartbeat, estado, eventos, ack, resultado): `426`
quando o `schema_version` do corpo está fora das versões que o hub suporta, com o anúncio do hub no corpo (ver
"Versões e evolução"). O hub responde ao long-poll em até `wait + 5` s; o cliente usa timeout maior que isso.

**Cabeçalhos do artefato:** `Content-Type: application/gzip`, `Content-Length`, `X-Fleet-Content-SHA256` (hex do
corpo gzip), `X-Fleet-Original-Content-Type` (`application/pdf` | `application/xml` | `text/csv`),
`X-Fleet-Original-Size`, `X-Fleet-Original-SHA256`. `name` casa `^[a-z0-9][a-z0-9._-]*$` (≤ 64); no v1,
`report.pdf.gz` | `report.xml.gz` | `report.csv.gz`. O resultado repete esses dados em
`fleet-result.schema.json#/$defs/artifact`. **Bomba de descompressão:** `original_size` é afirmação do nó
(não confiável) e tem teto de 1 GiB no schema; o hub aplica o **próprio** teto rígido (≤ 1 GiB), descomprime em
streaming abortando em min(`original_size`, teto) e só então confere o tamanho exato e o `original_sha256`.

**Reação do nó por status:**

| Status | Reação |
|---|---|
| `200`/`201`/`204` | sucesso; retira o item da fila local |
| `400` | não reenvia o mesmo corpo (é bug de contrato); audita; o item fica "não entregável", visível ao operador local |
| `403` | identidade recusada: para de enviar; só tenta heartbeat a cada 10 min; estado local `blocked`; certificado vencido exige novo enroll |
| `426` | versão do corpo fora das do hub: recalcula a maior versão comum com o anúncio do corpo; se existe, adota-a e reenvia o item re-serializado (uma vez por item); se não existe, ou se vier outro `426`, estado local `blocked_version` — só heartbeat a cada 10 min (na maior versão do nó, com o anúncio), sem poll; audita `version_mismatch`; sai sozinho quando um heartbeat mostra versão comum. Antes do enroll (sem certificado, sem heartbeat), re-tenta o enroll a cada 60 min enquanto o token valer |
| `404` | ack/resultado/artefato de comando que o hub não reconhece: descarta e audita; kind desconhecido: deixa de enviar esse kind |
| `409` | conflito de idempotência: não reenvia; audita |
| `413` | estado: corta no teto e marca `truncated`; demais: não reenvia e audita (o nó já confere os tetos antes de enviar) |
| `429`/`503` | respeita `Retry-After`; sem ele, backoff exponencial com jitter (1 s → 5 min) |
| outros `5xx`, erro de rede/TLS | backoff exponencial com jitter (1 s → 5 min); as filas duráveis preservam a ordem |

Resposta de enroll, renew ou heartbeat que não valida — inclusive numa versão que o nó não anunciou — é erro de
contrato do hub: o nó a descarta, audita e trata como falha transitória (backoff). Os comandos do long-poll não
seguem essa regra: cada um passa pelas linhas 0–9.

### Limites

| Item | Limite |
|---|---|
| envelope de comando | ≤ 64 KiB; `payload` ≤ 48 KiB |
| resposta do long-poll | 1–10 comandos, ≤ 1 MiB |
| janela do comando | `issued_at < not_after ≤ issued_at + 24 h` (recomendado: 1 h); skew 2 min |
| ack | ≤ 4 KiB |
| resultado | ≤ 256 KiB |
| heartbeat, enroll, renew | ≤ 64 KiB |
| estado (um kind) | ≤ 16 MiB **descomprimido**; o nó PODE enviar `Content-Encoding: gzip` no PUT de estado e o hub DEVE aceitar, com descompressão limitada em streaming; tetos de itens por kind no schema |
| lote de eventos | 1–100 eventos, ≤ 1 MiB |
| artefato | ≤ 64 MiB (67 108 864 bytes) de gzip e ≤ 1 GiB (1 073 741 824 bytes) descomprimido; ≤ 4 por comando (v1: exatamente 1, só `report.export`) |
| outbox de eventos | 10 000 eventos; cheio ⇒ descarta os mais antigos e conta em `outbox_dropped` |
| intervalo de poll | ≥ 5 s entre dois polls (piso do nó, qualquer que seja o `poll_wait_s`); backoff exponencial até 5 min quando um poll com comandos não traz nenhum novo aceito (rejeição, reentrega e adiamento contam como nada novo; o `204` do fim do `wait` não conta) |
| auditoria local | fluxo `exec` 32 MiB × 8 arquivos; fluxo `reject` 32 MiB × 4; linha ≤ 8 KiB; ≤ 1 linha `unauthenticated` e ≤ 1 linha `redelivered` por minuto; ≤ 1 linha `version_mismatch` a cada 10 min |
| orçamento local de comandos sensíveis | 30/h por nó (`policy.json` `sensitive_per_hour`), somando opt-in, `report.export` e `report.summary` |
| orçamento local de comandos aceitos | 120/h por nó (`policy.json` `total_per_hour`), qualquer tipo; os sensíveis contam nos dois |

## Catálogo de comandos v1

Payloads em `fleet-command.schema.json#/$defs/<payload>`, saídas em `fleet-result.schema.json#/$defs/<saída>`.
"Atual" = usuário gvmd atual do nó (D6), com checagem de que o **dono** do objeto é o usuário gvmd do tenant
do envelope (senão `not_found`, sem enumerar); "tenant" = a operação roda **autenticada como** o usuário gvmd
do tenant (o objeto nasce na partição dele). O usuário atual precisa de permissão **Super** sobre os usuários gvmd
dos tenants (ou ser admin): sem ela, os objetos dos tenants ficam invisíveis para ele — a checagem de dono dá
`not_found` e o estado não os lista sob o tenant. É **pré-requisito de deploy** (runbook da F2.8).

| Tipo | Payload | Política padrão | Nós | Execução | Usuário gvmd | Saída |
|---|---|---|---|---|---|---|
| `state.resync` | `payload_state_resync` | permitido | todos | reenvia já os kinds pedidos (kind inexistente no nó é ignorado) | atual (leitura) | `output_state_resync` |
| `task.start` | `payload_task_ref` | permitido | todos | re-checa os hosts do target contra o escopo (linha 9) → `start_task` | atual | `output_task_action` |
| `task.stop` | `payload_task_ref` | permitido | todos | `stop_task` | atual | `output_task_action` |
| `task.resume` | `payload_task_ref` | permitido | todos | re-checa os hosts do target contra o escopo (linha 9) → `resume_task` | atual | `output_task_action` |
| `task.create` | `payload_task_create` | opt-in | todos | re-checa os hosts do target (linha 9) → `create_task` (alvo/agenda do tenant; scanner padrão `OpenVAS Default`) | tenant | `output_task_create` |
| `task.modify` | `payload_task_modify` | opt-in | todos | com `target_id`, re-checa os hosts do novo target; com `schedule_id` não vazio, os do target da tarefa (linha 9) → `modify_task` (`schedule_id: ""` desvincula) | tenant | `output_task_modify` |
| `task.clone` | `payload_task_clone` | opt-in | todos | tarefa de origem com agenda ⇒ re-checa os hosts do target dela (linha 9) → `clone_task` (+ renomeia se `name`) | tenant | `output_task_clone` |
| `task.delete` | `payload_task_ref` | opt-in | todos | `delete_task(ultimate=false)` → **lixeira** | tenant | `output_trash` |
| `target.create` | `payload_target_create` | opt-in | todos | portão de escopo → `create_target` | tenant | `output_target_create` |
| `target.modify` | `payload_target_modify` | opt-in | todos | portão de escopo nos `hosts` resultantes: os novos ou, sem `hosts` no payload, os atuais lidos no gvmd (`exclude_hosts` só literal) → `modify_target` | tenant | `output_target_modify` |
| `target.delete` | `payload_target_ref` | opt-in | todos | `delete_target(ultimate=false)` → **lixeira** | tenant | `output_trash` |
| `schedule.create` | `payload_schedule_create` | opt-in (com `task_ids`, também exige `task.modify` permitido) | todos | com `task_ids`, re-checa os hosts dos targets dessas tarefas (linha 9) → `create_schedule` + `modify_task(schedule_id)` p/ cada `task_ids` | tenant | `output_schedule_create` |
| `schedule.modify` | `payload_schedule_modify` | opt-in | todos | re-checa os hosts dos targets das tarefas ligadas à agenda (linha 9) → `modify_schedule` | tenant | `output_schedule_modify` |
| `schedule.delete` | `payload_schedule_ref` | opt-in | todos | `delete_schedule(ultimate=false)` → **lixeira** | tenant | `output_trash` |
| `report.export` | `payload_report_export` | permitido (conta no orçamento) | todos | `get_report` com formato/idioma/variante (edição)/filtro **explícitos** e, se houver `delta_report_id`, em modo delta → gzip → `PUT` artefato; combinação não anunciada ⇒ `unsupported_report_variant` | atual | `output_report_export` + `artifacts[1]` |
| `report.summary` | `payload_report_summary` | permitido (conta no orçamento) | todos | `get_report` com o filtro que o **nó** monta de `min_qod`/`apply_overrides`/`levels` (sem filtro livre) → só contagens: por severidade, por faixa de QoD, nº de hosts e por IP | atual | `output_report_summary` |
| `agent.scan_now` | `payload_agent_ref` | permitido | central | API admin local `POST /api/v1/agents/{id}/commands` (`scan_now` = re-coleta de inventário, **não** varredura) | — | `output_agent_scan_now` |
| `agent.revoke` | `payload_agent_revoke` | opt-in | central | API admin local `POST /api/v1/agents/{id}/revoke` (nova, F2.2): revoga **só** os serials desse agente | — | `output_agent_revoke` |
| `enroll_token.create` | `payload_enroll_token_create` | opt-in | central | `POST /api/v1/tokens` com o tenant do envelope e **só** `policy=agent-endpoint` (TTL ≤ 168 h; `deployment` ≤ 1000 usos); token `scanner-sensor` continua local, com admin-bearer (ADR-0007) | — | `output_enroll_token_create` (`contains_secret: true`) |
| `enroll_token.revoke` | `payload_enroll_token_revoke` | opt-in | central | revoga **só o token** (corta enrolls futuros) pela rota da F2.2; os certificados já emitidos continuam válidos — revogá-los em massa é ação **local** (o `DELETE /api/v1/tokens/{id}` de hoje revoga tudo) | — | `output_enroll_token_revoke` |
| `sensor_job.enqueue` | `payload_sensor_job_enqueue` | opt-in | central | portão de escopo local → `POST /api/v1/tenants/{t}/scan-jobs` (`source=operator-scope`) só com `targets` (+ `ports`); o sensor usa o alive test, a scan config e a duração **dele** (ADR-0007) | — | `output_sensor_job_enqueue` |
| `feed.sync_now` | `payload_empty` | opt-in | central, standalone | feed-updater `POST /sync` (assíncrono; `409` dele = `already_running`) | — | `output_feed_sync_now` |

Regras transversais:

- **Política local** (`FLEET_STATE_DIR/policy.json` = `{"allow": [...], "sensitive_per_hour": n,
  "total_per_hour": m}`, o mesmo objeto que vai em `policy` no estado `node`). Sem o arquivo: `allow` = os tipos
  "permitido" suportados pelo `node_kind`, `sensitive_per_hour` = 30 e `total_per_hour` = 120. Opt-in = o
  operador **local** acrescenta o tipo em `allow`; nenhum comando altera a política. `policy_sha256` = sha256
  do objeto em JSON compacto, com chaves ordenadas e `allow` ordenado — o hub recalcula a partir do estado.
  **Dois orçamentos**, cada um numa janela **deslizante** de 1 h persistida no reinício: o **global** de
  aceitos (`total_per_hour`, qualquer tipo) e o de **sensíveis** (`sensitive_per_hour`: opt-in,
  `report.export` e `report.summary`, que contam nos dois). **Só comando aceito consome**: a linha 7 só
  pergunta se aceitar este estouraria algum dos dois, e o consumo é gravado junto com a decisão `accepted`. O
  global limita o quanto um hub comprometido faz crescer o fluxo `exec` da auditoria (conta em "Hub
  comprometido").
- **Objeto único.** Cada comando age sobre **um** objeto (sem operação em lote). O raio não é zero em dois
  casos, declarados: um token `deployment` (≤ 1000 usos, ≤ 168 h) habilita até 1000 enrolls de agente; e
  `agent.revoke` corta um agente de vez (volta só com re-enroll local). Revogação em massa de certificados não
  existe no v1 — é ação local.
- **`report.summary` sem filtro livre.** O hub escolhe só `min_qod` (0–100), `apply_overrides` e `levels`
  (subconjunto de `chmlg`, nessa ordem); o nó monta `apply_overrides=<0|1> min_qod=<n> levels=<levels> rows=-1`
  e devolve só contagens (por severidade, por faixa de QoD, nº de hosts e por IP). Não há como estreitar por
  host, porta, NVT, nome, CVE ou vulnerabilidade, e nenhum OID, nome ou CVE sai: isso só por `report.export`.
  Conta no orçamento de sensíveis.
- **Escopo, regra completa.** Passa pelo portão todo host que entra no gvmd pela frota e todo host que uma
  tarefa vai varrer por ordem dela. Isso inclui iniciar (`task.start/resume`), apontar para um target
  (`task.create/modify` com `target_id`) e ligar uma agenda a uma tarefa ou alterar uma agenda ligada a tarefas
  (`schedule.create` com `task_ids`, `task.modify` com `schedule_id` não vazio, `task.clone` de tarefa com
  agenda, `schedule.modify`): nesses casos, os hosts dos targets de todas as tarefas afetadas.
  - O portão exige IP/CIDR literal (host não literal no target ⇒ `scope_denied`), ⊆ escopo do tenant, fora do
    espaço degenerado e **sem conter** IP próprio nem do hub.
  - IP próprio = `FLEET_SELF_DENY_IPS`. IPs do hub = os que o conector resolve sozinho de `FLEET_HUB_URL`, na
    subida e a cada conexão, mais o IP remoto de cada conexão estabelecida; ele os soma ao self-deny, e sem
    eles não há conexão nem comando.
  - `exclude_hosts` só precisa ser IP/CIDR literal (acrescentar exclusão nunca amplia) e **não salva** um
    `hosts` que contenha IP próprio ou do hub: esse CIDR é negado mesmo que `exclude_hosts` cubra o IP.
  - Num `target.modify`, encolher `exclude_hosts` amplia o conjunto efetivo só **dentro** do escopo já checado:
    os hosts resultantes passam pelo portão em todo `target.modify`, e o self-deny não depende de
    `exclude_hosts`. A F2.3 confirma no gvmd se um target em uso aceita modificação.
  - Consequência operacional: um alvo que cubra o próprio nó (ex.: o `/24` inteiro da LAN onde ele mora) é
    negado, e o hub precisa montar faixas que não o contenham — o nó nunca injeta exclusões sozinho.
  - O `sensor/internal/scope` de hoje só nega IP próprio isolado; a F2.4 fecha isso no pacote extraído, com
    teste.
- **Lixeira, nunca `ultimate`.** Restaurar ou esvaziar a lixeira é ação **local** (GSA). Criação e alteração
  não têm rollback automático: `output_*_modify.before` traz os valores anteriores dos campos alterados
  (exceto `comment`) para reverter à mão.
- **Rastreabilidade na GSA.** O nó prefixa o `comment` de objeto criado/alterado com `fleet:<command_id> `.
- **Target sem nada além de hosts literais:** sem credenciais, sem `asset_hosts_filter`, sem reverse lookup;
  no `target.create`, exatamente um entre `port_list_id` e `port_range` (`^[TU]:[0-9,-]+$`, a gramática do
  `scan_bridge.py`); no `target.modify`, só `port_list_id` muda as portas — o `modify_target` do gvmd não tem
  `port_range`.
- **Alive test (decisão D9 do plano).** O valor de `alive_test` no contrato é o **nome de um conjunto** de
  métodos do gvmd, e o `fleet_ops.py` nunca manda esse nome ao gvmd. O gvmd 26 recusa o literal combinado
  (`ICMP, TCP-SYN Service & ARP Ping`) num valor único de `alive_tests` e aceita a combinação como **vários
  sub-elementos** `<alive_test>` de `<alive_tests>`. O `fleet_ops.py` monta um sub-elemento por método com o
  `XmlCommand` do python-gvm (nunca string formatada):

  | `alive_test` (contrato) | sub-elementos `<alive_test>` enviados |
  |---|---|
  | `ICMP, TCP-SYN Service & ARP Ping` (padrão quando omitido) | `ICMP Ping`, `TCP-SYN Service Ping`, `ARP Ping` |
  | `ICMP, TCP-ACK Service & ARP Ping` (fallback) | `ICMP Ping`, `TCP-ACK Service Ping`, `ARP Ping` |
  | `ICMP & TCP-ACK Service Ping` | `ICMP Ping`, `TCP-ACK Service Ping` |
  | `ICMP & ARP Ping` | `ICMP Ping`, `ARP Ping` |
  | `TCP-ACK Service & ARP Ping` | `TCP-ACK Service Ping`, `ARP Ping` |
  | `ICMP Ping`, `TCP-ACK Service Ping`, `TCP-SYN Service Ping`, `ARP Ping`, `Consider Alive`, `Scan Config Default` | um só, o próprio valor |

  - **Fallback documentado:** só se o gvmd recusar o padrão, o nó refaz com o conjunto
    `ICMP, TCP-ACK Service & ARP Ping`, também em sub-elementos.
  - `alive_test_effective` reporta, pelo nome do contrato, o conjunto de fato aplicado.
  - O nó **nunca** cai em silêncio para `Consider Alive` (varre host morto: lento e barulhento) nem para
    `Scan Config Default`.
  - Na leitura (estado `targets`, `before.alive_test`), o nó reporta o nome do contrato quando o conjunto lido
    casa um da tabela; senão, os métodos lidos unidos por `, `.
  - Que o gvmd 26.x aceita o padrão em sub-elementos continua item de confirmação em LAB (F2.3).
- **`report.export`.** `format`, `lang` e `variant` são sempre explícitos. `variant` é a **edição** do
  relatório (decisão D10 do plano): `technical` (o Premium PDF de hoje), `client` (sem falsos positivos; Log só
  como contagem; QoD baixo como "a validar") e `executive` (sumário). Cada edição × idioma é um objeto de report
  format próprio (fatia R5: 3 edições × 3 idiomas). Formatos `gvm-*` só existem em `en` + `technical`.
  **Completo × delta não é variante:** é só o `delta_report_id` opcional — presente ⇒ export delta contra esse
  report anterior da **mesma** tarefa; ausente ⇒ export completo. Um `delta_report_id` inexistente, de outra
  tarefa ou de outro tenant falha na execução com `not_found` (exige consulta GMP). Mapeamento local
  `(format, lang, variant) → report_format_id`:

  | `format` | `lang` | `variant` | `report_format_id` | Fonte |
  |---|---|---|---|---|
  | `suricatoos-pdf` | `en` / `pt_BR` / `es` | `technical` | `c6482c1b-57bb-406b-a501-c97eed86ad05` / `e43a4f20-d845-4916-83f0-851ac6dc5e57` / `91afce49-21fd-4ea0-ba16-7ba2bc51a03a` | `report-formats/build-feed-xml.py` |
  | `suricatoos-pdf` | `en` / `pt_BR` / `es` | `client`, `executive` | objetos novos da fatia R5 (ainda não existem) | R5 |
  | `gvm-xml` | `en` | `technical` | `a994b278-1f62-11e1-96ac-406186ea4fc5` | python-gvm `ReportFormatType.XML` |
  | `gvm-csv-results` | `en` | `technical` | `c1645568-627a-11e3-a660-406186ea4fc5` | `ReportFormatType.CSV_RESULTS` |
  | `gvm-pdf` | `en` | `technical` | `c402cc3e-b531-11e1-9163-406186ea4fc5` | `ReportFormatType.PDF` |

  O nó anuncia em `capabilities.report_formats` do estado `node` (`[{format, lang, variants:[…]}]`) só as
  combinações cujos objetos estão presentes e confiáveis no seu gvmd; até a R5 entrar, anuncia só `technical`.
  Um pedido válido no schema mas para combinação não anunciada é rejeitado (ack) com
  `unsupported_report_variant` — nunca cai em silêncio para outra edição.

  **Filtro explícito (normativo).** O export nunca cai nos padrões escondidos do gvmd (`min_qod=70`,
  `apply_overrides=0`). O `filter` tem de trazer os três tokens, explícitos e em qualquer ordem:
  - `apply_overrides=` com `0` ou `1`;
  - `min_qod=` com um inteiro de 0 a 100, em decimal sem zero à esquerda;
  - `levels=` com um subconjunto de `chmlgf`, sem repetir letra e em qualquer ordem.

  Os tokens são o filtro dividido por espaço (aspas não agrupam). Um token é de uma dessas chaves quando é a
  chave sozinha ou começa pela chave seguida de uma relação (`=`, `<`, `>`, `~` ou `:`) — uma palavra solta igual à
  chave seria termo de busca para o gvmd e estreitaria o export em silêncio. Cada chave aparece exatamente uma vez, com `=` e
  valor válido; senão, `bad_payload` (linha 8), e o `fleet_ops.py` também recusa. É regra semântica, não padrão do
  schema, porque o RE2 do Go não tem lookahead; o `validate_fleet_examples.py` a confere (checagem
  `export_filter`).
- **Escopo em `sensor_job.enqueue`:** **todos** os alvos passam pelo portão local; um fora do escopo rejeita o
  comando inteiro (`scope_denied`) — nada é descartado em silêncio. A `sensorjobs` ainda aplica o seu próprio
  portão (defesa em profundidade). No v1 o payload só leva `targets` e `ports`: o sensor aplica o alive test,
  a scan config e a duração máxima **dele** (`scanrun` do ADR-0007), e o contrato não finge controlá-los.
- **Fora do v1, por desenho:** ampliar/alterar escopo ou tenant; usuários, papéis e permissões do gvmd;
  credenciais de alvo (SSH, SMB, ESXi, SNMP); token de enroll `scanner-sensor` e revogação em massa de
  certificados; parâmetros de varredura do sensor no `sensor_job.enqueue`; aprovar/rejeitar remediação;
  passthrough GMP; esvaziar lixeira ou `delete ultimate`; editar a política local. O único segredo que o v1
  cria é o token `agent-endpoint` do `enroll_token.create` (uso único ou limitado, TTL ≤ 168 h, entregue uma
  vez).

## Estado e eventos

### Estado (`PUT /fleet/v1/state/{kind}`)

Cada PUT é o **retrato completo** de um kind (`fleet-state.schema.json`, `data` em `#/$defs/data_<kind>`). O
nó coleta a cada `FLEET_STATE_INTERVAL` (60 s), calcula `content_sha256` sobre os bytes de `data` e **só
envia quando o hash muda**; o heartbeat leva os hashes atuais e o hub pede **resync** (resposta do heartbeat
ou comando `state.resync`) quando os dele divergem. A leitura usa o usuário gvmd atual, que só enxerga os objetos
dos tenants com a permissão Super do Catálogo. Todo kind de lista leva `items` + `truncated` +
`unattributed_count`: objeto cujo dono gvmd (ou `O` do certificado) não mapeia para tenant conhecido é só
**contado**, nunca listado.

| `kind` | Nós | Conteúdo | Fonte local | O que **não** vai |
|---|---|---|---|---|
| `node` | todos | versões, feeds NVT/SCAP/CERT/GVMD_DATA com versão e idade, saúde, capacidades (tipos suportados, `report_formats` = combinações format/lang/variants que o nó renderiza), política local + `policy_sha256` | gvmd (`get_version`, `get_feeds`, `get_report_formats`), conector | — |
| `tasks` | todos | id, tenant, nome, status, progresso, ids de alvo/config/scanner/agenda, último report, nº de reports | `get_tasks` (filtro explícito) | `comment` |
| `targets` | todos | id, tenant, nome, entradas IP/CIDR **literais** (≤ 256) + contagens, alive test, em uso | `get_targets` | hostnames (só contados), credenciais, `comment` |
| `schedules` | todos | id, tenant, nome, fuso, iCalendar, tarefas ligadas e, só quando o gvmd a fornece, a próxima execução (o `get_schedules` do gvmd 26 não traz; o `fleet_ops.py` hoje a omite) | `get_schedules` | `comment` |
| `reports` | todos | id, tarefa, tenant, status, início/fim, contagens por severidade, nº de hosts | `get_reports` sem detalhes | **qualquer achado** |
| `agents` | central | agent_id (por padrão = **hostname** do host; pode ser dado pessoal), tenant, policy, SO/arch/versão, último contato, online | API admin local (F2.2) + online do ingest | campo de hostname separado, inventário |
| `tokens` | central | id, tenant, tipo, policy, usos, expiração, revogado | `GET /api/v1/tokens` | segredo, `created_by` |
| `sensors` | central | sensor_id, tenant, último contato, online, versão de feed, gvmd_up, jobs ativos | heartbeats do ADR-0007 (persistidos na F2.2) | — |
| `scan_requests` | central | jobs de sensor: id, tenant, estado, **nº** de alvos, criação/expiração | `sensorjobs` (F2.2) | os alvos; pedidos do loop ADR-0006 (sem tenant: só contados) |
| `remediation` | central | jobs do ADR-0010: id, tenant, agent_id, tipo, estado, datas — **leitura** (D3) | `remediation` (F2.2) | payload, assinatura, before/after |
| `scope` | todos | por tenant: habilitado, CIDRs, se há usuário gvmd de escrita, origem — **leitura** (D2) | `TENANTS_FILE` ou `FLEET_TENANT` + `FLEET_SCAN_SCOPE` | nome e senha do usuário gvmd |
| `audit_tail` | todos | últimas ≤ 200 linhas **verbatim** de cada fluxo da auditoria local (`exec` e `reject`) + `first_seq`/`last_seq`/`head_sha256` de cada um | `audit-exec.jsonl`, `audit-reject.jsonl` | segredo (nunca está lá) |

Nomes de tenant que não casam `^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$` ficam fora da frota (contados como não
atribuídos).

### Eventos (`POST /fleet/v1/events`)

Outbox **durável** no `FLEET_STATE_DIR`, lotes de até 100, **entrega ≥ 1 vez** com `event_id` (UUIDv4) e
**dedup no hub**. Eventos derivados de diff têm a granularidade da coleta (uma tarefa que vai de `Requested` a
`Done` em menos de 60 s gera um único evento) e disparam **na transição**, não a cada coleta.

| Evento | Escopo | Gatilho | `data` (`fleet-event.schema.json#/$defs/…`) |
|---|---|---|---|
| `connector.started` | nó | início do conector | `data_connector_started` |
| `task.status_changed` | tenant | status mudou entre duas coletas | `data_task_status_changed` |
| `report.completed` | tenant | report chegou a `Done` | `data_report_completed` (resumo = contagens) |
| `agent.online` / `agent.offline` | tenant | transição do `online` do ingest (janela de 35 min) | `data_agent_presence` |
| `feed.stale` | nó | idade do feed passou de `FLEET_FEED_STALE_HOURS` (72) | `data_feed_stale` |
| `feed.updated` | nó | versão do feed mudou | `data_feed_updated` |
| `remediation.pending_approval` | tenant | job ADR-0010 novo em `PENDING_APPROVAL` (aprovação continua **local**) | `data_remediation_pending` |
| `command.rejected_by_policy` | tenant | comando **autêntico** recusado localmente (linhas 6–9) | `data_command_rejected` |

Eventos de escopo **nó** não levam `tenant`; os de escopo **tenant** levam sempre.

### Auditoria local

- **Dois fluxos append-only**, uma linha JSON por evento (`fleet-state.schema.json#/$defs/audit_entry`):
  `FLEET_STATE_DIR/audit-exec.jsonl` (fluxo `exec`: `connector_started`, `identity_changed`, `policy_changed`
  e, para cada comando **aceito**, `received` → `executed` → `result`) e `FLEET_STATE_DIR/audit-reject.jsonl`
  (fluxo `reject`: `rejected` + motivo, `deferred` + motivo, as contagens periódicas `unauthenticated` e
  `redelivered` — envelopes da linha 2a, que não ganham linha própria — e `version_mismatch`, a entrada em
  `blocked_version` com as versões dos dois lados).
- **Encadeados por hash, cada um com o seu `seq`:** `seq` monotônico (+1 por linha, atravessa a rotação) e
  `prev_sha256` = sha256 dos bytes exatos da linha anterior do mesmo fluxo (sem o `\n`); a 1ª linha de cada
  fluxo usa 64 zeros. **Orçamentos de rotação separados** — `exec` 32 MiB × 8 arquivos, `reject` 32 MiB × 4 —,
  então uma enchente de rejeições nunca apaga o registro do que foi executado; a cadeia atravessa a rotação.
- **O "quê", limitado:** cada linha de comando leva `command_id`, `type`, `tenant`, `issued_by`,
  `payload_sha256` e os campos de evidência: `object_ids` (task/target/schedule/report, agente, token, job;
  ≤ 17); `hosts` (os primeiros 64 hosts/alvos de `target.*` e `sensor_job.enqueue`) + `hosts_count`; `report`
  (`report_id`, `format`, `lang`, `variant`, `delta_report_id`, `filter` do export ou os parâmetros do
  sumário); e, no `result` do `report.export`, `artifact` (sha256 e tamanho do que saiu). **Sem segredo:** o
  único segredo do contrato é a **saída** do `enroll_token.create`, que nunca é escrita.
- **Anti-enchente:** linhas 0–2 e reentregas (linha 2a) só como contagem periódica — no máximo uma linha
  `unauthenticated` e uma `redelivered` por minuto —, e no máximo uma linha `version_mismatch` a cada 10 min. O
  nó nunca faz poll mais de uma vez a cada 5 s, qualquer que seja o `poll_wait_s`. Entra em backoff exponencial
  (até 5 min) quando um poll que trouxe comandos não resulta em nenhum comando **novo** aceito: rejeições,
  reentregas e adiamentos contam como nada novo. O `204` do fim do `wait` é o ciclo normal e não conta.
- Cada linha é gravada (`O_APPEND` + `fsync`) **antes** do efeito que registra (`rejected` antes do ack,
  `executed` antes do exec).
- **Visível ao operador local:** os arquivos no host e a superfície local do conector (F2.2). O hub recebe as
  caudas **verbatim** dos dois fluxos (`audit_tail`) e serve de **testemunha**: reescrever a auditoria no nó
  quebra a cadeia que o hub já viu, e a **regra de lacuna** do hub (`first_seq` > último `seq` visto + 1 ⇒
  alerta) denuncia linhas que sumiram entre duas caudas — por enchente ou adulteração; a lacuna é alerta, não
  prova.

## Segurança

### Ameaças e mitigações

| Ameaça | Mitigações | Residual (honesto) |
|---|---|---|
| **Hub comprometido** (fila + chave de comando) | catálogo fechado (sem escopo, tenant, usuários/RBAC, credenciais de alvo, aprovação de remediação, passthrough GMP); escrita **opt-in por nó** (padrão = só operação e leitura); escopo local e inalterável remotamente (D2), re-checado também ao iniciar ou agendar tarefa; comando de objeto único; delete só para a lixeira; `report.summary` só com contagens; orçamentos locais de 120 aceitos/h e 30 sensíveis/h; auditoria local encadeada; kill switch local (`FLEET_ENABLED=false` ou parar o profile) | dentro da política local, o hub age: inicia/para tarefas existentes, lê contagens e exporta relatórios (permitidos por padrão; quem não quiser remove `task.*`/`report.*` de `allow`). Se o operador liberar os comandos de token: **(a)** `enroll_token.create` minta tokens `agent-endpoint` (≤ 1000 usos, ≤ 168 h) para qualquer tenant conhecido do nó, e um agente falso injeta inventário falso naquele tenant; **(b)** `enroll_token.revoke` revoga tokens e trava enrolls novos (DoS de onboarding) — certificados já emitidos não caem. **(c)** Com comandos permitidos, o hub faz crescer o fluxo `exec` da auditoria (3 linhas por aceito) para empurrar a rotação. O orçamento global limita isso a 120 × 24 × 3 = 8 640 linhas/dia: ~3,7 MB/dia com linhas típicas (~0,4 KiB), e os 256 MiB do `exec` guardam ~2,5 meses. No pior caso que os campos limitados permitem (`issued_by` de 128 caracteres e os 30 sensíveis/h como `target.create` opt-in com 64 hosts IPv6 na linha), ~10 MB/dia, ~4 semanas. Sem o orçamento global (~2 aceitos/s no piso de poll), seriam ~200 MB/dia, pouco mais de 1 dia. Reentregas (linha 2a) não gravam linha no `exec`, só contagem no `reject`, e não mudam a conta. A regra de lacuna do hub não ajuda aqui, porque a testemunha é o próprio atacante |
| **MITM** nó↔hub | TLS ≥ 1.3 + mTLS; servidor verificado (`FLEET_HUB_CA_FILE` ou trust store; hostname sempre) **e pinado** (`FLEET_HUB_PIN`, obrigatório, lista para rotação — uma CA de interceptação na rede do cliente não basta); comando assinado com chave **separada** da CA e do TLS (um terminador TLS não forja comando); pins da CA da frota e da chave de comando entregues out-of-band no enroll; envelope não autenticado não gera ack nem linha individual de auditoria (só contagem), então o MITM não finaliza comando legítimo nem enche a auditoria | com TLS quebrado, o atacante lê estado/resultados e atrasa ou derruba comandos (DoS); não executa nada |
| **Replay** | nonce **e** `command_id` indexados no store persistido, decisão final gravada antes do ack (menos `bad_window`/`expired`, finais e não gravados: ali a regra de não re-assinar é normativa para o hub); o hub nunca re-assina um `command_id`; janela ≤ 24 h; relógio de verificação monotônico (marca d'água persistida); `node_id` e `tenant` dentro da assinatura; store ilegível ou ausente, ou (re)enroll ⇒ piso de replay publicado (`replay_floor`), e o hub não emite abaixo dele + 10 min; no (re)enroll o hub descarta os comandos nunca entregues e marca `unknown_outcome` os entregues sem desfecho | — |
| **Nó comprometido** | o certificado identifica só aquele nó (CN=`node_id`, `OU=fleet-node`, CA da frota separada da CA de enroll); o hub autoriza tudo pelo CN (`403`/`404`); o nó não tem chave de assinatura; o hub trata **todo** dado de nó como não-confiável — nunca deriva autorização dele, nunca o cruza para outro nó ou tenant, e escapa ao renderizar (nomes são texto livre: XSS armazenado) | o nó mente sobre o próprio estado e resultados; revogar no hub corta o canal, não o nó |
| **Exfiltração** | D4: estado e eventos só com metadado e contagens; `report.summary` (orçado) só devolve contagens — por severidade, por faixa de QoD, nº de hosts e por IP —, com filtro montado pelo nó, sem estreitar por host, porta ou NVT; achado detalhado (NVT, CVE, porta, evidência) só via `report.export` explícito, orçado e removível da política; nada de `comment`, inventário ou segredo; artefato com sha256 e teto; hub fora da internet (tailnet) no canário | com a política padrão, um hub comprometido vê, por relatório, **quais IPs têm quantas vulnerabilidades por severidade** (`report.summary`) e baixa relatórios completos (`report.export`), tudo no ritmo do orçamento (30/h somados) e registrado na auditoria local |
| **Abuso de escopo** | escopo LOCAL (registro de tenants ou `FLEET_SCAN_SCOPE`); só IP/CIDR literal (sem DNS rebinding); CIDR inteiro dentro do escopo; deny absoluto (loopback, link-local/metadata, multicast, não-especificado) e de **qualquer CIDR que contenha** IP próprio (`FLEET_SELF_DENY_IPS`) ou do hub; os hosts do target são re-checados também em `task.start/resume`, `task.create/modify(target_id)` e em todo comando que liga ou altera agenda de tarefa (`schedule.create` com `task_ids`, `task.modify` com `schedule_id`, `task.clone` de tarefa com agenda, `schedule.modify`); `exclude_hosts` não salva um CIDR com IP próprio ou do hub; sem credencial/asset filter/reverse lookup em target; `sensor_job.enqueue` passa pelo portão local **e** pelo da `sensorjobs` | um target criado localmente com host fora do escopo continua existindo, mas a frota não o dispara nem o liga a uma agenda (`scope_denied`); uma tarefa assim que **já** tem agenda local segue disparando pelo gvmd, por configuração local que a frota não toca; a lacuna de CIDR do `scope.go` atual só some com a F2.4 |
| **Roubo do token de enroll** | uso único, TTL curto, pins out-of-band, CSR com prova de posse, `node_id` único (`409`) | quem usar o token antes do dono enrola um nó falso: o hub deve confirmar o nó (CN/fingerprint) out-of-band antes de enfileirar comandos para ele |
| **Roubo da chave do nó** | chave `0600`, TTL de 30 dias + renew, revogação no hub, alerta de sessões concorrentes do mesmo CN (obrigação do hub) | até a revogação, o ladrão consome os comandos do nó (não os executa no nó) e forja estado/resultado em nome dele |
| **Adulteração da auditoria** (e enchente) | dois fluxos JSONL encadeados (`exec` e `reject`), cada um com `seq` monotônico e orçamento de rotação próprio — enchente de rejeição não apaga execução; orçamento global de 120 aceitos/h — uma enchente de comando permitido leva ≥ ~4 semanas para girar o `exec` (conta em "Hub comprometido"); linhas 0–2 e reentregas (linha 2a) só como contagem periódica; piso de poll e backoff; cauda dos dois fluxos como testemunha no hub, com regra de lacuna | root no nó reescreve os arquivos; o hub detecta a quebra da cadeia ou a lacuna de `seq` na próxima cauda |
| **Vazamento de segredo** | `contains_secret` só em `enroll_token.create`; segredo nunca em disco/log/auditoria do nó; reinício antes da entrega ⇒ token revogado localmente + `secret_lost`; o hub não loga, cifra em repouso e mostra uma vez | — |

### Honestidade operacional

- **Revogar o nó no hub corta comandos FUTUROS — não desfaz o que já foi executado.** Uma varredura
  iniciada segue até ser parada (no nó ou por novo comando antes da revogação); um alvo criado continua lá; um
  relatório exportado já saiu.
- **Escrita sempre vai para a lixeira** — delete não apaga; restaurar ou esvaziar é ação local. Criar e
  alterar não têm desfazer automático (só o `before` do resultado).
- **Desligar o conector** (`FLEET_ENABLED=false`/parar o profile) é o corte local imediato; um exec em
  andamento é interrompido e o resultado vira `interrupted`, sem desfazer o que o gvmd já aplicou.
- **`timeout` não prova ausência de efeito**: o estado seguinte é a verdade.
- O nó é a autoridade local, mas um hub comprometido age **dentro** da política local: a política padrão sem
  escrita é a barreira principal, não um detalhe.

## Multi-tenant

| Propriedade | Mecanismo |
|---|---|
| **Tenant explícito e assinado** | `tenant` está na forma canônica; o nó só aceita tenant conhecido **e habilitado** localmente (`tenant_unknown`) |
| **Partição gvmd** | escrita autenticada como o usuário gvmd do tenant (D6); operação em objeto existente exige dono == usuário do tenant, senão `not_found` (sem enumeração cross-tenant); leitura e checagem de dono pelo usuário atual, que precisa de Super sobre os usuários dos tenants (ou ser admin) — sem isso, os objetos dos tenants não aparecem |
| **Estado atribuído** | cada item leva o `tenant` derivado do dono; objeto sem tenant conhecido só entra em `unattributed_count` |
| **Escopo por tenant** | target/sensor job ⊆ escopo **daquele** tenant (registro central ou `FLEET_SCAN_SCOPE`) |
| **Agentes, tokens, sensores** | tenant = `O` do certificado do agente/sensor; token = `Scope.Tenant`; divergência do envelope ⇒ `not_found` |
| **Identidade do nó ≠ tenant** | `O=<org>` do certificado do nó é a organização dona do nó no hub, usada pelo hub para particionar nós; **não** concede tenant algum. O RBAC de operador por tenant é obrigação do hub; o nó é defesa em profundidade |
| **Standalone/sensor** | um único tenant local (`FLEET_TENANT`); comando para outro tenant ⇒ `tenant_unknown` |
| **Tenant é local ao nó (normativo)** | o nome vem do `TENANTS_FILE` ou do `FLEET_TENANT` de **cada** nó, então dois nós podem ter um "acme" que não tem nada a ver um com o outro. No hub, a chave do tenant é **`(node_id, tenant)`**, e o RBAC de operador chaveia nisso; tratar o nome como global misturaria estado, eventos e exports de clientes diferentes |

## LGPD

Do nó para o hub saem **metadado operacional e contagens** (D4): versões, saúde, ids e nomes de objetos GVM,
status, entradas IP/CIDR literais de alvos e escopos, contagens por severidade (por IP só no `report.summary`,
sob comando e orçado). **Não saem:** achados
detalhados (fora de `report.export` explícito), entradas não-literais (hostnames) de alvos,
`comment` de objetos, inventário de agentes, payload/resultado técnico de remediação, senhas, chaves e segredos
(exceto o segredo de `enroll_token.create`, uma vez, marcado). **Texto livre (normativo):** o que sai em texto
livre são nomes de objeto GVM (tarefa, target, agenda), escritos por um operador, e as mensagens curtas que o
próprio conector gera (`detail`, `error.message`); o nó **nunca** insere dado de achado (OID, nome de NVT, CVE,
porta, evidência) em texto livre. Os demais textos são valores de sistema ou de comando, também sem achado:
`os`/`arch` do agente, `alive_test`, `policy` do token, versões e os filtros GMP ecoados (`report.filter` na
auditoria, `filter_applied` no sumário). **`agent_id` pode ser dado pessoal:** por padrão o
agente usa o hostname como `agent_id` (ex.: nome de pessoa no nome da máquina), e ele sai no estado `agents` e
`remediation`, nos eventos `agent.*`/`remediation.pending_approval` e nos comandos `agent.*`. Base legal: execução
do serviço de segurança contratado; recomenda-se id não pessoal no enroll do agente (pseudonimização por HMAC é
questão aberta). `issued_by` (operador do hub) entra na auditoria do nó e é **obrigatoriamente pseudônimo** (o
schema recusa `@` e espaço). Detalhe completo, com direção, finalidade e
sensibilidade por dado: [docs/data-inventory.md — Canal de gestão da frota (ADR-0011)](../data-inventory.md#canal-de-gestão-da-frota-adr-0011).

## Rollout faseado

- **F2.1 — contrato Go (só código, sem rede).** Módulo `fleet/` + `fleet/contract`: tipos dos 6 schemas,
  `Canonical`/`Verify`/`VerifyAt`, checagens 0–4, validação por tipo, golden vectors em
  `fleet/contract/testdata/` e teste que valida exemplos contra `schema/fleet-*.schema.json`; `go.work` + CI do
  módulo.
- **F2.2 — API admin local.** No control-plane: bearer **dedicado** da frota (`FLEET_CP_TOKEN`) aceito **só**
  nas rotas que o conector usa; rotas novas `POST /api/v1/agents/{id}/revoke`, uma rota (ou variante) que
  revoga **só o token** (usada pelo `enroll_token.revoke` e pelo `secret_lost`) — o `DELETE /api/v1/tokens/{id}`
  de hoje revoga também os certificados — e listagens sem segredo
  (`GET /api/v1/agents`, `GET /api/v1/sensors` com heartbeats persistidos, `GET /api/v1/scan-jobs`,
  `GET /api/v1/remediation/jobs`); superfície do operador local (status, política, auditoria) atrás do gate de
  sessão gsad do nginx — sem porta nova. DARK.
- **F2.3 — `gmp-bridge/fleet_ops.py`.** Um subcomando por operação GVM do catálogo + leituras de estado;
  python-gvm; filtro explícito; checagem de dono; alive test em sub-elementos `<alive_test>`, com o fallback
  documentado (confirmar em LAB que o gvmd 26.x aceita o padrão assim); `target.modify` muda portas só por
  `port_list_id`; testes sem gvmd, no estilo de `test_scan_bridge.py`.
- **F2.4 — política, escopo, anti-replay e auditoria.** `policy.json` + padrão; portão de escopo extraído de
  `sensor/internal/scope` para pacote compartilhado (sem cópia divergente; `scope_test.go` e
  `degenerate_test.go` migram junto) e com a regra de CIDR que **contém** IP próprio ou do hub (o `scope.go`
  atual só nega IP isolado), testada, mais os IPs do hub no self-deny e o re-check de escopo das agendas e do
  `target.modify`; store anti-replay/journal (linha 2a, `redeliveries`, `replay_floor`, sem gravar
  `bad_window`/`expired` — com teste de store inalterado depois da linha 3 —, tamanho dimensionado com teto e
  alerta); auditoria encadeada; orçamentos global (`total_per_hour`) e de sensíveis.
- **F2.5 — estado e eventos.** Coletores por kind com hash; outbox durável; detecção de transições.
- **F2.6 — conector, compose e CI.** `fleet/cmd/fleet-connector` (enroll → renew → heartbeat → estado →
  long-poll → verificação → ack → execução → artefato → resultado); serviço `fleet-connector` no profile
  `fleet` dos compose do nó central, standalone e sensor, com `FLEET_ENABLED=false` e nenhuma porta publicada;
  imagem no GHCR; CI (build, vet, gofmt, `test -race`).
- **F2.7 — hub de referência + E2E.** Implementação **mínima** do lado hub neste repo (CA da frota, signer no
  molde de `signkeys`, fila, stores, artefatos), só para E2E em CI e para o canário — **não** é o
  commandcenter. O E2E cobre todo o catálogo contra um gvmd de teste e os ataques (replay, nó errado, tenant
  desconhecido, fora do escopo, payload trocado).
- **F2.8 — runbook + canário.** `docs/runbooks/gestao-remota-frota.md` (pré-requisito de deploy: usuário gvmd
  atual com Super sobre os usuários gvmd dos tenants, ou admin; enroll com pins, política, kill switch,
  revogação, teardown, leitura da auditoria). Canário com o hub de referência no host do commandcenter,
  alcançado **só pela tailnet**, contra um nó de **LAB** (nunca de cliente); cada degrau com autorização por
  ação e critério de saída:
  1. **só-leitura por 24 h** (`allow = [state.resync]`): estado no hub == GSA; cadeia de auditoria íntegra;
     nenhum dado fora do D4 no hub; nenhuma rejeição inesperada;
  2. **`report.export`** de um report de LAB (`variant: technical`, a única anunciada antes da R5; um pedido
     `client`/`executive` tem de voltar `unsupported_report_variant`): sha256 do artefato confere; auditoria e
     orçamento registram;
  3. **`task.start`/`task.stop` em tarefa de LAB**, cujo target fica **dentro** do escopo do tenant de teste e
     não contém o IP do nó nem do hub (senão `scope_denied`): estados e eventos coerentes; reentrega idempotente;
     comando endereçado a outro nó rejeitado (`wrong_node`) — como o hub responde `404` ao ack de comando de
     outro nó, esse critério se observa pelo `audit_tail` (fluxo `reject`);
  4. **`target.create` em tenant de TESTE** (opt-in só desse tipo): alvo dentro do escopo aceito; fora dele
     ⇒ `scope_denied` + evento; `alive_test_effective` registrado.
- **Rollback:** `FLEET_ENABLED=false` (instantâneo) ou parar o profile `fleet`; revogar o nó no hub; imagem
  anterior com `--no-deps`. Mudança de schema segue "Versões e evolução": acréscimo é versão MINOR negociada.
  Um rollback da imagem do nó volta a anunciar só as versões que ela suporta; um rollback do hub é coberto pelo
  `426` e pelo anúncio em toda resposta de heartbeat.

## Consequências

- 👍 Frota gerenciável **atrás de NAT**, sem porta nova em nó nenhum; o hub **não guarda credencial** de nó.
- 👍 **Autenticidade por comando** com chave separada, amarrada a nó, tenant, janela e nonce; golden vectors
  impedem o nó e o hub de divergirem.
- 👍 **Autoridade local preservada**: escopo, política e tenant são do nó; o hub não amplia nada.
- 👍 **Minimização LGPD** por contrato (schemas fecham os campos) e **auditoria local** com testemunha remota.
- 👍 Reusa padrões já testados no repo (phone-home do sensor, canonical da remediação, `signkeys`, `scope`,
  registro de tenants, `scan_bridge`) em vez de inventar mecanismo novo.
- 👎 Componente novo em **todo** nó (conector + `fleet_ops.py`) e superfície nova (o hub).
- 👎 Estado **eventual** (60 s) e latência de long-poll (~25 s); eventos com granularidade de coleta.
- 👎 A chave de comando é o ativo mais crítico do hub, e o v1 não a rotaciona.
- 👎 Catálogo fechado: tudo fora dele continua exigindo acesso local (GSA) — por desenho.
- ⚠️ Operação multi-passo para ligar (profile + flag + bundle com pins + política para escrita): de propósito,
  para não acender por engano.

## Questões abertas

1. **Rotação da chave de comando (v2).** Esquema (sobreposição de duas chaves; declaração de rotação assinada
   pela chave antiga; `key_id` na forma canônica de um domínio `suricatoos-fleet-command-v2`; re-pin no renew)
   e guarda da chave no hub (HSM/KMS × signer offline).
2. **Aprovação remota de remediação (v2).** Só atrás de política local e, provavelmente, dual-control; como
   levar o `issued_by` do hub ao `approved_by` do ADR-0010 sem enfraquecer a aprovação humana por ação.
3. **Retenção de objetos GVM criados/apagados pela frota.** Quem esvazia a lixeira e quando; retenção de
   reports e de artefatos no hub; prefixo de nome obrigatório para objetos da frota?
4. **KEV.** Marcar achados do catálogo CISA KEV em `report.summary`/`report.completed`? Fonte e atualização
   da lista, e se isso cabe no D4 (é contagem, não achado).
5. **Usuário gvmd de menor privilégio** para leitura e operação, em vez do usuário atual (D6 mantém o atual
   no v1).
6. **Top findings agregados com k-anonimato** no `report.summary` (só quando o conjunto cobrir ≥ *k* hosts),
   para priorizar sem abrir o achado por host. No v1, OID, nome e CVE só saem por `report.export`.
7. **Parâmetros de varredura no `sensor_job.enqueue`.** Follow-up do ADR-0007: o sensor passar a aceitar alive
   test, scan config e duração e devolver os valores **efetivos** — só então o contrato os expõe.
8. **Pseudonimização do `agent_id` (v2).** HMAC com chave do nó no canal da frota, com o nó traduzindo de volta
   nos comandos `agent.*`, para que o hostname não saia nem como identificador.
9. **Token do `enroll_token.create` cifrado (v2)** para uma chave do operador, em vez de em claro no resultado.
10. **Rebaixamento de nó com várias versões.** Quando o nó suportar mais de uma versão MAJOR.MINOR e o hub
    rebaixar, quais corpos já serializados na versão mais alta o nó reenvia rebaixados e quais descarta, e como
    isso aparece na auditoria.
11. **Cabeçalho `Upgrade` no `426`.** Se o hub deve acompanhar o `426` com o cabeçalho `Upgrade` (RFC 9110)
    além do corpo `version_unsupported`, e se o nó deve usá-lo.
