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
   pubkey **pinada** no enroll; (c) o TLS do servidor do hub. Vazar um não concede os outros.
2. **Envelope assinado com domínio `suricatoos-fleet-command-v1`**, *canonical* length-prefixed idêntico em
   disciplina ao da remediação, amarrando `node_id`, `tenant`, `type`, `issued_by`, janela, `nonce` e o
   `sha256` do payload.
3. **Verificação local fail-closed, em ordem fixa** (forma → hash do payload → assinatura → janela → nó →
   nonce → tenant → catálogo/política/orçamento → payload → escopo), com motivo de rejeição tipado e
   decisão **persistida antes** de qualquer efeito.
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
| política local | `FLEET_STATE_DIR/policy.json` (`allow`, `sensitive_per_hour`); só o operador local edita |
| portão de escopo | lógica de `sensor/internal/scope` extraída para pacote compartilhado (F2.4) |
| coletores de estado + outbox de eventos | hash por kind; outbox durável, entrega ≥ 1 vez |
| auditoria local | `FLEET_STATE_DIR/audit.jsonl`, append-only, encadeada por hash |
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
| `FLEET_ENROLL_TOKEN` | — | token `ft_<id>.<secret>` de uso único; só até o enroll, depois ignorado |
| `FLEET_CA_PIN` | — | `sha256:<hex>` do DER da CA da frota — **obrigatório** para o enroll |
| `FLEET_COMMAND_KEY_PIN` | — | `sha256:<hex>` do SPKI DER da chave de comando — **obrigatório** para o enroll |
| `FLEET_NODE_ID` | `node-<uuid>` gerado e persistido | CN do certificado; `^[a-z0-9][a-z0-9-]{2,63}$` |
| `FLEET_NODE_KIND` | — | `central` \| `standalone` \| `sensor` |
| `FLEET_STATE_DIR` | `/var/lib/suricatoos-fleet` | chave/cert (`0600`), pins, anti-replay/journal, outbox, auditoria, política |
| `FLEET_GMP_USER`, `FLEET_GMP_PASSWORD_FILE` | usuário gvmd atual do nó | leitura e operação (D6) |
| `FLEET_TENANT`, `FLEET_SCAN_SCOPE`, `FLEET_TENANT_GMP_USER`, `FLEET_TENANT_GMP_PASSWORD_FILE` | — | standalone/sensor: o **único** tenant local, seu escopo e seu usuário gvmd de escrita (D2/D6) |
| `TENANTS_FILE`, `SENSOR_TENANT_SECRETS` | os do compose | central: registro de tenants e senhas por tenant, montados **read-only** |
| `FLEET_SELF_DENY_IPS` | — | IPs do próprio nó e do hub: nunca alvo (como `SCAN_SELF_DENY_IPS`) |
| `FLEET_CP_TOKEN_FILE` | — | central: bearer **dedicado** da frota para a API admin local (o control-plane o recebe em `FLEET_CP_TOKEN`) |
| `FLEET_CLOCK_SKEW` | `2m` | tolerância de relógio (a mesma da remediação) |
| `FLEET_STATE_INTERVAL` | `60s` | período de coleta de estado (mínimo 30 s) |
| `FLEET_FEED_STALE_HOURS` | `72` | limiar do evento `feed.stale` |

Intervalo de heartbeat e `wait` do long-poll vêm do hub (`heartbeat_interval_s` 15–600, padrão 60;
`poll_wait_s` 0–30, padrão 25), no enroll e em cada heartbeat.

### Trace ponta a ponta (enroll → heartbeat → state → comando → verificação → execução → artefato → resultado)

O artefato sobe **antes** do resultado que o lista, para o hub nunca receber resultado que aponte para um
artefato ausente.

```
NÓ (só SAÍDA :443 mTLS)                                        HUB (commandcenter; canário: só via tailnet)
──────────────────────────────────────────────────────         ─────────────────────────────────────────────
 0. operador do hub cadastra o nó → bundle OUT-OF-BAND:
      FLEET_HUB_URL, FLEET_ENROLL_TOKEN=ft_…, FLEET_CA_PIN=sha256:…, FLEET_COMMAND_KEY_PIN=sha256:…
 1. operador do nó grava o bundle no env do host, FLEET_ENABLED=true, sobe o profile `fleet`
 2. enroll ── POST /fleet/v1/enroll {token, node_id, node_kind, csr(CN=node_id), connector_version}
        (TLS autentica o HUB; o nó ainda não tem cert) ─▶
        ◀── 200 {certificate CN=node_id O=<org> OU=fleet-node, ca_cert, command_pubkey, server_time, …}
        → sha256(ca_cert DER)==FLEET_CA_PIN e sha256(command_pubkey SPKI)==FLEET_COMMAND_KEY_PIN, senão aborta;
          pina ambos; esquece o token; auditoria: identity_changed
 3. heartbeat ── POST /fleet/v1/heartbeat {state_hashes{kind:sha}, outbox_events, …} ─▶
        ◀── 200 {server_time, resync:[kinds], heartbeat_interval_s, poll_wait_s}
 4. state ── PUT /fleet/v1/state/{kind} {content_sha256, data} — só kinds com hash novo ou em resync ─▶ ◀── 204
 5. no hub, um operador pede "iniciar a tarefa T do tenant acme no nó N": o hub monta e ASSINA o envelope
 6. poll ── GET /fleet/v1/commands?wait=25 ─▶ ◀── 200 {commands:[envelope…]}  |  204 ao fim do wait
 7. verificação LOCAL em ordem: forma → sha256(payload) → Ed25519 (chave PINADA) → janela ±skew → node_id → nonce
        → tenant → catálogo/node_kind/política/orçamento → payload → escopo  ⇒ decisão gravada com o nonce (fsync)
        auditoria: received → rejected(motivo) | executed
 8. ack ── POST /fleet/v1/commands/{id}/ack {decision: accepted|rejected, reason?} ─▶ ◀── 204
        (rejeição de comando AUTÊNTICO também vira o evento command.rejected_by_policy)
 9. execução serial: fleet_ops.py task-start (python-gvm, 1 exec, socket gvmd local, filtro explícito,
        dono do objeto == usuário gvmd do tenant) | API admin local | feed-updater POST /sync
10. artefato (só report.export) ── PUT /fleet/v1/artifacts/{command_id}/report.pdf.gz (gzip + sha256) ─▶ ◀── 201
11. resultado ── POST /fleet/v1/commands/{id}/result {status, output|error, artifacts[], contains_secret} ─▶ ◀── 204
        auditoria: result
12. eventos ── POST /fleet/v1/events {events:[task.status_changed, report.completed, …]} (outbox, ≥ 1 vez) ─▶ ◀── 204
13. renew ── POST /fleet/v1/renew {node_id, csr} com o cert ATUAL, 7 dias antes de expirar ─▶
        ◀── 200 (mesmo formato; command_pubkey tem de ser IDÊNTICA à pinada)
```

Cada hop é **saída do nó**; nenhuma porta inbound é aberta, nem no cliente, nem no nó central.

## Contrato

Os seis schemas (JSON Schema Draft 2020-12, `$id` `https://suricatoos.dev/schema/fleet-*.schema.json`) são a
fonte da verdade dos corpos; este capítulo fixa a semântica. Os **primitivos compartilhados** (`uuid`,
`node_id`, `tenant`, `utc_time`, `sha256_hex`, `ip_or_cidr`, `alive_test`, `command_type`…) vivem em
`fleet-command.schema.json#/$defs` e são referenciados pelos demais.

### Identidade do nó e CA da frota

- O nó gera o par de chaves **localmente** (Ed25519; ECDSA P-256 aceito) — a privada nunca sai do nó
  (`0600` em `FLEET_STATE_DIR`) — e um CSR com `CN = node_id`.
- **Enroll** (`POST /fleet/v1/enroll`, `fleet-enroll.schema.json#/$defs/enroll_request`): token **opaco de uso
  único** emitido pelo hub, no formato do ADR-0004 com prefixo próprio — `ft_<id>.<secret>` — para nunca ser
  confundido com um token `st_` do scanner. TTL curto (recomendado ≤ 24 h). O hub **atribui** `O=<org>`
  (a organização dona do nó no hub) e `OU=fleet-node`; o nó não os escolhe.
- **Pins out-of-band.** O bundle do hub traz `FLEET_CA_PIN` e `FLEET_COMMAND_KEY_PIN`; o nó **recusa** a
  resposta (`fleet-enroll.schema.json#/$defs/enroll_response`) se `sha256(DER da CA)` ou `sha256(SPKI da chave
  de comando)` não bater.
  Assim um MITM no enroll não planta a sua chave de comando. O conector também recusa pinar a chave de
  **teste** dos golden vectors (abaixo).
- **Renew** (`POST /fleet/v1/renew`, `fleet-enroll.schema.json#/$defs/renew_request`): autenticado pelo
  certificado **atual** (mTLS);
  o CSR mantém `CN = node_id`; o hub recusa certificado revogado (fail-closed, como `enroll.Renew`). TTL
  recomendado de 30 dias, renovação 7 dias antes do fim; o cliente recarrega o certificado a cada handshake.
  A resposta tem o mesmo formato do enroll e a `command_pubkey` tem de ser **idêntica** à pinada — diferente
  ⇒ o nó mantém a pinada e audita (`identity_changed`, detalhe `command_key_mismatch`). Certificado vencido
  não renova: exige novo enroll (token novo).
- **Obrigações do hub em toda rota mTLS:** certificado da CA da frota, `OU == fleet-node` **exato**,
  `CN == node_id`, revogação checada **fail-closed**; `node_id` do corpo ≠ CN → `403`; recurso de outro nó
  (comando, ack, resultado, artefato) → `404`, sem distinguir de inexistente.

### Chave de comando

Ed25519 dedicada, gerada e guardada só no hub (molde `control-plane/signkeys`: PKCS#8, `0600`, pubkey PKIX
PEM). A pubkey chega ao nó no enroll e fica **pinada**; o v1 **não rotaciona** (questão aberta). Nenhum nó
possui chave de assinatura: um nó comprometido não forja comando para outro.

### Envelope assinado e forma canônica

O envelope (`fleet-command.schema.json`) tem 12 campos: os 10 assinados abaixo + `payload` (objeto JSON) +
`signature` (base64 padrão dos 64 bytes Ed25519). A mensagem assinada é a **forma canônica**:

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
  ⇒ `bad_envelope`. Diferente da remediação, os dois são **obrigatórios** (vazio ⇒ `bad_envelope`).
- `schema_version` = `1.0.0`; `command_id` = UUID minúsculo; `nonce` = 32 bytes de CSPRNG em hex minúsculo
  (64 caracteres); `issued_by` = identificador do operador do hub (recomendado **pseudônimo**, ex.
  `op-7f3a`; ver LGPD).
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

O nó para na **primeira** falha. Os motivos são `fleet-result.schema.json#/$defs/reject_reason`.

| # | Checagem | Motivo se falhar | Nonce gravado? |
|---|---|---|---|
| 0 | forma: JSON estrito (campo faltando/desconhecido recusado), `schema_version == 1.0.0`, formatos exatos (tempos, nonce, assinatura), tamanhos | `bad_envelope` | não (não autenticado) |
| 1 | `sha256(bytes crus de payload) == payload_sha256` | `payload_mismatch` | não |
| 2 | Ed25519 sobre a forma canônica com a chave **pinada** (1 + 2 = `Verify`) | `bad_signature` | não |
| 3 | `issued_at < not_after ≤ issued_at + 24 h` | `bad_window` | não |
| 3 | `agora ≥ issued_at − skew` | `not_yet_valid` | não |
| 3 | `agora ≤ not_after + skew` (3 = `VerifyAt`, skew = `FLEET_CLOCK_SKEW`, 2 min) | `expired` | não |
| 4 | `node_id == CN do próprio certificado` | `wrong_node` | não |
| 5 | nonce já visto com **outra** forma canônica (mesma forma = reentrega, ver abaixo) | `replay` | — |
| 6 | `tenant` conhecido **e habilitado** no nó (central: `TENANTS_FILE`; standalone/sensor: `== FLEET_TENANT`); escrita exige também usuário gvmd + segredo do tenant | `tenant_unknown` | sim |
| 7 | tipo no catálogo v1 e suportado por este `node_kind` | `unsupported` | sim |
| 7 | tipo presente em `allow` da política local | `type_not_allowed` | sim |
| 7 | orçamento local de comandos sensíveis (opt-in + `report.export` + `report.summary`) não estourado | `rate_limited` | sim |
| 8 | payload válido para o tipo (schema estrito + regras semânticas) | `bad_payload` | sim |
| 8 | `report.export`: a combinação (`format`, `lang`, `variant`) está em `capabilities.report_formats` do estado `node` | `unsupported_report_variant` | sim |
| 9 | escopo: os hosts de `target.create/modify`, os alvos de `sensor_job.enqueue` e os hosts do target de `task.start/resume` e de `task.create/modify` com `target_id` (lidos no gvmd antes da decisão) são IP/CIDR literais ⊆ escopo do tenant, fora do espaço degenerado e **sem conter** IP próprio nem do hub | `scope_denied` | sim |
| — | o store anti-replay/journal não pôde ser gravado | `unavailable` | não (fail-closed) |

Na linha 0, `type` só precisa casar `^[a-z][a-z_]*\.[a-z][a-z_]*$` (`command_type_any`): um tipo fora do
catálogo é `unsupported` (linha 7), não `bad_envelope` — um hub conforme ao schema v1 nunca o envia.
Passou em tudo ⇒ decisão `accepted`. A decisão (aceita **ou** rejeitada nas linhas 6–9) é gravada com o nonce
**antes** do ack e de qualquer efeito. Rejeições das linhas 6–9 são de comando **autêntico**: além do ack,
viram o evento `command.rejected_by_policy`. Rejeições 0–5 aparecem só no ack e na auditoria local. O nó
responde com ack sempre que extrai um `command_id` válido. **Rejeição é definitiva** para aquele
`command_id`: corrigida a causa local, o hub emite **outro** comando (novo id, novo nonce).

### Anti-replay, idempotência e entrega

- **Store persistido** (`FLEET_STATE_DIR`, escrita atômica temp+rename com `fsync`, `0600`): `nonce →
  {command_id, sha256(forma canônica), decisão, resultado sem segredo}`; cada entrada vive até `not_after +
  skew` (o TTL do cache é ≥ `not_after`), o journal do resultado até 7 dias depois.
- **Reentrega ≠ replay.** O hub reentrega um comando entregue e não-ackado após 60 s, até `not_after`
  (entrega ≥ 1 vez). Mesmo nonce **e** mesma forma canônica ⇒ o nó **não executa de novo**: reenvia o ack e,
  se houver, o resultado já gravados. Mesmo nonce com forma diferente ⇒ `replay`.
- **Só grava nonce autenticado** (após a linha 4): gravar nonce de envelope não autenticado deixaria um MITM
  "queimar" nonces legítimos.
- **Store ilegível no boot** ⇒ o nó grava um **piso de replay** = agora e rejeita (`replay`, detalhe
  `cache reiniciado`) todo comando com `issued_at < piso + skew`; depois de 24 h + skew o piso deixa de
  importar (janela máxima). Sem o store, nenhum comando é aceito (`unavailable`).
- **Ack antes, resultado depois.** O ack é a **decisão**; o resultado, o **desfecho**. Crash entre o ack e o
  resultado ⇒ no boot o nó **não re-executa**: reporta `failed` com `error.code = interrupted` (o estado
  seguinte mostra o que de fato aconteceu).
- **Execução serial** (um comando por vez, na ordem recebida). Timeouts: 120 s; `report.summary` 5 min;
  `report.export` 15 min. `timeout` **não prova** ausência de efeito.
- **Resultado e artefato ≥ 1 vez.** Artefatos sobem **antes** do resultado que os lista; o resultado é
  reenviado com backoff até `2xx`; o hub responde `204` a repetição idêntica e `409` a conteúdo diferente, e
  aceita resultados de comando entregue por **≥ 7 dias** após `not_after` (a ação aconteceu dentro da janela).
- **Segredo (`enroll_token.create`).** O segredo do token fica **só em memória** até o hub aceitar o resultado;
  nunca vai a disco, log ou auditoria. Se o conector reiniciar antes da entrega, no boot ele **revoga** o
  token pela API admin local e reporta `failed` com `secret_lost`.

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
| `vectors[].expect` | `accept` ou um `reject_reason` |

O vetor `accept/task.start` é o exemplo acima: `command_json` = o envelope, `canonical` = os bytes assinados,
`canonical_sha256` = `a9a4d1759628b5708691988ce1512e3cbfa6881f90dfc0000d3fea08edcb7d74`,
`own_node_id` = `node-lab-0001`, `verify_at` = `2026-10-11T12:30:00Z`.

Vetores obrigatórios: `accept` (um por formato de payload);
`payload_mismatch` (payload trocado); `bad_signature` (cada um dos 10 campos alterado após assinar; outra
chave; mensagem assinada com o domínio da remediação); `not_yet_valid`/`expired` **nas bordas** (`issued_at −
skew` e `not_after + skew` aceitos; ±1 s rejeitado); `bad_window` (`not_after ≤ issued_at`; janela > 24 h);
`wrong_node`; `bad_envelope` (fração de segundo, offset, nonce maiúsculo, campo faltando, campo
desconhecido, `schema_version` 1.1.0); payload com UTF-8 (acentos) hasheado sobre os bytes crus. Vetores
**só-canonical** com valores contendo `\n`, `=` e `:` (que o envelope v1 recusa por formato) provam que o
framing é injetivo mesmo assim — e que um *join* ingênuo colidiria.

### Rotas do hub

Todas iniciadas pelo nó. JSON com `Content-Type: application/json`; `User-Agent:
suricatoos-fleet-connector/<versão>`. O corpo de **erro** é `text/plain` curto e **não-contratual** (≤ 2 KiB, só
para log, como os `http.Error` do repo): o nó decide **só pelo status**.

| Rota | Autenticação | Pedido | Sucesso | Erros esperados |
|---|---|---|---|---|
| `POST /fleet/v1/enroll` | TLS que autentica o hub + token `ft_` no corpo | `fleet-enroll.schema.json#/$defs/enroll_request` | `200` + `fleet-enroll.schema.json#/$defs/enroll_response` | `400` corpo/CSR inválido, prova de posse falhou, CN ≠ `node_id`; `403` token inválido, expirado, usado ou revogado (mensagem genérica); `409` `node_id` já registrado; `413`; `429` |
| `POST /fleet/v1/renew` | mTLS (certificado atual) | `fleet-enroll.schema.json#/$defs/renew_request` | `200` + `fleet-enroll.schema.json#/$defs/enroll_response` | `400` CSR inválido ou CN ≠ certificado; `403` certificado revogado/desconhecido; `413`; `429` |
| `POST /fleet/v1/heartbeat` | mTLS | `fleet-heartbeat.schema.json#/$defs/heartbeat_request` | `200` + `fleet-heartbeat.schema.json#/$defs/heartbeat_response` | `400`; `403`; `413`; `429` |
| `PUT /fleet/v1/state/{kind}` | mTLS | `fleet-state.schema.json` (`kind` == `{kind}`) | `204` sem corpo | `400` schema, `kind` ≠ caminho, `content_sha256` ≠ sha256 dos bytes de `data`; `403`; `404` kind desconhecido; `413`; `429` |
| `POST /fleet/v1/events` | mTLS | `fleet-event.schema.json` | `204` sem corpo (também com `event_id` repetido) | `400`; `403`; `413`; `429` |
| `GET /fleet/v1/commands?wait=25` | mTLS | sem corpo; `wait` inteiro 0–30 (s) | `200` + `fleet-command.schema.json#/$defs/poll_response` (1–10 comandos, mais antigo primeiro); `204` sem corpo se nada chegou até o fim do `wait` | `400` `wait` inválido; `403`; `429` |
| `POST /fleet/v1/commands/{id}/ack` | mTLS | `fleet-result.schema.json#/$defs/ack` | `204` sem corpo (ack idêntico repetido também) | `400`; `403`; `404` comando inexistente ou de outro nó; `409` decisão diferente já registrada; `429` |
| `POST /fleet/v1/commands/{id}/result` | mTLS | `fleet-result.schema.json` (`command_id` == `{id}`) | `204` sem corpo (resultado idêntico repetido também) | `400` schema, id ≠ caminho, artefato listado e não recebido; `403`; `404`; `409` resultado diferente já registrado; `413` > 256 KiB; `429` |
| `PUT /fleet/v1/artifacts/{command_id}/{name}` | mTLS | corpo **binário gzip** + cabeçalhos abaixo | `201` sem corpo (reenvio idêntico também) | `400` sha256 do corpo ≠ cabeçalho, cabeçalho faltando ou `name` inválido; `403`; `404` comando inexistente, de outro nó ou de tipo ≠ `report.export`; `409` outro conteúdo com o mesmo nome; `411` sem `Content-Length`; `413` > 64 MiB; `415` `Content-Type` ≠ `application/gzip`; `429` |

Em todas: `5xx`/`503` = falha transitória. O hub responde ao long-poll em até `wait + 5` s; o cliente usa
timeout maior que isso.

**Cabeçalhos do artefato:** `Content-Type: application/gzip`, `Content-Length`, `X-Fleet-Content-SHA256` (hex do
corpo gzip), `X-Fleet-Original-Content-Type` (`application/pdf` | `application/xml` | `text/csv`),
`X-Fleet-Original-Size`, `X-Fleet-Original-SHA256`. `name` casa `^[a-z0-9][a-z0-9._-]*$` (≤ 64); no v1,
`report.pdf.gz` | `report.xml.gz` | `report.csv.gz`. O resultado repete esses dados em
`fleet-result.schema.json#/$defs/artifact`; com `original_size` o hub limita a descompressão.

**Reação do nó por status:**

| Status | Reação |
|---|---|
| `200`/`201`/`204` | sucesso; retira o item da fila local |
| `400` | não reenvia o mesmo corpo (é bug de contrato); audita; o item fica "não entregável", visível ao operador local |
| `403` | identidade recusada: para de enviar; só tenta heartbeat a cada 10 min; estado local `blocked`; certificado vencido exige novo enroll |
| `404` | ack/resultado/artefato de comando que o hub não reconhece: descarta e audita; kind desconhecido: deixa de enviar esse kind |
| `409` | conflito de idempotência: não reenvia; audita |
| `413` | estado: corta no teto e marca `truncated`; demais: não reenvia e audita (o nó já confere os tetos antes de enviar) |
| `429`/`503` | respeita `Retry-After`; sem ele, backoff exponencial com jitter (1 s → 5 min) |
| outros `5xx`, erro de rede/TLS | backoff exponencial com jitter (1 s → 5 min); as filas duráveis preservam a ordem |

### Limites

| Item | Limite |
|---|---|
| envelope de comando | ≤ 64 KiB; `payload` ≤ 48 KiB |
| resposta do long-poll | 1–10 comandos, ≤ 1 MiB |
| janela do comando | `issued_at < not_after ≤ issued_at + 24 h` (recomendado: 1 h); skew 2 min |
| ack | ≤ 4 KiB |
| resultado | ≤ 256 KiB |
| heartbeat, enroll, renew | ≤ 64 KiB |
| estado (um kind) | ≤ 16 MiB; o nó PODE enviar `Content-Encoding: gzip` no PUT de estado e o hub DEVE aceitar; tetos de itens por kind no schema |
| lote de eventos | 1–100 eventos, ≤ 1 MiB |
| artefato | ≤ 64 MiB (67 108 864 bytes) de gzip; ≤ 4 por comando (v1: exatamente 1, só `report.export`) |
| outbox de eventos | 10 000 eventos; cheio ⇒ descarta os mais antigos e conta em `outbox_dropped` |
| orçamento local de comandos sensíveis | 30/h por nó (`policy.json` `sensitive_per_hour`), somando opt-in, `report.export` e `report.summary` |

## Catálogo de comandos v1

Payloads em `fleet-command.schema.json#/$defs/<payload>`, saídas em `fleet-result.schema.json#/$defs/<saída>`.
"Atual" = usuário gvmd atual do nó (D6), com checagem de que o **dono** do objeto é o usuário gvmd do tenant
do envelope (senão `not_found`, sem enumerar); "tenant" = a operação roda **autenticada como** o usuário gvmd
do tenant (o objeto nasce na partição dele).

| Tipo | Payload | Política padrão | Nós | Execução | Usuário gvmd | Saída |
|---|---|---|---|---|---|---|
| `state.resync` | `payload_state_resync` | permitido | todos | reenvia já os kinds pedidos (kind inexistente no nó é ignorado) | atual (leitura) | `output_state_resync` |
| `task.start` | `payload_task_ref` | permitido | todos | re-checa os hosts do target contra o escopo (linha 9) → `start_task` | atual | `output_task_action` |
| `task.stop` | `payload_task_ref` | permitido | todos | `stop_task` | atual | `output_task_action` |
| `task.resume` | `payload_task_ref` | permitido | todos | re-checa os hosts do target contra o escopo (linha 9) → `resume_task` | atual | `output_task_action` |
| `task.create` | `payload_task_create` | opt-in | todos | re-checa os hosts do target (linha 9) → `create_task` (alvo/agenda do tenant; scanner padrão `OpenVAS Default`) | tenant | `output_task_create` |
| `task.modify` | `payload_task_modify` | opt-in | todos | com `target_id`, re-checa os hosts do novo target (linha 9) → `modify_task` (`schedule_id: ""` desvincula) | tenant | `output_task_modify` |
| `task.clone` | `payload_task_clone` | opt-in | todos | `clone_task` (+ renomeia se `name`) | tenant | `output_task_clone` |
| `task.delete` | `payload_task_ref` | opt-in | todos | `delete_task(ultimate=false)` → **lixeira** | tenant | `output_trash` |
| `target.create` | `payload_target_create` | opt-in | todos | portão de escopo → `create_target` | tenant | `output_target_create` |
| `target.modify` | `payload_target_modify` | opt-in | todos | portão de escopo (se `hosts`/`exclude_hosts`) → `modify_target` | tenant | `output_target_modify` |
| `target.delete` | `payload_target_ref` | opt-in | todos | `delete_target(ultimate=false)` → **lixeira** | tenant | `output_trash` |
| `schedule.create` | `payload_schedule_create` | opt-in (com `task_ids`, também exige `task.modify` permitido) | todos | `create_schedule` + `modify_task(schedule_id)` p/ cada `task_ids` | tenant | `output_schedule_create` |
| `schedule.modify` | `payload_schedule_modify` | opt-in | todos | `modify_schedule` | tenant | `output_schedule_modify` |
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

- **Política padrão** (sem `policy.json`): `allow` = os tipos "permitido" suportados pelo `node_kind`;
  `sensitive_per_hour` = 30 (soma dos opt-in, `report.export` e `report.summary`). Opt-in = o operador **local** acrescenta o tipo em `allow`. Nenhum comando altera
  a política. `policy_sha256` = sha256 do JSON compacto da política (com `allow` ordenado), publicado no
  estado `node`.
- **Objeto único.** Cada comando age sobre **um** objeto (sem operação em lote). O raio não é zero em dois
  casos, declarados: um token `deployment` (≤ 1000 usos, ≤ 168 h) habilita até 1000 enrolls de agente; e
  `agent.revoke` corta um agente de vez (volta só com re-enroll local). Revogação em massa de certificados não
  existe no v1 — é ação local.
- **`report.summary` sem filtro livre.** O hub escolhe só `min_qod` (0–100), `apply_overrides` e `levels`
  (subconjunto de `chmlg`, nessa ordem); o nó monta `apply_overrides=<0|1> min_qod=<n> levels=<levels> rows=-1`
  e devolve só contagens (por severidade, por faixa de QoD, nº de hosts e por IP). Não há como estreitar por
  host, porta, NVT, nome, CVE ou vulnerabilidade, e nenhum OID, nome ou CVE sai: isso só por `report.export`.
  Conta no orçamento de sensíveis.
- **Escopo, regra completa.** Todo host que entra no gvmd pela frota, ou que uma tarefa vai varrer por ordem
  dela (`task.start/resume`, `task.create/modify` com `target_id`), passa pelo portão: IP/CIDR literal (host
  não literal no target ⇒ `scope_denied`), ⊆ escopo do tenant, fora do espaço degenerado e **sem conter**
  nenhum IP de `FLEET_SELF_DENY_IPS` nem os IPs resolvidos do host de `FLEET_HUB_URL`. Consequência
  operacional: um alvo que cubra o próprio nó (ex.: o `/24` inteiro da LAN onde ele mora) é negado, e o hub
  precisa montar faixas que não o contenham — o nó nunca injeta exclusões sozinho. O `sensor/internal/scope`
  de hoje só nega IP próprio isolado; a F2.4 fecha isso no pacote extraído, com teste.
- **Lixeira, nunca `ultimate`.** Restaurar ou esvaziar a lixeira é ação **local** (GSA). Criação e alteração
  não têm rollback automático: `output_*_modify.before` traz os valores anteriores dos campos alterados
  (exceto `comment`) para reverter à mão.
- **Rastreabilidade na GSA.** O nó prefixa o `comment` de objeto criado/alterado com `fleet:<command_id> `.
- **Target sem nada além de hosts literais:** sem credenciais, sem `asset_hosts_filter`, sem reverse lookup;
  exatamente um entre `port_list_id` e `port_range` (`^[TU]:[0-9,-]+$`, a gramática do `scan_bridge.py`).
- **Alive test.** Padrão quando omitido: `ICMP, TCP-SYN Service & ARP Ping`. O enum `AliveTest` do python-gvm
  27.x (verificado no 27.10.0) **não** tem essa combinação — o `fleet_ops.py` a envia como valor literal do
  elemento `alive_tests` (montado pelo builder XML do python-gvm, nunca string formatada). **Fallback
  documentado:** se o gvmd recusar o valor, o nó refaz com `ICMP, TCP-ACK Service & ARP Ping` (a combinação
  mais próxima suportada) e reporta o valor aplicado em `alive_test_effective`; **nunca** cai em silêncio para
  `Consider Alive` (varre host morto: lento e barulhento) nem para `Scan Config Default`. Se o gvmd 26.x aceita
  o padrão é confirmado na F2.3, em LAB.
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
ou comando `state.resync`) quando os dele divergem. Todo kind de lista leva `items` + `truncated` +
`unattributed_count`: objeto cujo dono gvmd (ou `O` do certificado) não mapeia para tenant conhecido é só
**contado**, nunca listado.

| `kind` | Nós | Conteúdo | Fonte local | O que **não** vai |
|---|---|---|---|---|
| `node` | todos | versões, feeds NVT/SCAP/CERT/GVMD_DATA com versão e idade, saúde, capacidades (tipos suportados, `report_formats` = combinações format/lang/variants que o nó renderiza), política local + `policy_sha256` | gvmd (`get_version`, `get_feeds`, `get_report_formats`), conector | — |
| `tasks` | todos | id, tenant, nome, status, progresso, ids de alvo/config/scanner/agenda, último report, nº de reports | `get_tasks` (filtro explícito) | `comment` |
| `targets` | todos | id, tenant, nome, entradas IP/CIDR **literais** (≤ 256) + contagens, alive test, em uso | `get_targets` | hostnames (só contados), credenciais, `comment` |
| `schedules` | todos | id, tenant, nome, fuso, iCalendar, próxima execução, tarefas ligadas | `get_schedules` | `comment` |
| `reports` | todos | id, tarefa, tenant, status, início/fim, contagens por severidade, nº de hosts | `get_reports` sem detalhes | **qualquer achado** |
| `agents` | central | agent_id, tenant, policy, SO/arch/versão, último contato, online | API admin local (F2.2) + online do ingest | hostname, inventário |
| `tokens` | central | id, tenant, tipo, policy, usos, expiração, revogado | `GET /api/v1/tokens` | segredo, `created_by` |
| `sensors` | central | sensor_id, tenant, último contato, online, versão de feed, gvmd_up, jobs ativos | heartbeats do ADR-0007 (persistidos na F2.2) | — |
| `scan_requests` | central | jobs de sensor: id, tenant, estado, **nº** de alvos, criação/expiração | `sensorjobs` (F2.2) | os alvos; pedidos do loop ADR-0006 (sem tenant: só contados) |
| `remediation` | central | jobs do ADR-0010: id, tenant, agent_id, tipo, estado, datas — **leitura** (D3) | `remediation` (F2.2) | payload, assinatura, before/after |
| `scope` | todos | por tenant: habilitado, CIDRs, se há usuário gvmd de escrita, origem — **leitura** (D2) | `TENANTS_FILE` ou `FLEET_TENANT` + `FLEET_SCAN_SCOPE` | nome e senha do usuário gvmd |
| `audit_tail` | todos | últimas ≤ 200 linhas **verbatim** da auditoria local + `head_sha256` | `audit.jsonl` | segredo (nunca está lá) |

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

- `FLEET_STATE_DIR/audit.jsonl`, **append-only**, uma linha JSON por evento
  (`fleet-state.schema.json#/$defs/audit_entry`): `connector_started`, `identity_changed` (enroll/renew),
  `policy_changed`, `received`, `rejected` (+ `reason`), `executed`, `result` (+ `status`/`error_code`).
- **Encadeada por hash:** `prev_sha256` = sha256 dos bytes exatos da linha anterior (sem o `\n`); a 1ª linha
  usa 64 zeros. Rotação a 32 MiB, mantendo 8 arquivos; a cadeia **atravessa** a rotação.
- Cada linha é gravada (`O_APPEND` + `fsync`) **antes** do efeito que registra (`rejected` antes do ack,
  `executed` antes do exec).
- **Sem segredo:** payload só por `payload_sha256`; nunca token, senha ou chave.
- **Visível ao operador local:** o arquivo no host e a superfície local do conector (F2.2). O hub recebe a
  cauda **verbatim** (`audit_tail`) e serve de **testemunha**: reescrever a auditoria no nó quebra a cadeia
  que o hub já viu.

## Segurança

### Ameaças e mitigações

| Ameaça | Mitigações | Residual (honesto) |
|---|---|---|
| **Hub comprometido** (fila + chave de comando) | catálogo fechado (sem escopo, tenant, usuários/RBAC, credenciais de alvo, aprovação de remediação, passthrough GMP); escrita **opt-in por nó** (padrão = só operação e leitura); escopo local e inalterável remotamente (D2), re-checado também ao iniciar tarefa; comando de objeto único; delete só para a lixeira; `report.summary` só com contagens; orçamento local de 30 sensíveis/h; auditoria local encadeada; kill switch local (`FLEET_ENABLED=false` ou parar o profile) | dentro da política local, o hub age: inicia/para tarefas existentes, lê contagens e exporta relatórios (permitidos por padrão; quem não quiser remove `task.*`/`report.*` de `allow`). Se o operador liberar os comandos de token: **(a)** `enroll_token.create` minta tokens `agent-endpoint` (≤ 1000 usos, ≤ 168 h) para qualquer tenant conhecido do nó, e um agente falso injeta inventário falso naquele tenant; **(b)** `enroll_token.revoke` revoga tokens e trava enrolls novos (DoS de onboarding) — certificados já emitidos não caem |
| **MITM** nó↔hub | TLS ≥ 1.3 + mTLS; servidor verificado (`FLEET_HUB_CA_FILE` ou trust store; hostname sempre); comando assinado com chave **separada** da CA e do TLS (um terminador TLS não forja comando); pins da CA da frota e da chave de comando entregues out-of-band no enroll | com TLS quebrado, o atacante lê estado/resultados e atrasa ou derruba comandos (DoS); não executa nada |
| **Replay** | nonce de uso único em store persistido até `not_after + skew`; janela ≤ 24 h; `node_id` e `tenant` dentro da assinatura; `command_id` idempotente; store ilegível ⇒ piso de replay | — |
| **Nó comprometido** | o certificado identifica só aquele nó (CN=`node_id`, `OU=fleet-node`, CA da frota separada da CA de enroll); o hub autoriza tudo pelo CN (`403`/`404`); o nó não tem chave de assinatura; o hub trata **todo** dado de nó como não-confiável — nunca deriva autorização dele, nunca o cruza para outro nó ou tenant, e escapa ao renderizar (nomes são texto livre: XSS armazenado) | o nó mente sobre o próprio estado e resultados; revogar no hub corta o canal, não o nó |
| **Exfiltração** | D4: estado e eventos só com metadado e contagens; `report.summary` (orçado) só devolve contagens — por severidade, por faixa de QoD, nº de hosts e por IP —, com filtro montado pelo nó, sem estreitar por host, porta ou NVT; achado detalhado (NVT, CVE, porta, evidência) só via `report.export` explícito, orçado e removível da política; nada de `comment`, inventário ou segredo; artefato com sha256 e teto; hub fora da internet (tailnet) no canário | com a política padrão, um hub comprometido vê, por relatório, **quais IPs têm quantas vulnerabilidades por severidade** (`report.summary`) e baixa relatórios completos (`report.export`), tudo no ritmo do orçamento (30/h somados) e registrado na auditoria local |
| **Abuso de escopo** | escopo LOCAL (registro de tenants ou `FLEET_SCAN_SCOPE`); só IP/CIDR literal (sem DNS rebinding); CIDR inteiro dentro do escopo; deny absoluto (loopback, link-local/metadata, multicast, não-especificado) e de **qualquer CIDR que contenha** IP próprio (`FLEET_SELF_DENY_IPS`) ou do hub; os hosts do target são re-checados também em `task.start/resume` e `task.create/modify(target_id)`; sem credencial/asset filter/reverse lookup em target; `sensor_job.enqueue` passa pelo portão local **e** pelo da `sensorjobs` | um target criado localmente com host fora do escopo continua existindo, mas a frota não o dispara (`scope_denied`); a lacuna de CIDR do `scope.go` atual só some com a F2.4 |
| **Roubo do token de enroll** | uso único, TTL curto, pins out-of-band, CSR com prova de posse, `node_id` único (`409`) | quem usar o token antes do dono enrola um nó falso: o hub deve confirmar o nó (CN/fingerprint) out-of-band antes de enfileirar comandos para ele |
| **Roubo da chave do nó** | chave `0600`, TTL de 30 dias + renew, revogação no hub, alerta de sessões concorrentes do mesmo CN (obrigação do hub) | até a revogação, o ladrão consome os comandos do nó (não os executa no nó) e forja estado/resultado em nome dele |
| **Adulteração da auditoria** | JSONL encadeado + cauda como testemunha no hub | root no nó reescreve o arquivo; o hub detecta a quebra na próxima cauda |
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
| **Partição gvmd** | escrita autenticada como o usuário gvmd do tenant (D6); operação em objeto existente exige dono == usuário do tenant, senão `not_found` (sem enumeração cross-tenant) |
| **Estado atribuído** | cada item leva o `tenant` derivado do dono; objeto sem tenant conhecido só entra em `unattributed_count` |
| **Escopo por tenant** | target/sensor job ⊆ escopo **daquele** tenant (registro central ou `FLEET_SCAN_SCOPE`) |
| **Agentes, tokens, sensores** | tenant = `O` do certificado do agente/sensor; token = `Scope.Tenant`; divergência do envelope ⇒ `not_found` |
| **Identidade do nó ≠ tenant** | `O=<org>` do certificado do nó é a organização dona do nó no hub, usada pelo hub para particionar nós; **não** concede tenant algum. O RBAC de operador por tenant é obrigação do hub; o nó é defesa em profundidade |
| **Standalone/sensor** | um único tenant local (`FLEET_TENANT`); comando para outro tenant ⇒ `tenant_unknown` |

## LGPD

Do nó para o hub saem **metadado operacional e contagens** (D4): versões, saúde, ids e nomes de objetos GVM,
status, entradas IP/CIDR literais de alvos e escopos, contagens por severidade (por IP só no `report.summary`,
sob comando e orçado). **Não saem:** achados
detalhados (fora de `report.export` explícito), hostnames de agentes e entradas não-literais de alvos,
`comment` de objetos, inventário de agentes, payload/resultado técnico de remediação, senhas, chaves e segredos
(exceto o segredo de `enroll_token.create`, uma vez, marcado). `issued_by` (operador do hub) entra na
auditoria do nó — recomenda-se identificador **pseudônimo**. Detalhe completo, com direção, finalidade e
sensibilidade por dado: [docs/data-inventory.md — Canal de gestão da frota (ADR-0011)](../data-inventory.md#canal-de-gestão-da-frota-adr-0011).

## Rollout faseado

- **F2.1 — contrato Go (só código, sem rede).** Módulo `fleet/` + `fleet/contract`: tipos dos 6 schemas,
  `Canonical`/`Verify`/`VerifyAt`, checagens 0–4, validação por tipo, golden vectors em
  `fleet/contract/testdata/` e teste que valida exemplos contra `schema/fleet-*.schema.json`; `go.work` + CI do
  módulo.
- **F2.2 — API admin local.** No control-plane: bearer **dedicado** da frota (`FLEET_CP_TOKEN`) aceito **só**
  nas rotas que o conector usa; rotas novas `POST /api/v1/agents/{id}/revoke`, uma rota (ou variante) que
  revoga **só o token** — o `DELETE /api/v1/tokens/{id}` de hoje revoga também os certificados — e listagens sem segredo
  (`GET /api/v1/agents`, `GET /api/v1/sensors` com heartbeats persistidos, `GET /api/v1/scan-jobs`,
  `GET /api/v1/remediation/jobs`); superfície do operador local (status, política, auditoria) atrás do gate de
  sessão gsad do nginx — sem porta nova. DARK.
- **F2.3 — `gmp-bridge/fleet_ops.py`.** Um subcomando por operação GVM do catálogo + leituras de estado;
  python-gvm; filtro explícito; checagem de dono; alive test com o fallback documentado (confirmar em LAB se o
  gvmd 26.x aceita o padrão); testes sem gvmd, no estilo de `test_scan_bridge.py`.
- **F2.4 — política, escopo, anti-replay e auditoria.** `policy.json` + padrão; portão de escopo extraído de
  `sensor/internal/scope` para pacote compartilhado (sem cópia divergente; `scope_test.go` e
  `degenerate_test.go` migram junto) e com a regra de CIDR que **contém** IP próprio ou do hub (o `scope.go`
  atual só nega IP isolado), testada; store anti-replay/journal; auditoria encadeada; orçamento de sensíveis.
- **F2.5 — estado e eventos.** Coletores por kind com hash; outbox durável; detecção de transições.
- **F2.6 — conector, compose e CI.** `fleet/cmd/fleet-connector` (enroll → renew → heartbeat → estado →
  long-poll → verificação → ack → execução → artefato → resultado); serviço `fleet-connector` no profile
  `fleet` dos compose do nó central, standalone e sensor, com `FLEET_ENABLED=false` e nenhuma porta publicada;
  imagem no GHCR; CI (build, vet, gofmt, `test -race`).
- **F2.7 — hub de referência + E2E.** Implementação **mínima** do lado hub neste repo (CA da frota, signer no
  molde de `signkeys`, fila, stores, artefatos), só para E2E em CI e para o canário — **não** é o
  commandcenter. O E2E cobre todo o catálogo contra um gvmd de teste e os ataques (replay, nó errado, tenant
  desconhecido, fora do escopo, payload trocado).
- **F2.8 — runbook + canário.** `docs/runbooks/gestao-remota-frota.md` (enroll com pins, política, kill switch,
  revogação, teardown, leitura da auditoria). Canário com o hub de referência no host do commandcenter,
  alcançado **só pela tailnet**, contra um nó de **LAB** (nunca de cliente); cada degrau com autorização por
  ação e critério de saída:
  1. **só-leitura por 24 h** (`allow = [state.resync]`): estado no hub == GSA; cadeia de auditoria íntegra;
     nenhum dado fora do D4 no hub; nenhuma rejeição inesperada;
  2. **`report.export`** de um report de LAB (`variant: technical`, a única anunciada antes da R5; um pedido
     `client`/`executive` tem de voltar `unsupported_report_variant`): sha256 do artefato confere; auditoria e
     orçamento registram;
  3. **`task.start`/`task.stop` em tarefa de LAB**: estados e eventos coerentes; reentrega idempotente;
     comando endereçado a outro nó rejeitado (`wrong_node`);
  4. **`target.create` em tenant de TESTE** (opt-in só desse tipo): alvo dentro do escopo aceito; fora dele
     ⇒ `scope_denied` + evento; `alive_test_effective` registrado.
- **Rollback:** `FLEET_ENABLED=false` (instantâneo) ou parar o profile `fleet`; revogar o nó no hub; imagem
  anterior com `--no-deps`; schemas são aditivos.

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
