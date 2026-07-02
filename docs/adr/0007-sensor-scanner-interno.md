# 0007 — Sensor de scanner interno (GVM phone-home, multi-tenant)

- **Status:** PROPOSTO (design only, 2026-07-01)
- **Deciders:** William (mantenedor), Claude Code
- **Relacionado:** [0004-bootstrap-token](0004-bootstrap-token.md), [0006-loop-rengine-openvas](0006-loop-rengine-openvas.md)

O sensor é o **contraparte interno** do loop externo do ADR-0006: a mesma máquina de
enroll/mTLS/CRL/command-channel/import, mas o scanner vive **dentro** da rede do cliente e a **nuvem é
autoritativa** sobre o que ele pode tocar. Este ADR é **design only**: nenhuma mutação em prod, nenhum push.

## Contexto e problema

Queremos um **sensor de scanner interno Suricatoos**: uma máquina/container implantada **dentro** da rede
do cliente que roda o Suricatoos Scanner (stack GVM completa), alcança a rede interna RFC1918, e no boot
**faz enroll na nuvem** (descobre seu tenant) e integra com o Suricatoos Score.

Restrições e premissas (decididas pelo mantenedor):

- **Stack GVM completa por sensor** — auto-contido: `gvmd` + `openvasd`/`ospd-openvas` + Notus + feeds
  **locais**. Sem depender do gvmd central para escanear.
- **Alvos vêm de DUAS fontes:** (a) um **escopo interno por-tenant definido pelo operador** na nuvem, e
  (b) **assets descobertos** pelo Score/reNgine + os agentes de endpoint. Ambos despachados ao sensor do
  tenant por um canal **nuvem→sensor** de jobs.
- **Cliente atrás de NAT/firewall** → o sensor é **phone-home (só saída)**: nunca abre porta inbound.

O problema difícil **não é a plumbing** (é ~80% montagem do que já existe): é a **segurança na borda
hostil**. O sensor roda em turf possivelmente comprometido; os feeds NVT são **código NASL** que o openvas
executa; a atribuição de achados é **multi-tenant** numa mesma CA. Duas propostas concorrentes (Design A
"máximo reuso" e Design B "isolamento multi-tenant") foram submetidas a uma **revisão adversária** que
levantou 13 riscos (5 altos). Este ADR **funde o melhor das duas e resolve TODOS os 13**.

O que já existe e é reusado (verificado, read-only):

- `control-plane/enroll/enroll.go` — token+CSR → cert. `Scope.Tenant→O`, `Scope.Policy→OU` (L128-129),
  `CN==agent_id` (L119), unicidade global de `agent_id` (`tokens.Consume`), grava `CertSerial` p/ revogação.
- `control-plane/ca/ca.go` — CA Ed25519; `SignClientCSRIssued` (serial), `RevokeCertSerial`/`IssueCRL`/
  `GET /v1/crl.der`, `Fingerprint` (`--ca-pin`), e **`ca.Sign(msg)`** (L257) — **hoje a MESMA chave assina
  todo cert de tenant E os manifests de update** (`update.go`). Ver risco de chave abaixo.
- `control-plane/provision/provision.go` — fluxo sem-fricção, **hardcoda `Scope{Tenant:"default"}`** (L72) e
  minta token **sem admin-bearer**, protegido só pela sessão GSA no nginx.
- `control-plane/api/api.go` — `POST/GET/DELETE /api/v1/tokens` **com admin-bearer** (`withAuth`);
  `revokeToken` percorre `rec.Enrollments` e chama `RevokeCertSerial` por serial (kill switch).
- `control-plane/commands/service.go` — command-channel: `agentCN` deriva identidade do `X-Client-Cert-DN`
  encaminhado; fila **em memória, 1 pendência por agente, sem payload** (inadequada p/ jobs de scan).
- `control-plane/update/update.go` — padrão de **manifest assinado** (`ca.Sign` + verificação com a CA
  pinada no enroll).
- `ingest/scanlaunch/*` (ADR-0006) — motor de scan ativo: `authz.go` (DN exato O+OU), `allowlist.go`
  (default-deny; RFC1918 **allowlist-gated**, deny absoluto de loopback/link-local/metadata/self+irmãs),
  `crl.go` (fail-closed), reconciler serializado, state machine, `registry.go` idempotente,
  `types.go` (`RengineScanHistoryID int64`, L54 — âncora de idempotência; nome de task
  `suricatoos-rengine-{id}`).
- `gmp-bridge/bridge.py` — `create_container_task` + `import_report(in_assets=True)`; **nota verificada
  (L14-17): "gvmd NÃO recomputa severity no import — `result.severity` fica no valor que fornecemos"** →
  por isso `fetch_nvt_meta` re-atesta severity/CVE **do feed central por OID** (invariante de
  não-fabricação). `safe_host_id` neutraliza injeção de token de host.
- `gmp-bridge/scan_bridge.py` — `launch|status|fetch|stop` contra um socket gvmd (`--socket`).
- `ingest/server.go` — `markSeen`/`lastSeen` (persistido em `AGENT_LASTSEEN_FILE`) + `agentsHandler`
  guardado por `X-Suricatoos-UI==1` → base da UI de saúde.
- `compose/nginx/default.conf` — locations mTLS que exigem `ssl_client_verify==SUCCESS` e encaminham
  `$ssl_client_s_dn`/`$ssl_client_verify`/`$ssl_client_serial`. **Pegadinha:** o `/agent/` genérico e
  `/agent/api/`, `/agent/provision/` **NÃO limpam `X-Client-Cert-DN`**; e `/agent/v1/commands`
  **não encaminha o serial** (sem enforcement de CRL no control-plane).

## Opções consideradas

### Import dos resultados no gvmd central (o eixo decisivo de integridade)

- **Reconstruir o report no servidor + re-atestar severity/CVE por OID contra o feed CENTRAL (escolhido).**
  O sensor envia `Finding[]` normalizado; a nuvem descarta qualquer severity/OID/CVE/host que o sensor
  afirme e reconstrói o report via `bridge.py --mode network` reusando `fetch_nvt_meta`.
  - 👍 Fecha o buraco de fabricação. Como `bridge.py` (L14-17) documenta, **gvmd mantém a severity que a
    gente fornece** — então a única defesa é derivar severity/CVE do feed central por OID (OID ausente →
    0.0/Log). Um sensor comprometido **não** consegue suprimir um achado real (false-negative) nem forjar
    críticos (extorsão/alarme).
  - 👎 A nuvem faz N lookups de OID por report (custo de CPU no ingest, mitigável por cache — `NVTMeta`).
- **Importar o report XML cru exportado pelo gvmd LOCAL do sensor (`--raw-report`), descartado.**
  - 👎 **Reabre exatamente** o buraco que `bridge.py` existe p/ fechar: em turf hostil o sensor fabrica
    `<severity>`, OID, CVE, nome e até `<host>` (o conteúdo do report nunca é re-checado contra a
    allowlist). Perda total de integridade daquele tenant. **Rejeitado.**

### Fronteira de execução do scan local no sensor

- **Chamar o reconciler `scanlaunch` IN-PROCESS no `sensor-agent` (escolhido).** Sem HTTP, sem forjar
  headers de cert.
  - 👍 Não expõe primitiva de scan. Reusa `scanlaunch` (reconciler serializado, allowlist, caps) como
    biblioteca no mesmo binário Go.
- **Injetar jobs no `ingest`/`scanlaunch` local por loopback `127.0.0.1:9090` forjando
  `X-Client-Cert-Verify:SUCCESS` (Design A), descartado.**
  - 👎 Qualquer processo/container co-localizado que alcance a porta TCP ganha um **launch de scan
    não-autenticado** contra a rede interna; os checks locais de CRL/authz viram teatro. **Rejeitado.**

### Canal de despacho nuvem→sensor

- **Novo canal durável `/agent/v1/scan-jobs` (long-poll) + pacote `control-plane/sensorjobs/` (escolhido).**
  Modelado no `scanlaunch/registry.go` (persistência atômica temp+rename, id inforjável, `FindOrCreate`).
  - 👍 Jobs **duráveis**, idempotentes, com payload de alvos, escopados por tenant. Redelivery após crash.
- **Estender o command-channel `commands.Queue`, descartado.** É **em memória, 1 pendência por agente, sem
  payload**, perdido em restart. 👎 Inadequado p/ jobs de scan de rede ricos e duráveis. **Rejeitado.**

### Distribuição de feeds (o problema difícil da GVM completa)

- **(b) Espelho na nuvem sobre o canal mTLS + snapshot cold-start baked + manifest assinado com blobs
  content-addressed SHA-256 (escolhido).**
  - 👍 Primeiro boot **offline-completo** (snapshot no tarball, `save/load`). Updates fluem **da nuvem**
    (único egress garantido = `sensor→nuvem :443`), não do Greenbone. A nuvem já roda `feed-updater.py` e
    valida a assinatura GnuPG upstream. Consistência de versão de feed sensor↔central (a re-atestação por
    OID assume feeds casados). Zero egress novo no cliente.
  - 👎 Nuvem vira CDN de feeds p/ N sensores (mitigado: blobs content-addressed, só entrega mudados,
    range-requests resumíveis, zona de rate-limit + cap de banda por sensor).
- **(a) Sensor puxa imagens de feed do Greenbone direto, descartado.** 👎 Viola egress restrito
  (whitelist de `registry.community.greenbone.net`), move a confiança de feed p/ fora do Suricatoos (o proxy
  do cliente poderia MITM/envenenar NASL), e deixa cada sensor **derivar p/ uma versão de feed diferente do
  central** — quebra a re-atestação por OID. **Rejeitado** (opt-in só onde o cliente permitir).
- **(c) Feed 100% baked, sem delta, descartado como mecanismo único.** 👎 Feeds são o bulk multi-GB e mudam
  ~diariamente; re-bake + `save/load` por update é cadência inviável. **Mantido só como semente cold-start.**

### Autorização do minting do token do sensor

- **Só via API admin-bearer `POST /api/v1/tokens` com tenant+policy explícitos (escolhido).**
  - 👍 Fecha o **deputy confuso**: quem seta `Scope.Tenant` controla toda a cadeia tenant→cert-O→partição.
- **Variante session-gated do `provision.go` com tenant em query-param, descartado.** 👎 Hoje o provision
  minta **sem admin-bearer** (só sessão GSA); qualquer usuário GSA autenticado (mesmo role baixo) mintaria um
  token `scanner-sensor` p/ um tenant **arbitrário** e enrolaria um sensor rogue como aquele tenant.
  **Rejeitado.**

### Rotação de identidade

- **`POST /agent/v1/renew` autenticado por mTLS (escolhido).** Rotaciona o cert usando o cert válido atual
  como auth — serial novo **sem** re-consumir o token single-use nem esbarrar na unicidade de `agent_id`.
  Serve também os agentes de endpoint (hoje sem rotação).
- **Re-provisionar com o mesmo `agent_id` (Design A), descartado.** 👎 Bate em `ErrAgentAlreadyExists`
  (unicidade global) → **não há renovação funcional** → empurra p/ TTL longo demais. **Rejeitado.**

### Chaves de assinatura (blast radius da chave)

- **Separar chaves por propósito: emissão-de-cert ≠ assinatura-de-feed ≠ assinatura-de-update (escolhido).**
  - 👍 Hoje `ca.Sign` (L257) usa a **mesma** chave Ed25519 que emite TODO cert de tenant; `update.go` já a
    reusa. Uma compromissão dessa chave em `.97` = personificar qualquer tenant + push de binário RCE + push
    de NASL envenenado. Separar limita o raio; pubkeys de verificação de feed/update são **distribuídas no
    enroll** (pinadas) p/ permitir rotação. Roadmap: mover a chave de emissão p/ HSM/signer offline.

## Decisão

**Base = Design B** (integridade dos resultados: reconstruir o report no servidor + re-atestar severity/CVE
por OID contra o feed central; endpoint `renew` mTLS; **allowlist dupla** = gate de despacho na nuvem +
gate baked no sensor; scope-gating no despacho), **com o framing de máximo reuso e o rollout dark P0–P5 do
Design A**, e reusando `scanlaunch` **verbatim** como runner do lado sensor (mas **in-process**, sem o
listener loopback que forja headers do Design A).

**Identidade = tenant.** O cert do sensor tem `O=<tenant> OU=scanner-sensor CN=sensor-<tenant>-<uuid>`,
atribuído pelo `Scope.Tenant`/`Scope.Policy` do bootstrap token no enroll (o sensor **não escolhe** o
tenant). A nuvem **sempre re-deriva o tenant do `O` do cert verificado**, nunca de um campo de payload.
"Fetch tenant" **não é um RPC** — o cert **é** a credencial de tenant.

**Chave de correlação** = `correlation_id` (UUID), âncora ponta a ponta: job → task gvmd local
(`suricatoos-sensor-{correlation_id}`) → sensor-report → report central → Score. O id externo de job
(`job_id`) é inforjável (fecha IDOR).

Todos os 13 riscos da revisão adversária são resolvidos (tabela na seção Segurança). Em particular: **NÃO**
importamos XML de report vindo do sensor; **NÃO** expomos listener de scan por header-trust; o minting de
token do sensor exige **admin-bearer**; toda rota de sensor tem location mTLS dedicada que **encaminha o
serial** + os headers `X-Client-Cert-*` são **limpos** nas locations não-mTLS; a **CRL fail-closed** é
ligada no canal de jobs do control-plane; e afirmamos honestamente que a **CRL corta o trust de nuvem
(despacho + import), mas não para o scan local de um sensor comprometido** — esse só morre com teardown
operacional/físico.

## Arquitetura

### Componentes

**Reusados verbatim / com edição mínima:**

| Componente | Uso |
|---|---|
| `enroll/enroll.go` | token→CSR→cert `O=tenant/OU=scanner-sensor`. **Edição:** estender `Response` com URLs (`jobs_url`, `report_url`, `feed_url`, `config_url`, `renew_url`, `heartbeat_url`) + as **pubkeys de verificação** de feed e update (pinadas). |
| `ca/ca.go` | emite cert, `RevokeCertSerial`/`IssueCRL`/`crl.der`, `Fingerprint`. **Edição:** 3 chaves distintas (emissão/feed/update) em vez de 1. |
| `api/api.go` | `POST /api/v1/tokens` (admin-bearer) minta o token `scanner-sensor`; `DELETE /api/v1/tokens/{id}` → revoga todos os serials (kill switch). |
| `ingest/scanlaunch/*` | motor de scan como **biblioteca in-process** no `sensor-agent` (reconciler serializado, allowlist, crl, caps, exec). **Edição:** `allowlist.go` `selfAndSiblingIPs` → **env-driven** (`SCAN_SELF_DENY_IPS`) p/ o sensor negar suas próprias interfaces + endpoints da nuvem, não `.97/.124/.89`; e `types.go` ganha uma âncora `scan_id string` genérica (aditiva; o loop `.97` segue usando `rengine_scan_history_id`). |
| `gmp-bridge/scan_bridge.py` | `launch/status/fetch/stop` contra o gvmd **local** do sensor. **Sem mudança.** |
| `gmp-bridge/bridge.py` | **Edição:** `--mode network` reusando `fetch_nvt_meta` + `create_container_task` + `import_report`, sob o **usuário gvmd por-tenant**, re-validando cada IP de host contra o escopo do tenant. |
| `ingest/server.go` | `markSeen`/`lastSeen` + `agentsHandler` → UI de Sensores (cópia, session-gated, filtrada por tenant). |
| `control-plane/update/update.go` | self-update do `sensor-agent` (assinado com a **chave de update**, não a de emissão). |

**Novos na NUVEM (`.97`):**

- `control-plane/sensorjobs/{service,registry,store}.go` — fila FIFO durável por `(tenant, sensor)`
  (modelada no `scanlaunch/registry.go`: escrita atômica temp+rename, `job_id` inforjável, `FindOrCreate`,
  ownership por `O`). Rotas `GET /agent/v1/scan-jobs`, `POST /agent/v1/scan-jobs/{id}/ack`.
- `control-plane/sensorconfig/` — `GET /agent/v1/sensor-config` (mTLS OU=scanner-sensor): escopo autorizado
  do tenant + defaults de scan + cadência de feed, **assinado com a chave de feed/config** (hot-reload).
- `control-plane/feed/` — `GET /agent/v1/feed/manifest` (assinado, `{feed_version, files:[{path,sha256,
  size}], sig}`) + `GET /agent/v1/feed/blob/{sha256}` (mTLS, range-requests).
- `control-plane/enroll` renew — `POST /agent/v1/renew` (mTLS com o cert atual → serial novo).
- `control-plane` heartbeat — `POST /agent/v1/heartbeat` → `markSeen(CN)` do ingest.
- `ingest/sensorreport/` — `POST /ingest/v1/sensor-report` (mTLS OU=scanner-sensor → `bridge.py --mode
  network` → partição por-tenant do gvmd central).
- `api`: `PUT /api/v1/tenants/{t}/scope`, `POST /api/v1/tenants/{t}/scan-jobs` (admin-bearer).
- nginx: locations mTLS **dedicadas** p/ cada rota de sensor (verify SUCCESS + set DN de `$ssl_client_s_dn` +
  **encaminha `$ssl_client_serial`** + limpa `X-Suricatoos-UI`); e **limpar `X-Client-Cert-*`** nas
  locations genéricas `/agent/`, `/agent/api/`, `/agent/provision/`.

**Novos no SENSOR (repo `suricatoos-infra/sensor/`):**

- `sensor/cmd/sensor-agent/main.go` + `internal/{enroll,feedsync,jobs,scanrun,report,health}` — o supervisor
  Go: enroll → `sensor-config` → feed cold-start+sync → poll `scan-jobs` → `scanrun` in-process contra o
  gvmd local → `POST sensor-report` → ack → heartbeat. Importa `agent/internal/enroll` +
  `ingest/scanlaunch` (mesmo módulo) — a maior parte é cola sobre pacotes reusados.
- `sensor/compose/docker-compose.sensor.yml` — a stack GVM (`compose.yaml` verbatim) + `sensor-agent`;
  sockets gvmd/openvasd **só na rede do compose** (nunca publicados). Embarca `scan_bridge.py`.
- `packaging/install/sensor-install.sh` — installer pesado: `docker load` do tarball (GHCR privado, sem pull
  na caixa) + `compose up` + keygen/CSR/enroll.

### Trace ponta a ponta (boot → enroll → job → scan → resultados → Score)

```
REDE DO CLIENTE (NAT/firewall, saída :443 mTLS apenas)     NUVEM .97 (control-plane + ingest + gvmd central) / Score .124
──────────────────────────────────────────────────        ──────────────────────────────────────────────────────────────
[sensor: docker compose = gvmd+openvasd+feeds+sensor-agent]
 0. operador: POST /api/v1/tokens {tenant:"acme", policy:"scanner-sensor"}  (ADMIN-BEARER) → bundle YAML + --ca-pin
 1. install: docker load (tarball c/ snapshot de feed baked) → compose up; keygen; agent_id=sensor-acme-<uuid> (persistido)
 2. enroll ── POST /agent/v1/enroll {token,csr,agent_id,os,arch} ─▶ nginx(mTLS)→control-plane
        ◀── {certificate O=acme OU=scanner-sensor, ca_cert, jobs/report/feed/config/renew/heartbeat_url,
              feed_pubkey, update_pubkey}                              (enroll.go, Response estendida)
 3. GET /agent/v1/sensor-config (mTLS) ─▶ control-plane
        ◀── ASSINADO {allowlist_scope:["10.20.0.0/16","192.168.50.0/24"], scan_defaults, feed_cadence}
        → carrega allowlist_scope no scanlaunch.Allowlist LOCAL (fronteira baked, independente)
 4. feedsync: snapshot baked sobe já; GET /agent/v1/feed/manifest (assinado, chave de FEED) → baixa só blobs
        faltantes por sha256 (range-resumível) → verifica hash + assinatura GPG upstream preservada → swap atômico
 5. heartbeat ── POST /agent/v1/heartbeat {sensor_id,feed_version,gvmd_up,active_jobs} ─▶ markSeen(CN) → UI Sensores
 6. DESPACHO (2 fontes → 1 fila): (a) escopo do operador (PUT scope + sweep/POST scan-jobs) e (b) Score/agente
        chamam sensorjobs.Enqueue(tenant,targets…): SCOPE-GATE (targets ⊆ acme.scope) + dedup + cooldown + caps → PENDING
 7. loop ── GET /agent/v1/scan-jobs (mTLS OU=scanner-sensor, SERIAL→CRL fail-closed) ─▶ control-plane
        ◀── ScanJob{job_id, correlation_id, tenant=acme(=O), source, targets[], ports, scan_config} (204 se ocioso)
        POST /agent/v1/scan-jobs/{job_id}/ack {status:accepted}                         (redelivery idempotente)
 8. scanrun (IN-PROCESS, sem HTTP): re-valida cada alvo na allowlist LOCAL baked → reconciler serializado →
        scan_bridge.py launch/status/fetch contra o gvmd LOCAL (create_target→create_task→start_task)
        task local = suricatoos-sensor-{correlation_id} (gvmd = fonte da verdade, sobrevive a restart)
 9. em Done: fetch (get_report details=True) → Finding[] normalizado (shape do scanlaunch), cacheia
10. push ── POST /ingest/v1/sensor-report (mTLS) {correlation_id, sensor_id, feed_version, targets, findings[]} ─▶ ingest
        · authz DN exato (OU=scanner-sensor) + CRL fail-closed · tenant = cert O (payload só cross-check; mismatch→403)
        · re-valida cada IP de host ⊆ acme.scope
        · bridge.py --mode network: p/ cada finding fetch_nvt_meta(oid) do FEED CENTRAL → severity/CVE do feed
          (OID ausente→0.0/Log; severity do sensor NUNCA confiada) → reconstrói report XML no servidor →
          create_container_task("suricatoos-sensor-acme") + import_report(in_assets=True) COMO usuário gvmd tenant-acme
        → visível na GSA central (admin Super), tenant-owned
11. Score: mapeia os mesmos achados tenant-scoped (tenant DERIVADO do O, correlation_id) → Vulnerability,
        particionado por owner de tenant (espelha o usuário gvmd). Loop fechado; sensor só-saída o tempo todo.
```

Cada hop é **saída do sensor**; nenhuma porta inbound é aberta no cliente.

### Schema do job (as duas fontes → uma fila) — `schema/scan-job.schema.json`

```json
{
  "schema_version": "1.0.0",
  "job_id": "3f9c…",              // atribuído pela nuvem, inforjável (fecha IDOR)
  "correlation_id": "b21a…",      // âncora: job → task local → sensor-report → report central → Score
  "tenant": "acme",               // = cert O; server-set, re-derivado server-side; sensor re-checa (defesa em profundidade)
  "source": "operator-scope|score-discovery|agent-discovery",
  "targets": ["10.20.5.0/24","192.168.50.13"],  // só IP/CIDR literais (sem hostname → sem DNS rebinding em scan)
  "ports": "T:1-65535",
  "scan_config": "full-and-fast", // → daba56c8-… ; scanner → 08b69003-…
  "alive_test": "Consider Alive",
  "max_duration": "6h",
  "not_before": "2026-07-01T…", "expires_at": "2026-07-02T…", "created_at": "…"
}
```

**Duas fontes → uma fila, scope-gated:**

- **(a) Escopo por-tenant do operador** — o allow-set autoritativo vive na nuvem (`PUT
  /api/v1/tenants/{t}/scope`). Um scheduler (cron) e/ou `POST /api/v1/tenants/{t}/scan-jobs` enfileira
  sweeps (`source=operator-scope`).
- **(b) Descoberta Score/reNgine + agente** — o Score (`O=score-hub`, com `SURICATOOS_SCANNER_ALLOW_PRIVATE`
  do ADR-0006) e os agentes de endpoint expõem IPs internos; são postados ao mesmo `Enqueue` interno
  (`source=score-discovery`/`agent-discovery`), resolvendo o tenant pelo `O` do descobridor.
- **Um gate único:** `targets ⊆ tenant.scope` (assets descobertos **fora** do escopo declarado são
  **dropados**, não escaneados) + dedup + cooldown + caps. A **nuvem é autoritativa** sobre o que qualquer
  sensor pode escanear — um Score comprometido ou uma descoberta confusa **não** contrabandeia alvos
  arbitrários (espelha "scanner autoritativo, reNgine nunca confiado sobre alvos" do ADR-0006).

**Dedup/idempotência (três camadas reusadas):** chave = `sha256(tenant | sorted(targets) | scan_config)`
dentro do cooldown; `correlation_id` é a âncora ponta a ponta; o `scanrun` local é idempotente via
`FindOrCreate` no `scan_id` + nome de task determinístico — um job re-entregue nunca faz duplo-launch.

### Endpoints & auth

| Endpoint | Auth | Owner | Reusa |
|---|---|---|---|
| `POST /agent/v1/enroll` (Response estendida) | token | `control-plane/enroll` | tokens, ca |
| `POST /agent/v1/renew` **(novo)** | mTLS (cert atual) | `control-plane/enroll` | `SignClientCSRIssued` |
| `GET /agent/v1/sensor-config` **(novo)** | mTLS OU=scanner-sensor + CRL | `control-plane/sensorconfig` | chave-feed `Sign`, authz |
| `GET /agent/v1/feed/manifest`, `/feed/blob/{sha256}` **(novo)** | mTLS + CRL | `control-plane/feed` | chave-feed `Sign` |
| `GET /agent/v1/scan-jobs`, `POST …/{id}/ack` **(novo)** | mTLS OU=scanner-sensor + CRL fail-closed | `control-plane/sensorjobs` | scanlaunch registry/authz/crl |
| `POST /agent/v1/heartbeat` **(novo)** | mTLS + CRL | `control-plane` → ingest | `server.go markSeen` |
| `POST /ingest/v1/sensor-report` **(novo)** | mTLS OU=scanner-sensor + CRL fail-closed | `ingest/sensorreport` | authz, crl, `bridge.py --mode network` |
| `PUT /api/v1/tenants/{t}/scope`, `POST /api/v1/tenants/{t}/scan-jobs` **(novo)** | admin-bearer | `control-plane/api` | tokens/api |
| `POST /api/v1/tokens` (tenant+policy=scanner-sensor) | admin-bearer | `control-plane/api` | tokens |
| `GET /v1/crl.der`, `GET /v1/update/check` | as-is | control-plane | — |

## Plano de implementação (por repo)

### `suricatoos-infra` → nuvem (`.97`)

- **NOVO `control-plane/sensorjobs/`** (clone de `scanlaunch/registry.go`): fila durável por `(tenant,
  sensor)`, `Enqueue` com scope-gate, `Poll/Ack` **autorizados pelo `O` derivado server-side** (id
  estrangeiro → `404`, como `scanlaunch.lookupOwned`), `job_id` inforjável. + testes.
- **NOVO `control-plane/sensorconfig/`, `control-plane/feed/`** — handlers assinados com a **chave de feed**
  (separada da de emissão); manifest content-addressed; blob com range-requests.
- **NOVO `ingest/sensorreport/`** — handler mTLS: `authz.go` (OU exato) + `crl.go` (fail-closed) + tenant =
  `O`; re-valida IPs de host ⊆ escopo; chama `bridge.py --mode network`.
- **Editado (pouco):** `enroll.go` (`Response` + rota `renew`), `ca.go` (3 chaves), `api.go` (`/tenants/{t}/
  scope|scan-jobs`), `ingest/server.go` (rota heartbeat + UI Sensores), `scanlaunch/allowlist.go`
  (`SCAN_SELF_DENY_IPS` env), `scanlaunch/types.go` (`scan_id string` aditivo), `bridge.py` (`--mode
  network`), `compose/nginx/default.conf` (locations mTLS dedicadas + limpar `X-Client-Cert-*` nas genéricas
  + zonas de rate-limit `scanjobs`/`sensorreport`/`feedblob`), `compose/docker-compose.override.yml` (env dos
  novos serviços; flags `SENSOR_JOBS_ENABLED`).
- **Docs:** este ADR + runbook `docs/runbooks/sensor-scanner-interno.md` (criar usuário gvmd `tenant-<t>` +
  permissão Super, geração das 3 chaves, **decommission/teardown de sensor comprometido**, rollout/rollback,
  rotação/renew).

### `suricatoos-infra/sensor/` → sensor (novo)

- `cmd/sensor-agent` + `internal/{enroll,feedsync,jobs,scanrun,report,health}`; `compose/
  docker-compose.sensor.yml`; embarca `gmp-bridge/scan_bridge.py`; usa `ingest/scanlaunch` como lib
  in-process. `packaging/install/sensor-install.sh`.

### `suricatoos-scan` (reNgine) → Score (`.124`)

- Importer de achados de sensor **particionado por owner de tenant** (espelha o usuário gvmd por-tenant),
  chaveado pelo **tenant derivado server-side** (nunca por campo do sensor) + `correlation_id`. Reusa o
  `import_openvas_findings` do ADR-0006.

## Segurança

### Resolução dos 13 riscos da revisão adversária

| # | Sev | Risco | Resolução (todas neste ADR) |
|---|---|---|---|
| 1 | alta | Import de report cru do sensor forja severity/OID/CVE/host (Design A) | **Nunca importar XML do sensor.** Reconstruir o report no servidor a partir de `Finding[]`; re-atestar severity+CVE por OID contra o **feed CENTRAL** (`fetch_nvt_meta`; OID ausente→0.0/Log; severity do sensor descartada); re-validar todo IP de host ⊆ escopo antes de criar asset; **`--raw-report` removido**. |
| 2 | alta | Integridade de feed → RCE NASL em turf do cliente | **Bake + lock do keyring GPG Greenbone** na imagem (imutável, **nunca** servido/substituído pelo mirror — `gpg-data` fica fora do mirror); **verificação de assinatura NASL no sensor** (`nasl_no_signature_check=0`, feed sig check on); assinaturas destacadas upstream **preservadas** nos blobs espelhados e verificadas sensor-side; manifest assinado com **chave de feed distinta da de emissão** (#3). Uma nuvem comprometida sozinha **não** envenena NASL. |
| 3 | alta | Uma única chave CA assina tudo (`ca.go:257`) | **Separar por propósito:** chave de **emissão-de-cert** ≠ **feed** ≠ **binário/update**, cada uma com escopo limitado. Mover a chave de emissão p/ **HSM/KMS ou signer offline** (roadmap P5). Pubkeys de verificação de feed/update **distribuídas no enroll** (pinadas) → rotação sem re-bake de trust. |
| 4 | alta | Minting cross-tenant via provision session-gated | **Só via API admin-bearer** (`POST /api/v1/tokens`) p/ tenant escolhido pelo chamador; **sem** query-param de tenant no path session-gated. UI (se houver) bind a um claim de tenant por-operador server-side + check de role explícito, **nunca** um parâmetro de request. |
| 5 | alta | `X-Client-Cert-DN` forjável em rotas `/agent/` não-mTLS | Toda rota de sensor tem location mTLS **dedicada** (`if ($ssl_client_verify != SUCCESS){return 403;}` + set DN de `$ssl_client_s_dn` + **encaminha `$ssl_client_serial`**); **limpar** `X-Client-Cert-DN/-Verify/-Serial` (`proxy_set_header … ""`) nas locations genéricas `/agent/`, `/agent/api/`, `/agent/provision/`. Nunca montar handler que confia no DN num path também servido por location que não sobrescreve. |
| 6 | média | CRL não para sensor rogue | **Ligar CRL fail-closed + `$ssl_client_serial`** nas rotas `scan-jobs`/`sensor-config`/`heartbeat` do control-plane (hoje o command-channel não encaminha serial e o control-plane não tem CRL). **Honestidade:** a CRL **corta o trust de nuvem** (despacho + import), mas um **sensor comprometido segue escaneando sua allowlist baked autonomamente** — isso só para com **teardown operacional/físico**. TTL de cert curto (30d) + runbook de decommission (`docker stop`/remoção de imagem). |
| 7 | média | Rotação de cert quebrada (Design A) | `POST /agent/v1/renew` autenticado por mTLS (serial novo sem re-consumir token nem esbarrar em `agent_id` único). Vale p/ os agentes de endpoint também. |
| 8 | média | Listener loopback com header-trust (Design A) | `scanrun` chama o reconciler `scanlaunch` **in-process**; **nada** capaz de scan bind numa porta TCP; sem forjar `X-Client-Cert-*`. |
| 9 | média | Clonagem do sensor / roubo de cert+chave | Perms restritas na chave + **seal a TPM** onde disponível; detectar o **mesmo CN de múltiplos IPs/sessões concorrentes** e alertar; TTL curto + renew; **alertar em todo enroll novo** e exigir **confirmação out-of-band** do CN/fingerprint antes de ativar o escopo do tenant. |
| 10 | média | IDOR de ack/status cross-tenant | **Autorizar TODA operação de job** (poll/ack/status) contra o **`O` derivado server-side**, `404` em id de tenant estrangeiro (como `scanlaunch.lookupOwned`); `job_id` inforjável; **nunca** aceitar tenant de body/query. |
| 11 | média | Partição no Score sub-especificada | Passar ao Score o **tenant derivado server-side** (do `O`, nunca campo do sensor) e particionar assets/vulns por **owner de tenant explícito** (espelha o usuário gvmd). Reformular a authz das rotas de sensor: **`OU==scanner-sensor` exato E `O ∈ registro-de-tenants-conhecidos`, `O` usado como chave de partição** (não um único `AllowedO` fixo). |
| 12 | baixa | Colisão `correlation_id`→int64 (Design A) | Rename back-compat p/ **`scan_id string`** genérico no schema do `scanlaunch` local (aditivo; o loop `.97` segue no `rengine_scan_history_id int64`), **em vez** de hash em int64. |
| 13 | baixa | Realidade de egress restrito p/ feeds | Blobs **content-addressed por-arquivo** com **range-requests resumíveis**, só entrega mudados; **zona de rate-limit + cap de banda por sensor** em `feed/blob`; expor **staleness de `feed_version`** com destaque na UI de Sensores + **alerta de SLA** de drift (o `feed_version` já vem no heartbeat/sensor-report). |

### Multi-tenancy & isolamento

| Propriedade | Mecanismo |
|---|---|
| **Identidade = tenant** | `O` setado pelo `Scope.Tenant` do token no enroll; o sensor não o escolhe; a nuvem sempre deriva o tenant do `O` verificado (nginx `X-Client-Cert-DN` → authz), **nunca** de payload. |
| **Separação de capability na CA compartilhada** | `OU=scanner-sensor` **exato** gate jobs/config/report; um cert de agente de endpoint (mesma CA, OU diferente) é rejeitado; um cert `score-hub/scan-requester` não puxa jobs de sensor; um cert de sensor não dirige o `scanlaunch` da nuvem. |
| **Partição de despacho** | job enfileirado só p/ sensor com `O == job.tenant`, e `targets ⊆ tenant.scope`. O sensor do tenant A nunca recebe job da rede de B nem faixa fora do escopo. |
| **Partição de resultados** | import central **owned pelo usuário gvmd por-tenant** (`tenant-<t>`, role=User) + admin com permissão **`Super`** (padrão do ADR-0006) → a isolação de ownership do próprio gvmd separa hosts/reports/results/assets. **Resolve colisão de IP interno:** dois tenants escaneando `192.168.1.10` não fundem (asset vive no namespace de cada usuário). Score particiona pelo mesmo owner. |
| **Sem read cross-tenant** | leituras do sensor = enroll (1x), feed/config assinados (dado público tenant-agnóstico), seus próprios jobs (escopados por `O`), CRL, update-check. `/ingest/` e as locations de sensor limpam `X-Suricatoos-UI` → um sensor não alcança `GET /agents` (postura da frota). |
| **Sem inject cross-tenant** | tenant derivado server-side + owner por-tenant → um sensor-A comprometido escreve só a partição de A; `tenant=B` no payload é ignorado/rejeitado; ele não consegue alvejar B (jobs escopados + allowlist baked de A). |

### Blast radius de um sensor comprometido (turf hostil)

- **Sem inbound.** Só phone-home; sockets gvmd/openvasd só na rede do compose, nunca publicados.
- **Só cert escopado.** `O=tenant OU=scanner-sensor` — sem admin-bearer, sem minting, sem read de frota, sem
  capability de scanlaunch da nuvem (DN exato separa os fluxos na CA compartilhada).
- **Scan duplamente limitado** (gate de escopo na nuvem + allowlist baked no sensor), com a deny-list
  absoluta ainda protegendo metadata/loopback/a nuvem/as próprias interfaces (`SCAN_SELF_DENY_IPS`). Pior
  caso de compromisso total: o atacante só escaneia as faixas internas **já autorizadas** do próprio cliente
  e empurra achados na partição **do próprio tenant** — sem caminho lateral p/ outros tenants ou admin da
  nuvem.
- **Sem creds centrais.** O sensor tem admin só do gvmd **local** (senha gerada **por-sensor** no install, sem
  segredo compartilhado); writes na nuvem passam pelo import tenant-scoped, nunca GMP central cru.
- **CRL fail-closed** severa despacho + import em ≤5min; **mas não para o scan local** → **kill real =
  teardown operacional/físico** (runbook) + TTL curto (30d) + renew.
- **Autenticidade de feed** (keyring GPG baked+lock + chave de feed separada + hash de blob) derrota
  envenenamento de NASL mesmo em rede totalmente MITM.
- **Limites de recurso/DoS** (concorrência, max-duration, cooldown, caps de host/porta, rate-limit nginx)
  impedem um job ruim de martelar a rede do cliente.

## Plano de rollout faseado (respeita GHCR privado build+`save/load`, `--no-deps`, autorização por-ação)

- **P0 — só código.** `sensorjobs`/`sensorconfig`/`feed`/`renew`/`ingest/sensorreport` + `bridge.py --mode
  network` + `scanrun` in-process + `sensor-agent` + compose + locations nginx + **rework de authz** +
  allowlist env + **separação das 3 chaves** + rename `scan_id`. Branches+PRs, CI verde, imagens `save`.
  **Nenhuma mutação em prod.**
- **P1 — nuvem, no escuro.** `load` das imagens novas (flags `SENSOR_JOBS_ENABLED=false`); locations nginx
  (`nginx -t` → `--no-deps` reload) **incluindo a limpeza de `X-Client-Cert-*` nas genéricas**; **gerar as 3
  chaves** (feed/update separadas, pubkeys no enroll); criar usuário gvmd `tenant-<piloto>` + `Super`. *(cada
  = 1 ação autorizada)* Verificar: agente + `scanlaunch` + GSA intactos; 403 sem cert; 503 feature-off.
- **P2 — sensor de lab (NOSSA rede, não do cliente).** Mintar token `scanner-sensor` **via API admin-bearer**;
  rodar `sensor-install` numa VM de lab; verificar enroll → `sensor-config` assinado → feed-sync → heartbeat
  online → `scan-jobs` 204. Confirmar CN/fingerprint out-of-band. **Sem job.**
- **P3 — canário.** `PUT scope` do tenant piloto com um `/24` de lab; enfileirar **um** job operator-scope;
  acompanhar despacho → scan local → sensor-report → **severity re-atestada** → task no gvmd central
  (partição do tenant) → `Vulnerability` no Score. **Asserção:** achados só na partição do piloto.
- **P4 — fonte de descoberta.** Ligar descoberta Score/agente; asserção de que o scope-gate **dropa**
  out-of-scope; soak de **dois tenants** provando zero contaminação cruzada.
- **P5 — primeiro sensor de cliente real** (autorizado por-ação), depois expandir. TTL curto + renew + alerta
  de expiração/enroll; tuning de banda dos deltas de feed; **migração da chave de emissão p/ HSM/offline**.
- **Rollback:** flag primeiro (instantâneo → sensor fica inerte sem jobs da nuvem); imagem = recria tag
  anterior com `--no-deps`; nginx = restaura conf boa; schema aditivo.

## Consequências

- 👍 Sensor interno phone-home **sem porta inbound**, ~80% montagem do enroll/command-channel/scanlaunch/
  bridge existentes; a **nuvem é autoritativa** sobre o que cada sensor escaneia.
- 👍 **Integridade de resultados real**: severity/CVE vêm do **feed central por OID**, nunca do sensor — um
  sensor comprometido não suprime nem forja achados.
- 👍 **Isolamento multi-tenant** por `O` derivado server-side + usuário gvmd por-tenant + owner no Score;
  colisões de IP interno não fundem.
- 👍 **Menor blast radius de chave**: emissão/feed/update separadas (roadmap HSM); envenenamento de NASL
  derrotado por GPG baked+lock.
- 👎 GVM completa é **pesada**: piso ≈ **4 vCPU / 8 GB RAM / 25–30 GB disco** por sensor (postgres+redis+
  openvas+feeds). Documentar como sizing mínimo.
- 👎 Nova superfície na caixa pública (rotas de sensor) + a nuvem vira **CDN de feeds** p/ N sensores —
  mitigado por default-deny + rate-limit + cap de banda + rollout no escuro.
- 👎 Passos manuais de config no gvmd (usuário por-tenant + Super) e curadoria do escopo por-tenant.
- 👎 **Honestidade operacional:** revogar não para o scan local de um sensor comprometido — exige teardown
  físico/operacional (runbook obrigatório).
- Decisão **reversível**: se um tenant exigir isolamento mais forte que um usuário gvmd por-tenant, um gvmd
  central por-tenant (ou o `scan-orchestrator` dedicado do ADR-0006) reusa este mesmo sensor + `scan_bridge.py`
  + caminho de import inalterados.

## Auditoria adversária pós-implementação P0 (2026-07-01)

O P0 (só-código) passou por uma auditoria adversária (10 dimensões × 2 lentes de
verificação). 16 defeitos distintos; veredito **go-with-fixes**. Estado:

**Corrigido + testado antes do merge (blockers + funcionais de feed + integridade):**

- **Renew burlava a CRL** — `renew` re-emitia cert p/ identidade revogada. Agora
  `enroll.Renew` exige o serial e checa `IsRevoked` (fail-closed), `AppendEnrollment`
  recusa token revogado, wired via `WithRevocationCheck`. Regressão testada.
- **Score-push fabricava achados** — o push ao Score mandava severity/CVE crua do
  sensor. Agora `bridge.py --mode network` emite os achados **re-atestados** (feed por
  OID) via `--reattested-out`, e o ingest encaminha ESSES. Testado nos dois lados.
- **Path traversal no feedsync → RCE root** — manifest com `../` escapava do FeedDir.
  Guard de contenção lexical (`filepath.IsLocal` + `Rel`) antes de escrever. Testado.
- **RootCAs do mTLS matava o feature** — cliente confiava só na CA de enroll e não
  validava o cert público (LE) da nuvem. Agora `RootCAs=nil` (system trust) no cloud +
  renew (espelha o agente de endpoint). Regressão testada.
- **enroll omitia feed/update pubkey** (só renew retornava) + **renew descartava
  pubkeys rotacionadas** — ambos corrigidos (rotação de chave de feed alcança a frota).
- **sem location nginx `/agent/v1/feed`** — feed caía na `/agent/` genérica que zera os
  headers de cert → 403. Location mTLS dedicada adicionada.
- **supervisor dava ack antes de rodar** — crash/push falho perdia achados. Ack movido
  p/ **depois** do push; job fica DELIVERED → re-entregue (idempotente). Testado.
- **Score import não-idempotente** + **colisão de slug de tenant** — ledger
  `SensorImport` (idempotência por `correlation_id`) + slug injetivo no tenant bruto.
- **CIDR sweep podia sobrepor metadata/link-local** — rejeição de CIDR sobre espaço
  degenerado adicionada ao scope-gate baked. Testado.
- **Módulo `sensor` não tinha CI nem estava no `go.work`** (por isso os bugs acima
  passaram) — adicionado ao workspace + `sensor-ci.yml` (build/vet/gofmt/test -race).

**Deferido para a fase de rollout (NÃO habilitar o feed até resolver):**

- **#7 (alto) — o mirror de feed verificado é escrito num dir que nenhum container GVM
  lê**, então o openvas ainda puxaria NASL do Greenbone (a opção "a" rejeitada). É
  estrutural (montar `SENSOR_FEED_DIR` nos volumes de feed do gvmd/openvas + desligar
  os containers de feed upstream + snapshot cold-start). **Enquanto não for wired,
  manter `SENSOR_FEED_ROOT`/`SENSOR_FEED_DIR` DESLIGADOS** — a distribuição de feed
  cloud→sensor não deve ser ligada no P1/P2. Endereçar antes da P-feed.
- **Hardening/observabilidade (baixos):** reaper da fila durável de jobs (evita
  crescimento sem limite de `SENSOR_JOBS_FILE`); canonicalização das chaves de dedup;
  telemetria real do heartbeat (`gvmd_up`/`active_jobs`); scan em goroutine separada p/
  não bloquear heartbeats; `ssl_crl` no nginx como defesa-em-profundidade (a CRL do
  control-plane já é autoritativa); `USER` não-root + rootfs read-only no container do
  sensor. Follow-up.

## Questões abertas (para a implementação / P5, não agora)

1. **Chave de emissão em HSM/KMS vs. signer offline** — qual, e o caminho de migração a partir da chave atual
   on-disk (`0600`) em `.97` (`ca.go`), que hoje é única e persistente. Mudança exige autorização por-ação.
2. **Armazenamento das creds do usuário gvmd por-tenant na nuvem** (env map vs. secret file vs. automação de
   provisioning por-tenant) — decidir na P1 ao criar o primeiro `tenant-<t>`.
3. **Qual `/24` (ou `/32`) interno semeia o canário P3** — uma VM descartável dentro do tenant piloto
   (o plano nega explicitamente as próprias caixas de prod).
4. **GSA local no sensor** p/ troubleshooting on-site, sim/não? (Isolamento-simples: não; só a GSA central.)
5. **Disponibilidade de TPM** no hardware dos clientes p/ seal da chave (oportunístico, best-effort).
6. **Ordem de entrega:** `renew` + separação de chaves são benéficas p/ a frota de agentes de endpoint hoje —
   vale landar como PRs próprios (P0.5) **antes** de qualquer trabalho de sensor?
</content>
</invoke>
