# Runbook — Sensor de scanner interno (ADR-0007)

Deploy faseado do sensor de scanner interno (GVM phone-home multi-tenant). O sensor
vive **dentro da rede do cliente**, faz enroll na nuvem (`.97`), recebe jobs de scan
escopados por tenant, roda `scanlaunch` in-process contra o gvmd LOCAL, e faz push dos
achados → gvmd central (re-atestado por OID) + Score por tenant.

> **Acesso:** os passos de nuvem rodam **no host `.97`**. A estação do Claude não toca
> `.97` sem autorização por-ação (política "prod protegida"). Os passos de sensor rodam
> na VM do sensor (lab na P2, cliente na P5).

## Flags de escuridão (o sensor é OFF por padrão)

O feature é gated por **duas** flags independentes — ambas ausentes/false = dark:

| Flag | Serviço | Efeito |
|---|---|---|
| `SENSOR_JOBS_ENABLED=true` | control-plane | monta `GET /v1/scan-jobs`, `/v1/heartbeat`, feed, enqueue |
| `SENSOR_REPORT_ENABLED=true` | ingest | monta `POST /v1/sensor-report` |
| `SENSOR_FEED_ROOT=<dir>` | control-plane | liga o mirror de feed **(MANTER OFF até o fix #7)** |
| `SENSOR_SCORE_URL=<url>` | ingest | liga o push pro Score (P3+) |

**#7 (auditoria):** o mirror de feed ainda não está wired nos volumes do gvmd/openvas
(escreve num dir que nenhum container lê). **NÃO** definir `SENSOR_FEED_ROOT`/
`SENSOR_FEED_DIR` até resolver — senão o openvas seguiria puxando NASL do Greenbone.

---

## P1 — Nuvem, no escuro (só landa o código auditado em prod)

As imagens novas (com os fixes da auditoria) são publicadas no GHCR pelo CI a cada push
na `main` (`control-plane-publish` / `ingest-publish`). No diretório do compose do `.97`
(projeto `greenbone-community-edition`):

```sh
# 1) Puxa as imagens novas + recria control-plane e ingest, SEM ligar o sensor.
docker compose pull control-plane ingest
docker compose up -d --no-deps control-plane ingest
docker compose logs --tail=20 control-plane ingest
#   control-plane: "sensor: dispatch de scan-jobs desabilitado (SENSOR_JOBS_ENABLED != true)"
#   ingest:        "sensorreport: desabilitado — defina SENSOR_REPORT_ENABLED=true ..."
#   → confirma que o sensor está DARK.

# 2) nginx: novo default.conf (adiciona a location mTLS /agent/v1/feed; as demais
#    rotas de sensor já falham fechado). Gotcha (ver deploy-pipeline.md §4): o nginx lê
#    o default.conf por bind-mount de arquivo único; o git pull troca o arquivo (inode
#    novo) e o reload NÃO o pega. Valide num container descartável e RECRIE o nginx.
git pull                                              # no host, no diretório do compose
docker compose run --rm --no-deps --entrypoint nginx nginx -t
docker compose up -d --no-deps --force-recreate nginx
curl -sS --resolve <dominio>:443:127.0.0.1 -o /dev/null -w 'status=%{http_code}\n' https://<dominio>/

# 3) Separação das 3 chaves (emissão ≠ feed ≠ update — risco #3). As chaves de feed/
#    update são auto-geradas no 1º boot se o path existir e o arquivo faltar. As pubkeys
#    passam a ser distribuídas no enroll. (Confirme que /var/lib/suricatoos-cp está
#    montado no container do control-plane — é onde vivem ca.crt + control-plane.env.)
cat >> /var/lib/suricatoos-cp/control-plane.env <<'EOF'
FEED_SIGN_KEY_FILE=/var/lib/suricatoos-cp/feed-sign.key
UPDATE_SIGN_KEY_FILE=/var/lib/suricatoos-cp/update-sign.key
EOF
docker compose up -d --no-deps --force-recreate control-plane
docker compose logs --tail=8 control-plane

# 4) Verificação (dark): frota de agentes + GSA intactas; rotas de sensor fail-closed.
curl -sk -o /dev/null -w 'renew-sem-cert=%{http_code}\n'    -X POST https://scanner.suricatoos.com/agent/v1/renew      # 403
curl -sk -o /dev/null -w 'scanjobs-sem-cert=%{http_code}\n'        https://scanner.suricatoos.com/agent/v1/scan-jobs   # 403
curl -sk -o /dev/null -w 'feed-sem-cert=%{http_code}\n'            https://scanner.suricatoos.com/agent/v1/feed/manifest # 403
#   Com um cert de agente VÁLIDO, /agent/v1/scan-jobs → 404 (handler não montado, dark). OK.
#   O renew com CRL: um cert revogado (na CRL) → 403 mesmo apresentando cert válido no TLS.
```

**Verificações de não-regressão (P1):** enroll de agente OK; push de inventário do
agente → 202 e correlação/import intactos (ver deploy-pipeline.md §5); GSA responde.

## P2 — Sensor de lab (NOSSA rede, não a do cliente)

```sh
# Na nuvem (.97): habilita o dispatch (control-plane) + import (ingest), ainda sem tenant.
#   control-plane.env:  SENSOR_JOBS_ENABLED=true  SENSOR_JOBS_FILE=/var/lib/suricatoos-cp/sensor-jobs.json  TENANTS_FILE=/var/lib/suricatoos-cp/tenants.json
#   ingest env:         SENSOR_REPORT_ENABLED=true  TENANTS_FILE=/data/tenants.json  SENSOR_TENANT_SECRETS=<file>  (NÃO definir SENSOR_SCORE_URL ainda)
docker compose up -d --no-deps --force-recreate control-plane ingest

# Cria o usuário gvmd por-tenant do piloto (+ permissão Super — padrão ADR-0006) via GSA/GMP.
#   registra o tenant no TENANTS_FILE (escopo + usuário gvmd) — ver control-plane/tenants.

# Minta o token do sensor (ADMIN-BEARER — nunca o provision session-gated):
curl -sk -X POST https://scanner.suricatoos.com/api/... \  # POST /api/v1/tokens
  -H "Authorization: Bearer $ADMIN_SECRET" \
  -d '{"type":"single_host","tenant":"piloto","policy":"scanner-sensor","ttl_hours":720}'

# Na VM de lab: rodar o sensor-install (docker load do tarball GHCR-privado + compose up +
#   keygen/CSR/enroll). Verifica: enroll → sensor-config assinado → feed cold-start →
#   heartbeat online → GET /agent/v1/scan-jobs = 204 (ocioso). Confirma CN/fingerprint
#   OUT-OF-BAND antes de ativar o escopo. SEM job ainda.
```

## P3 — Canário

`PUT /api/v1/tenants/{piloto}/scope` com um `/24` de lab (VM descartável, nunca prod);
`POST /api/v1/tenants/{piloto}/scan-jobs` com **um** job. Acompanhar: dispatch → scan
local → sensor-report → **severity re-atestada do feed** → task `suricatoos-sensor-piloto`
no gvmd central (partição do tenant). Ligar `SENSOR_SCORE_URL` só aqui, e conferir que o
Score recebe severity/CVE **do feed** (não do sensor — fix #2). Asserção: achados só na
partição do piloto.

Durante o scan o heartbeat do sensor segue saindo (goroutine própria) e informa
`active_jobs=1`: o log do control-plane mostra `sensorjobs: heartbeat ... jobs=1`. Um sensor
com a versão anterior do agente ficava sem heartbeat enquanto escaneava — não o confunda com
sensor fora do ar.

## P4 — Fonte de descoberta

Ligar descoberta Score/agente; asserção de que o scope-gate **dropa** out-of-scope; soak
de dois tenants provando zero contaminação cruzada.

## P5 — Primeiro sensor de cliente real

Autorizado por-ação. TTL de cert curto + renew + alerta de expiração/enroll. **Antes de
ligar o feed cloud→sensor, resolver o #7** (montar o mirror nos volumes de feed do
gvmd/openvas + desligar os containers de feed upstream + snapshot cold-start).

---

## Rollback (P1)

```sh
# Imagem: recria a tag anterior (o compose referencia :stable; pinne a digest anterior).
docker compose up -d --no-deps control-plane ingest    # com a tag/digest boa
# nginx: restaura o default.conf anterior (git), valida (nginx -t) e recria o nginx
#   (--no-deps --force-recreate), como no passo 2 da P1.
# chaves: remova as linhas *_SIGN_KEY_FILE do control-plane.env + recreate (schema aditivo).
```

Flag primeiro é o rollback instantâneo: `SENSOR_JOBS_ENABLED`/`SENSOR_REPORT_ENABLED`
ausentes → sensor inerte, sem jobs da nuvem, sem import.

## Decommission de um sensor comprometido

A CRL corta o **trust de nuvem** (despacho + import) em ≤5min — `DELETE /api/v1/tokens/{id}`
revoga todos os serials (inclusive renovados; o renew agora recusa cert revogado — fix #1).
**Mas não para o scan local** de um sensor comprometido → **kill real = teardown
operacional/físico** (`docker stop` + remoção da imagem na VM do sensor) + TTL curto.
