# Runbook — Deploy do pipeline ingest + correlation + bridge

Coloca o **data-plane do agente** no ar no stack do `.97`: os agentes empurram
inventário (mTLS, outbound) → `ingest` correlaciona contra as advisories Notus do
feed → importa os achados no `gvmd` (gmp-bridge) → visíveis na GSA.

```
agente --(mTLS, 443)--> nginx [verify client cert vs CA de enroll]
                          └─ /ingest/ ──> ingest:9090 ──┬─ correlation (Notus)
                                                         └─ gmp-bridge ──> gvmd.sock
```

Validado ponta-a-ponta localmente contra um **gvmd 26.31.1** (mesma versão do
`.97`): inventário RHEL vulnerável → 1 achado importado + host registrado;
inventário Rocky (outra distro) → 0 achados (scoping correto, sem falso-positivo).

> **Acesso:** este runbook roda **no host `.97`** (a estação de trabalho do Claude
> não alcança o `.97` — porta 22 bloqueada). Os passos abaixo são para você executar lá.

## 0. Pré-requisitos

- Imagem publicada no GHCR pelo CI (`ingest-publish.yml`, dispara em push na `main`
  que toque `ingest/`, `correlation/` ou `gmp-bridge/`). Confirme:
  `docker pull ghcr.io/williamsouzadelima/suricatoos-ingest:stable`
- Host já logado no `ghcr.io` (ver memória de auth GHCR).
- Control-plane já deployado (a CA de enrollment vive em `/var/lib/suricatoos-cp/ca.crt`).

## 1. Confirmar os nomes reais dos volumes do feed/socket

```sh
docker volume ls | grep -E 'notus|gvmd_socket'
# esperado: greenbone-community-edition_notus_data_vol
#           greenbone-community-edition_gvmd_socket_vol
# Confira que há *.notus no volume (o ingest faz WalkDir recursivo):
docker run --rm -v greenbone-community-edition_notus_data_vol:/n alpine \
  sh -c 'find /n -name "*.notus" | head; echo "total:"; find /n -name "*.notus" | wc -l'
```

Se os nomes diferirem do override (`gvmd_socket_vol` / `notus_data_vol` → prefixados
pelo projeto `greenbone-community-edition`), ajuste o `compose/docker-compose.override.yml`.

## 2. Segredo do gvmd (env file do ingest)

```sh
mkdir -p /var/lib/suricatoos-cp
printf 'GVM_PASSWORD=%s\n' '<senha-admin-do-gvmd>' > /var/lib/suricatoos-cp/ingest.env
chmod 600 /var/lib/suricatoos-cp/ingest.env
# Usuário GMP padrão = admin (GMP_USERNAME no override); ajuste se diferente.
```

A CA de enrollment já deve existir em `/var/lib/suricatoos-cp/ca.crt` (é o
`CA_CERT_FILE` do control-plane). O nginx a monta para verificar os certs dos agentes.

## 3. Subir o serviço `ingest`

No diretório do compose (ex.: `/root/suricatoos/compose`):

```sh
docker compose pull ingest
docker compose up -d --no-deps ingest
docker compose logs --tail=20 ingest
# esperar:
#   pipeline: correlation enabled (NOTUS_DIR=/notus)
#   pipeline: GMP import enabled (BRIDGE_SCRIPT=/usr/local/share/suricatoos/bridge.py)
#   ingest listening on :9090 (plaintext — use TLS in production)
```

`plaintext` aqui é esperado: o nginx termina o TLS/mTLS; o ingest só escuta na
rede interna do docker (sem porta publicada).

## 4. Aplicar a config do nginx (mTLS + rota /ingest/)

⚠️ **Gotcha conhecido:** `nginx_config_vol` é montado **depois** do bind-mount do
`default.conf`, então o volume vence. Copie o config atualizado para o volume e
faça **restart** (não reload). E garanta o mount da CA.

```sh
# 1) confirme que o nginx tem o mount da CA (override): /etc/nginx/enroll-ca.crt
docker compose up -d --no-deps --force-recreate nginx   # pega o novo volume mount da CA

# 2) copie o default.conf atualizado para dentro do volume que o nginx lê
VOL=/var/lib/docker/volumes/greenbone-community-edition_nginx_config_vol/_data
cp compose/nginx/default.conf "$VOL/default.conf"

# 3) valide a sintaxe e recarregue
docker compose exec nginx nginx -t
docker compose exec nginx nginx -s reload
```

## 5. Verificar (smoke test com cert de agente)

Use um par cert/chave emitido pelo control-plane (ou um token de enroll → cert):

```sh
# sem cert → 403 (mTLS barra)
curl -sk -o /dev/null -w 'sem-cert=%{http_code}\n' \
  -X POST https://scanner.suricatoos.com/ingest/v1/inventory -d '{}'

# com cert de agente → 202 (e o ingest correlaciona/importa)
curl -sk --cert agent.crt --key agent.key \
  -o /dev/null -w 'com-cert=%{http_code}\n' \
  -X POST https://scanner.suricatoos.com/ingest/v1/inventory \
  -H 'content-type: application/json' --data @inventario-de-teste.json

docker compose logs --tail=10 ingest   # "findings=N" + "gmp-bridge ok"
```

Confira na GSA (ou via GMP) que apareceu um report da task `suricatoos-agent-<host>`
com o host atribuído.

## 6. Lado do agente — URL do ingest via enrollment (automático)

O agente **aprende a URL do ingest no enrollment**: o control-plane a devolve na
resposta de `/enroll` e o agente a persiste (`ingest.url` no state dir). Logo
`suricatoos-agent run` / `install` **não precisam de `--ingest`** — ele é herdado
(passe `--ingest` só para sobrescrever).

Para isso, o control-plane precisa do env `INGEST_URL`:

```sh
# acrescente ao env file do control-plane e recrie o serviço:
echo 'INGEST_URL=https://scanner.suricatoos.com/ingest/v1/inventory' \
  >> /var/lib/suricatoos-cp/control-plane.env
docker compose up -d --no-deps --force-recreate control-plane
docker compose logs --tail=5 control-plane   # "ingest URL (handed to agents on enroll): ..."
```

Tokens cunhados depois disso geram bundles com `ingest_url:` e os agentes que
enrolarem com eles já reportam ao ingest sem config extra. Fluxo no host do agente:

```sh
suricatoos-agent enroll --server <...> --token <...> --ca-pin <...>
suricatoos-agent run            # usa a URL herdada do enroll
# ou instalar como serviço:
suricatoos-agent install --state <mesmo state do enroll>
```

## 7. Rollback

```sh
docker compose stop ingest && docker compose rm -f ingest
# e remova a location /ingest/ + as linhas ssl_verify_client do default.conf,
# recopie p/ o volume e nginx -s reload.
```

## Notas de segurança

- Só agentes **enrolados** (cert da CA de enrollment) postam — nginx `ssl_verify_client`.
- Rate-limit `zone=ingest` (30 r/min/IP, burst 10).
- Hardening futuro: pinar `CN(cert) == agent_id` no ingest (o nginx já repassa
  `X-Client-Cert-DN`/`X-Client-Cert-Verify`).
- O ingest nunca falha o 202 para o agente: erros de correlação/import são logados,
  não propagados (store-and-forward do agente cuida do retry).
