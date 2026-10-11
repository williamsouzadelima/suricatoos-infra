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

⚠️ **Gotcha:** o nginx lê o `compose/nginx/default.conf` por **bind-mount de arquivo
único** (o `nginx_config_vol` fica por baixo e só fornece o resto de `conf.d`, como o
`headers.conf`). O `git pull` troca o arquivo por rename — inode novo — e o container em
execução segue com o antigo: `nginx -s reload` relê o conteúdo VELHO, sem erro e sem aviso;
e `up -d` sozinho não recria o nginx, porque a config do serviço não mudou, só o arquivo.
Por isso **não** se copia nada para o volume e **não** se usa reload: valide e **recrie** o
container. Vale também para o `standalone.conf`. O mount da CA de enrollment
(`/etc/nginx/enroll-ca.crt`) já vem no override; o arquivo precisa existir no host (§0).

```sh
cd <clone>/compose    # sempre do diretório do compose (ver OPERATIONS.md)
git pull

# 1) valide o arquivo NOVO num container descartável (mesma rede e mesmos mounts do serviço;
#    o nginx em execução ainda enxerga o inode antigo)
docker compose run --rm --no-deps --entrypoint nginx nginx -t

# 2) recrie só o nginx: o bind-mount passa a apontar para o arquivo novo e o container
#    pega também um mount novo, como o da CA (override): /etc/nginx/enroll-ca.crt
docker compose up -d --no-deps --force-recreate nginx

# 3) confira pelo NOME do host: com roteamento por SNI na frente, localhost pode cair em
#    outro vhost
curl -sS --resolve <dominio>:443:127.0.0.1 -o /dev/null -w 'status=%{http_code}\n' https://<dominio>/
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
# e remova a location /ingest/ + as linhas ssl_verify_client do default.conf, valide
# (nginx -t) e recrie o nginx (--no-deps --force-recreate), como no passo 4.
```

## Notas de segurança

- Só agentes **enrolados** (cert da CA de enrollment) postam — nginx `ssl_verify_client`.
- Rate-limit `zone=ingest` (30 r/min/IP, burst 10).
- Hardening futuro: pinar `CN(cert) == agent_id` no ingest (o nginx já repassa
  `X-Client-Cert-DN`/`X-Client-Cert-Verify`).
- O ingest nunca falha o 202 para o agente: erros de correlação/import são logados,
  não propagados (store-and-forward do agente cuida do retry).
