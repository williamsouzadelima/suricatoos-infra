# Suricatoos — Guia de Operação

Operação do stack Suricatoos (fork dos Greenbone Community Containers / GVM-OpenVAS).
Guia **genérico**: não traz IP, hostname nem caminho de um host específico — onde aparecer
`<dominio>`, `<projeto>` ou `<clone>`, use o valor do seu deploy. Segredos nunca vão para o git.
Os passos detalhados de cada procedimento ficam em [`docs/runbooks/`](docs/runbooks/) (lista no fim).

## 1. O stack

O stack é o compose deste repositório, no diretório `compose/` do clone git:

| Arquivo | Papel |
|---|---|
| `compose.yaml` | Greenbone Community Containers (pinado) |
| `docker-compose.override.yml` | nossas imagens e serviços (gsa/gsad, report-formats, ingest, control-plane, feed-updater), os mounts do nginx e os flags do `ospd-openvas` |
| `docker-compose.shared-host.yml` **ou** `docker-compose.standalone.yml` | perfil do host (seção 2) — um dos dois |
| `docker-compose.scap-order.yml` | opcional: corrige a corrida entre o marcador e o payload do feed SCAP |

O nome do projeto e a lista de arquivos vêm do `.env` ao lado do compose (`compose/.env`, fora do git):

```sh
COMPOSE_PROJECT_NAME=<projeto>
COMPOSE_FILE=compose.yaml:docker-compose.override.yml:docker-compose.shared-host.yml   # ou ...standalone.yml
# opcional, ao fim da lista:  :docker-compose.scap-order.yml
# SCANNER_BIND_IP=...    standalone: endereço extra em que a UI escuta (padrão: só loopback)
# COMPOSE_DIR_HOST=...   caminho do compose/ como o DAEMON do host o enxerga (o feed-updater roda
#                        `docker compose` por dentro do container); um clone git precisa defini-lo.
#                        Caminho inexistente: o Docker cria um DIRETÓRIO VAZIO no lugar e o
#                        feed-updater passa a operar sobre o nada
```

**Rode `docker compose` sempre de dentro de `compose/`.** O `COMPOSE_FILE` usa caminhos relativos. Sem
o `.env` ao lado o compose assume outro nome de projeto, e um `up -d` assim sobe um segundo stack em
vez de atualizar o existente.

```sh
cd <clone>/compose
docker compose ps                  # estado dos serviços
docker compose config --quiet      # valida os arquivos do COMPOSE_FILE
docker compose logs -f gvmd        # logs do manager
```

Depois de qualquer `up -d`, confira o `docker compose ps`: a política de restart cobre falha do
processo, não falha na **criação** do container (um bind-mount quebrado o deixa fora do ar sem alarde).

## 2. Perfis de host (nginx)

Cada perfil usa o **seu** arquivo de config do nginx — não troque um pelo outro:

| | Atrás de um roteador L4 (SNI) | Standalone |
|---|---|---|
| Compose | `docker-compose.shared-host.yml` | `docker-compose.standalone.yml` |
| Config do nginx | `nginx/default.conf` — `listen 443 ssl proxy_protocol` | `nginx/standalone.conf` — `listen 443 ssl` |
| TLS | termina no nginx, com o certificado público do host (`/etc/letsencrypt`) e a CA de enrollment (mTLS dos agentes) | certificado self-signed do `gvm-config`; sem domínio público, sem Let's Encrypt e sem CA de enrollment |
| Publicação | `127.0.0.1:8443` — o roteador do host faz passthrough por SNI e envia o preâmbulo PROXY | `127.0.0.1:443` e `SCANNER_BIND_IP` |
| Uso | host compartilhado com outras plataformas | scanner dentro da rede que ele audita (navegador local, túnel SSH ou VPN) |

O `default.conf` exige o proxy L4 na frente: sem o preâmbulo PROXY toda conexão falha (um `curl` direto
na porta publicada não o envia). Sem proxy na frente, use o perfil standalone.

## 3. Regras de deploy

1. **Recrie só o serviço tocado, com `--no-deps`:** `docker compose up -d --no-deps <serviço>`. Sem
   `--no-deps` o compose reavalia — e pode recriar — tudo de que o serviço depende.
2. **Nunca reinicie nem recrie `gvmd` ou `ospd-openvas` com scan rodando:** o scan morre. Confirme antes:
   ```sh
   docker compose exec -T pg-gvm psql -U gvmd -d gvmd -tAc "SELECT count(*) FROM tasks WHERE run_status=4;"   # tem que dar 0
   ```
   (`docs/runbooks/ospd-admission-control-e-watchdog.md` §0 traz também a checagem por processo.)
3. **Arquivo único em bind-mount exige `--force-recreate`.** O nginx lê `nginx/default.conf` (ou
   `standalone.conf`) por bind-mount de arquivo único. Ao atualizar o arquivo, o `git pull` o apaga e
   recria (unlink + create) — inode novo — e o container em execução segue com o antigo: `nginx -s reload`
   relê o conteúdo velho, **sem erro**; e `up -d` sozinho não recria, porque a config do serviço não
   mudou, só o arquivo. Depois de um pull que mude o nginx:
   ```sh
   git pull
   docker compose run --rm --no-deps --entrypoint nginx nginx -t   # valida o arquivo NOVO, num container descartável na rede do projeto
   docker compose up -d --no-deps --force-recreate nginx           # o mount passa a apontar para o arquivo novo
   ```
   Recriar o nginx derruba um import de `sensor-report` em voo: faça quando nenhum estiver em andamento
   (um sensor com job em andamento informa `jobs=1` nos heartbeats do log do control-plane). O job é
   reentregue em até ~5 min, sem perda, mas o import recomeça. (Para renovar certificado o `reload`
   continua certo: `/etc/letsencrypt` é um diretório montado.)
4. **Teste o vhost pelo nome, não por `localhost`.** Com roteador SNI na frente, `localhost` ou o IP podem
   cair em outro vhost do host:
   ```sh
   curl -sS --resolve <dominio>:443:127.0.0.1 -o /dev/null -w '%{http_code}\n' https://<dominio>/
   ```
   No standalone o `server_name` é `localhost` e o certificado é self-signed: `curl -sk https://localhost/`.

## 4. Usuário gvmd

O CLI do `gvmd` roda como o usuário `gvmd` do container — sempre `-u gvmd`:

```sh
docker compose exec -u gvmd gvmd gvmd --get-users
docker compose exec -u gvmd gvmd gvmd --user=admin --new-password='<NOVA_SENHA>'   # evite deixar a senha no histórico
```

A senha do `admin` também está no env file do `ingest` (`GVM_PASSWORD`): trocá-la sem atualizar esse
arquivo e recriar o `ingest` (`--no-deps`) quebra a autenticação do import de achados no gvmd.

## 5. Feeds

- Os containers de feed `vulnerability-tests`, `notus-data`, `scap-data`, `cert-bund-data`,
  `dfn-cert-data`, `data-objects` e `gpg-data` são da Greenbone (`FEED_RELEASE=24.10`); o `gvmd` valida a
  assinatura GPG contra a chave Greenbone — **não** troque. O `report-formats` é **nosso**: imagem própria
  (definida no `docker-compose.override.yml`) que acrescenta o formato "Suricatoos Premium PDF" ao feed.
- **Sync:** pela UI (tela de status do feed: atualizar agora ou agendar — quem executa é o `feed-updater`)
  ou à mão, do diretório do compose, com o mesmo comando dele:
  ```sh
  docker compose up -d --no-deps --pull always data-objects report-formats scap-data cert-bund-data \
    dfn-cert-data notus-data gpg-data vulnerability-tests
  ```
  **Sem** `--force-recreate`: recriar os feeds em paralelo causa corrida no `openvas --update-vt-info`
  (lê NVT incompleto) e o scanner fica sem NVTs.
- Os data objects chegam ao `gvmd` pelo volume `data_objects_vol`, preenchido pelos containers de feed
  `data-objects` e `report-formats`; é o sync do próprio `gvmd` que os instala — o formato "Suricatoos
  Premium PDF" entra assim e aparece no GSA sem mudança de frontend (`report-formats/Dockerfile`). O
  `feed-updater` atualiza os feeds com o comando acima (`up -d --no-deps --pull always`) e não reinicia
  o `gvmd`.
- Status do feed: Administration > Feed Status (VT/SCAP/CERT = Current).
- **Poda de imagens:** só as *dangling* — `docker image prune -f`. **Nunca** `-a` num host compartilhado:
  apaga toda imagem sem container em execução, inclusive as de outras plataformas.

## 6. Backup

O que importa é o banco do `gvmd` (Postgres, serviço `pg-gvm`). Dump em formato custom, **sem** os
schemas `scap` e `cert`, que são regeneráveis a partir do feed:

```sh
docker compose exec -T pg-gvm pg_dump -U gvmd -d gvmd -Fc \
  --exclude-schema=scap --exclude-schema=cert > gvmd-$(date +%F).dump
```

`-T` (sem TTY) é obrigatório, senão o binário sai corrompido. Trate o dump como dado sensível (contém
resultados de scan): guarde-o cifrado e fora do host. Config do fork e assets já estão no git.

## 7. Cuidados e hardening

- **Não rode `docker compose down -v`:** remove os volumes (banco do gvmd e feeds). No perfil shared-host
  os volumes são `external` e o `-v` os ignora; no standalone, não.
- Hardening (fail2ban do login, Let's Encrypt com hook de reload, `openvas-watchdog`): `hardening/README.md`.

## 8. Reproduzir e atualizar

`README.md` e `VERSIONS.md` (tags pinadas + patches). Nova release do GVM: re-clonar gsa/gsad nas tags
novas, re-aplicar os patches, rebuildar e re-pinar o compose.

## 9. Runbooks (`docs/runbooks/`)

| Runbook | Quando usar |
|---|---|
| [`deploy-pipeline.md`](docs/runbooks/deploy-pipeline.md) | colocar no ar ingest + correlation + bridge (mTLS em `/ingest/`) e aplicar o nginx |
| [`sensor-scanner-interno.md`](docs/runbooks/sensor-scanner-interno.md) | sensor de scanner interno (ADR-0007): fases, rollback, decommission |
| [`ospd-admission-control-e-watchdog.md`](docs/runbooks/ospd-admission-control-e-watchdog.md) | admissão de scans no `ospd`, watchdog de scan travado, `no-store` no nginx |
| [`loop-rengine-openvas.md`](docs/runbooks/loop-rengine-openvas.md) | loop reNgine (score) → OpenVAS (scanner) |
| [`agent-posture-and-rescan.md`](docs/runbooks/agent-posture-and-rescan.md) | postura do endpoint (agente) e re-scan on-demand |
| [`remediation-operation.md`](docs/runbooks/remediation-operation.md) | operar a remediação: ligar, aprovar, verificar, reverter |
| [`remediation-lab-canary.md`](docs/runbooks/remediation-lab-canary.md) | validar o executor de remediação em LAB (canário e2e) |
