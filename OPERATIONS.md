# Suricatoos — Guia de Operação

Operação do stack Suricatoos (fork dos Greenbone Community Containers / GVM-OpenVAS).
Substitua `SERVIDOR`, `USUARIO` e `SENHA` pelos valores do seu deploy — **não** versione segredos.

## Acesso

SSH é **key-only** (senha desabilitada). Conecte com sua chave:
```bash
ssh root@SERVIDOR        # chave autorizada em /root/.ssh/authorized_keys
```

## Stack

```bash
cd /root/suricatoos/compose
docker compose ps                 # estado dos 16 servicos
docker compose logs -f gvmd       # logs do manager
```
- Aplicacao rebrandeada: `suricatoos/gsa` (UI) + `suricatoos/gsad` (web daemon)
- Backend/feeds: upstream Greenbone (gvmd, openvas-scanner, ospd-openvas, pg-gvm, redis, nginx)
- UI exposta em `127.0.0.1:443` e `127.0.0.1:9392` (HTTP->HTTPS). Acesse via tunel SSH:
  ```bash
  ssh -N -L 8443:127.0.0.1:443 root@SERVIDOR    # depois: https://localhost:8443
  ```
- Tema: claro/escuro (auto, segue o SO). Acento indigo. `assets/suricatoos-theme.css`.

## Usuario admin (GMP)

```bash
# resetar a senha do admin (rode como usuario gvmd):
docker compose exec -u gvmd gvmd gvmd --user=admin --new-password='NOVA_SENHA'
docker compose exec -u gvmd gvmd gvmd --get-users
```

## Rodar um scan (CLI, via gvm-tools)

```bash
cd /root/suricatoos/compose
gmp() { docker compose run --rm -T gvm-tools gvm-cli \
  --gmp-username admin --gmp-password 'SENHA' \
  socket --socketpath /run/gvmd/gvmd.sock --xml "$1" 2>/dev/null; }

# UUIDs padrao GVM:
#   Full and fast config = daba56c8-73ec-11df-a475-002264764cea
#   OpenVAS Default scanner = 08b69003-5fc2-4037-a479-93b440211c73

gmp '<create_target><name>alvo</name><hosts>ALVO</hosts><port_range>T:1-1024</port_range></create_target>'
# -> pegue o id do target, crie a task, <start_task>, depois <get_reports report_id="...">
```
Ver `scripts/overnight-scan.sh` (no servidor) como exemplo de orquestracao E2E.

## Feeds (permanecem Greenbone)

Os 8 containers de feed + `gpg-data` ficam em `registry.community.greenbone.net` (`FEED_RELEASE=24.10`).
`gvmd` valida a assinatura GPG do feed contra a chave Greenbone — **nao** trocar.
```bash
# status do feed na UI: Administration > Feed Status (VT/SCAP/CERT = Current)
```

## Hardening (aplicado)

- **Firewall** `ufw`: `default deny incoming`, somente porta **22** liberada. GVM e 127.0.0.1-only.
- **SSH key-only**: `PasswordAuthentication no`, root `prohibit-password`, `MaxAuthTries 3`.
  Drop-in: `/etc/ssh/sshd_config.d/99-suricatoos-hardening.conf`.
- **fail2ban**: jail `sshd` (backend systemd, maxretry 5, bantime 1h). `fail2ban-client status sshd`.
- Stack com `restart: always` (sobrevive reboot).

## Backup

```bash
# config do fork + assets (ja versionado em git)
# dados do gvmd (postgres) e feeds ficam em volumes Docker:
docker run --rm -v greenbone-community-edition_psql_data_vol:/v -v /root/backups:/b \
  alpine tar czf /b/psql_$(date +%F).tgz -C /v .
```

## Reproduzir/Upgrade

Ver `README.md` e `VERSIONS.md` (tags pinadas + patches). Para nova release GVM:
re-clonar gsa/gsad nas novas tags, re-aplicar os patches, rebuildar, re-pinar o compose.

## Pendente

- **Publicar imagens** `suricatoos/gsa`+`gsad` num registry (GHCR): requer token com escopo
  `write:packages` (`gh auth refresh -s write:packages` e `docker login ghcr.io`).
