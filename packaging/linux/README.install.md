# Suricatoos Agent — instalação (Linux)

Agente passivo/local de postura de vulnerabilidade. Coleta inventário de pacotes
localmente e reporta **outbound** (mTLS) ao pipeline Suricatoos; a correlação roda
server-side e os achados aparecem na GSA. **Não faz scanning de rede.**

## Instalar

```sh
# Debian/Ubuntu
sudo apt install ./suricatoos-agent_<versão>_<arch>.deb
# RHEL/Fedora/SUSE
sudo dnf install ./suricatoos-agent-<versão>.<arch>.rpm
```

A instalação coloca o binário em `/usr/bin/suricatoos-agent`, a unit systemd em
`/lib/systemd/system/suricatoos-agent.service` (NÃO habilitada) e cria
`/var/lib/suricatoos-agent` (state).

## Verificar a assinatura (recomendado)

Os pacotes são assinados pela chave **Suricatoos Agent Packages**
(`packaging/keys/suricatoos-agent-pkg-pub.asc`, fingerprint
`12CB 5520 BBCF 8388 D2D2 3BF1 7EA8 AFD3 C0A8 A055`).

**RPM** (RHEL/Fedora/SUSE):

```sh
sudo rpm --import suricatoos-agent-pkg-pub.asc
rpm -K suricatoos-agent-*.rpm        # → "digests signatures OK"
```

**DEB** (Debian/Ubuntu): o `.deb` carrega assinatura GPG `_gpgorigin`. A
verificação automática real vem do **repositório apt** (Release assinada) — ao
servir os pacotes, assine o repo e adicione a chave em
`/etc/apt/keyrings/`. Para checar um `.deb` avulso, use `debsig-verify` com uma
policy apontando para esta chave.

## Enrolar + habilitar

1. Gere um **token de enrollment** no control-plane (admin da GSA → bundle).
2. No endpoint:

   ```sh
   sudo suricatoos-agent enroll --state /var/lib/suricatoos-agent \
     --server https://scanner.suricatoos.com/agent/v1 \
     --token "<TOKEN>" --ca-pin "<CA-PIN>"

   sudo systemctl enable --now suricatoos-agent
   sudo systemctl status suricatoos-agent
   journalctl -u suricatoos-agent -f
   ```

   - `--server` **deve terminar em `/v1`**.
   - `--ca-pin` aceita `sha256:<hex>`, hex puro ou `AB:CD:..`.
   - A **URL do ingest é herdada do enrollment** — `run`/o serviço não precisam de `--ingest`.

## O que o agente coleta

Nome+versão+arch de pacotes (dpkg/rpm), distro/release/kernel, portas em escuta
**locais**. **Não** coleta arquivos do usuário, credenciais nem telemetria.

## Remover

```sh
sudo apt remove suricatoos-agent     # ou: dnf remove suricatoos-agent
```

O state dir (`/var/lib/suricatoos-agent`, com os certs) é **preservado**. Para
apagar de vez: `sudo rm -rf /var/lib/suricatoos-agent`.
