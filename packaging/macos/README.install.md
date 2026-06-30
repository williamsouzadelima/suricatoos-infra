# Suricatoos Agent — instalação (macOS)

Agente passivo/local de postura de vulnerabilidade (binário **universal**
amd64+arm64). Coleta inventário local e reporta outbound (mTLS) ao pipeline.

## Instalar

```sh
sudo installer -pkg suricatoos-agent-<versão>.pkg -target /
```

Coloca o binário em `/usr/local/bin/suricatoos-agent`, o LaunchDaemon em
`/Library/LaunchDaemons/com.suricatoos.agent.plist` (NÃO carregado) e cria
`/var/lib/suricatoos-agent`.

> **Assinatura/notarização:** o `.pkg` do CI é **unsigned**. Em produção, assine
> e notarize (senão o Gatekeeper bloqueia fora de MDM):
> ```sh
> productsign --sign "Developer ID Installer: SEU NOME (TEAMID)" in.pkg signed.pkg
> xcrun notarytool submit signed.pkg --apple-id <id> --team-id <TEAMID> --keychain-profile <perfil> --wait
> xcrun stapler staple signed.pkg
> ```

## Enrolar + carregar o serviço

```sh
sudo suricatoos-agent enroll --state /var/lib/suricatoos-agent \
  --server https://scanner.suricatoos.com/agent/v1 \
  --token "<TOKEN>" --ca-pin "<CA-PIN>"

sudo launchctl bootstrap system /Library/LaunchDaemons/com.suricatoos.agent.plist
sudo launchctl print system/com.suricatoos.agent | grep state
```

- `--server` **deve terminar em `/v1`**; `--ca-pin` aceita `sha256:<hex>`/hex/`AB:CD:..`.
- A URL do ingest é **herdada do enrollment** (sem `--ingest`).
- Logs: `/var/log/suricatoos-agent.log`.

## Remover

```sh
sudo launchctl bootout system/com.suricatoos.agent
sudo rm -f /Library/LaunchDaemons/com.suricatoos.agent.plist /usr/local/bin/suricatoos-agent
sudo pkgutil --forget com.suricatoos.agent
# state (certs) preservado; apague com: sudo rm -rf /var/lib/suricatoos-agent
```
