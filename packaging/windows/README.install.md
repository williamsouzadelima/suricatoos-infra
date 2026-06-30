# Suricatoos Agent — instalação (Windows)

Agente passivo/local de postura de vulnerabilidade (x64). Coleta inventário
local e reporta outbound (mTLS) ao pipeline Suricatoos.

## Instalar

```powershell
msiexec /i suricatoos-agent-<versão>.msi /qn
```

Instala `suricatoos-agent.exe` em `C:\Program Files\Suricatoos Agent\`.

> **Assinatura (Authenticode):** o MSI do CI é **unsigned** — o SmartScreen/AV
> avisa. Em produção, assine (no Windows, ou `osslsigncode` no Linux):
> ```
> signtool sign /fd SHA256 /tr <RFC3161-TSA> /td SHA256 /a suricatoos-agent-X.msi
> ```

## Enrolar + registrar o serviço

```powershell
cd "C:\Program Files\Suricatoos Agent"

.\suricatoos-agent.exe enroll --state "C:\ProgramData\Suricatoos\agent" `
  --server https://scanner.suricatoos.com/agent/v1 `
  --token "<TOKEN>" --ca-pin "<CA-PIN>"

# registra o serviço SCM "SuricatoosAgent" (start automático) e inicia:
.\suricatoos-agent.exe install
sc query SuricatoosAgent
```

- `--server` **deve terminar em `/v1`**; `--ca-pin` aceita `sha256:<hex>`/hex/`AB:CD:..`.
- A URL do ingest é **herdada do enrollment** (sem `--ingest`).
- State (certs): `C:\ProgramData\Suricatoos\agent`.

## Remover

```powershell
.\suricatoos-agent.exe uninstall   # remove o serviço SCM
msiexec /x suricatoos-agent-<versão>.msi /qn
# state (certs) preservado; apague com: rmdir /s "C:\ProgramData\Suricatoos\agent"
```
