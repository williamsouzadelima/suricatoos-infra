# Packaging

Pacotes nativos + assinatura. O binário é **genérico e assinado** (uma assinatura para todos); o que
varia por download é o **bundle de enrollment** (token injetado como parâmetro de instalação). Ver
brief §6.A e §7.

- **Linux:** `.deb` / `.rpm` assinados (`dpkg-sig` / `rpm --addsign`); serviço via systemd.
- **macOS:** `.pkg` com **codesign + notarytool** (notarização — senão o Gatekeeper bloqueia);
  serviço via launchd LaunchDaemon.
- **Windows:** **MSI + Authenticode** (`signtool`) para reduzir SmartScreen/AV; serviço via SCM. O
  token de enrollment entra como propriedade do MSI.

**Fase 4.**

## Estado

- **Linux (.deb/.rpm): IMPLEMENTADO** → `packaging/linux/` (nfpm + systemd + scripts).
  - Build: `packaging/linux/build.sh [VERSÃO]` → `dist/*.deb` e `dist/*.rpm` (amd64 + arm64).
  - CI: `.github/workflows/agent-package.yml` (manual ou tag `agent-v*`; sobe os pacotes como artifacts).
  - Instalação/uso: `packaging/linux/README.install.md` (enroll → `systemctl enable --now`).
  - Validado: instala em Debian 12 limpo; unit systemd + state dir corretos; `suricatoos-agent inventory` coleta.
  - **Pendente: assinatura** (`dpkg-sig` / `rpm --addsign`) — precisa de chave GPG.
- **macOS (.pkg) e Windows (MSI): pendentes** — exigem credenciais de assinatura
  (Apple Developer ID + notarytool; Authenticode/signtool) que ficam com o operador.
