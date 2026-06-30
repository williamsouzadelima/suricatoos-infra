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
  - **Assinatura GPG: IMPLEMENTADA.** Chave dedicada *Suricatoos Agent Packages*
    (fp `DF0B2F8E…B50F113D`); pública em `packaging/keys/`. `build.sh` assina
    quando `SIGN_KEY_FILE` está definido; o CI assina via segredo `PKG_SIGNING_KEY`.
    Validado: `.rpm` verifica com `rpm -K` ("digests signatures OK"); `.deb` com
    assinatura `_gpgorigin`. Verificação no `README.install.md`.
  - **Distribuição: GitHub Release** no tag `agent-v*` (pacotes + SHA256SUMS + chave
    pública). Opcional/futuro: repo apt/yum com Release/repo assinada (verificação
    automática no `apt`/`dnf` sem baixar o .deb/.rpm avulso).
- **macOS (.pkg): SCAFFOLD pronto** → `packaging/macos/` (pkgbuild + LaunchDaemon).
  - Build: `packaging/macos/build.sh [VERSÃO]` → `.pkg` **universal** (amd64+arm64); CI no `macos-latest`.
  - Validado: payload + perms corretos, binário universal roda; instala via `installer -pkg`.
  - **UNSIGNED** — assinatura + notarização (`productsign` Developer ID + `notarytool` + `stapler`)
    precisam de credenciais Apple do operador. Sem isso, o Gatekeeper bloqueia fora de MDM.
- **Windows (MSI): SCAFFOLD pronto** → `packaging/windows/` (wixl/msitools + .wxs).
  - Build: `packaging/windows/build.sh [VERSÃO]` → `.msi` x64; CI builda via `wixl` no Linux (sem runner Windows).
  - Validado: `msiinfo` confirma o `.exe` na File table, ProductName/Manufacturer/Version corretos.
  - **UNSIGNED** — Authenticode (`signtool`/`osslsigncode`) precisa do cert do operador.
