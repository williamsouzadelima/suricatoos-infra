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
