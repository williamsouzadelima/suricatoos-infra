#!/usr/bin/env bash
# Builds an UNSIGNED Windows MSI of the Suricatoos Agent (x64), via wixl (msitools).
#
#   packaging/windows/build.sh [VERSION]
#
# Roda em Linux (precisa de go + wixl/msitools). Para PRODUÇÃO, assine com
# Authenticode (no Windows, ou osslsigncode no Linux):
#   signtool sign /fd SHA256 /tr <RFC3161-TSA> /td SHA256 /a suricatoos-agent-X.msi
#   # ou: osslsigncode sign -pkcs12 cert.p12 -ts <TSA> -in in.msi -out signed.msi
# Sem isso o SmartScreen/AV avisa.
set -euo pipefail

VERSION="${1:-0.1.0}"
REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT"
mkdir -p dist

echo ">> build suricatoos-agent.exe (windows/amd64)"
( cd agent && GOOS=windows GOARCH=amd64 CGO_ENABLED=0 GOWORK=off \
    go build -trimpath -ldflags="-s -w" -o "$REPO_ROOT/dist/suricatoos-agent.exe" ./cmd/suricatoos-agent/ )

echo ">> render .wxs + wixl"
wxs="dist/suricatoos-agent.wxs"
sed -e "s|\${VERSION}|$VERSION|g" packaging/windows/suricatoos-agent.wxs > "$wxs"
wixl -o "dist/suricatoos-agent-$VERSION.msi" "$wxs"

echo "=== gerado (UNSIGNED) ==="
ls -la "dist/suricatoos-agent-$VERSION.msi"
