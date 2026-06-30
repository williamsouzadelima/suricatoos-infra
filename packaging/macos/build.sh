#!/usr/bin/env bash
# Builds an UNSIGNED macOS .pkg of the Suricatoos Agent (universal: amd64+arm64).
#
#   packaging/macos/build.sh [VERSION]
#
# macOS-only (usa pkgbuild + lipo). Para PRODUÇÃO, assine e NOTARIZE:
#   productsign --sign "Developer ID Installer: ..." in.pkg out.pkg
#   xcrun notarytool submit out.pkg --apple-id ... --team-id ... --wait
#   xcrun stapler staple out.pkg
# Sem isso o Gatekeeper bloqueia a instalação fora de canais gerenciados (MDM).
set -euo pipefail

VERSION="${1:-0.1.0}"
REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT"
mkdir -p dist

echo ">> build binário universal (darwin amd64 + arm64)"
( cd agent && GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 GOWORK=off \
    go build -trimpath -ldflags="-s -w" -o "$REPO_ROOT/dist/suricatoos-agent-darwin-amd64" ./cmd/suricatoos-agent/ )
( cd agent && GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 GOWORK=off \
    go build -trimpath -ldflags="-s -w" -o "$REPO_ROOT/dist/suricatoos-agent-darwin-arm64" ./cmd/suricatoos-agent/ )
lipo -create -output "$REPO_ROOT/dist/suricatoos-agent-darwin" \
  "$REPO_ROOT/dist/suricatoos-agent-darwin-amd64" "$REPO_ROOT/dist/suricatoos-agent-darwin-arm64"
lipo -info "$REPO_ROOT/dist/suricatoos-agent-darwin"

echo ">> monta o payload + pkgbuild"
ROOT="$(mktemp -d)"
mkdir -p "$ROOT/usr/local/bin" "$ROOT/Library/LaunchDaemons"
install -m 0755 "$REPO_ROOT/dist/suricatoos-agent-darwin" "$ROOT/usr/local/bin/suricatoos-agent"
install -m 0644 packaging/macos/com.suricatoos.agent.plist "$ROOT/Library/LaunchDaemons/com.suricatoos.agent.plist"

pkgbuild --root "$ROOT" \
  --scripts packaging/macos/scripts \
  --identifier com.suricatoos.agent \
  --version "$VERSION" \
  --install-location / \
  "dist/suricatoos-agent-$VERSION.pkg"

rm -rf "$ROOT"
echo "=== gerado (UNSIGNED) ==="
ls -la "dist/suricatoos-agent-$VERSION.pkg"
