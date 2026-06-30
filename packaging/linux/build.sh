#!/usr/bin/env bash
# Builds the Suricatoos Agent .deb and .rpm for linux/amd64 + linux/arm64.
#
#   packaging/linux/build.sh [VERSION]
#
# Requires: go (or run in golang image) and nfpm (github.com/goreleaser/nfpm).
# Output: dist/*.deb dist/*.rpm
set -euo pipefail

VERSION="${1:-0.1.0}"
REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT"
mkdir -p dist

for arch in amd64 arm64; do
  echo ">> build binário linux/$arch"
  ( cd agent && GOOS=linux GOARCH="$arch" CGO_ENABLED=0 GOWORK=off \
      go build -trimpath -ldflags="-s -w" \
      -o "$REPO_ROOT/dist/suricatoos-agent-$arch" ./cmd/suricatoos-agent/ )

  # Renderiza o nfpm.yaml com sed (robusto entre versões do nfpm — não depende
  # da env-expansion do nfpm, que varia).
  cfg="dist/nfpm-$arch.yaml"
  sed -e "s|\${PKG_ARCH}|$arch|g" -e "s|\${PKG_VERSION}|$VERSION|g" \
    packaging/linux/nfpm.yaml > "$cfg"

  for pkg in deb rpm; do
    echo ">> nfpm $pkg ($arch)"
    nfpm package -f "$cfg" -p "$pkg" -t dist/
  done
done

echo "=== pacotes gerados ==="
ls -1 dist/*.deb dist/*.rpm
