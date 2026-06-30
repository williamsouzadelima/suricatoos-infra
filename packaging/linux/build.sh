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

# Injeta versão/commit/data no pacote version (usado pelo auto-update p/ comparar
# versões — sem isto o binário se reporta "0.0.0-dev" e tentaria atualizar sempre).
VER_PKG="github.com/williamsouzadelima/suricatoos-infra/agent/internal/version"
COMMIT="$(git -C "$REPO_ROOT" rev-parse --short HEAD 2>/dev/null || echo none)"
BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
LDFLAGS="-s -w -X ${VER_PKG}.Version=${VERSION} -X ${VER_PKG}.Commit=${COMMIT} -X ${VER_PKG}.BuildDate=${BUILD_DATE}"

for arch in amd64 arm64; do
  echo ">> build binário linux/$arch (v$VERSION)"
  ( cd agent && GOOS=linux GOARCH="$arch" CGO_ENABLED=0 GOWORK=off \
      go build -trimpath -ldflags="$LDFLAGS" \
      -o "$REPO_ROOT/dist/suricatoos-agent-$arch" ./cmd/suricatoos-agent/ )

  # Renderiza o nfpm.yaml com sed (robusto entre versões do nfpm — não depende
  # da env-expansion do nfpm, que varia).
  cfg="dist/nfpm-$arch.yaml"
  sed -e "s|\${PKG_ARCH}|$arch|g" -e "s|\${PKG_VERSION}|$VERSION|g" \
    packaging/linux/nfpm.yaml > "$cfg"

  # Assinatura GPG opcional: se SIGN_KEY_FILE apontar p/ uma chave privada,
  # injeta as seções deb/rpm signature (nfpm assina durante o package).
  if [ -n "${SIGN_KEY_FILE:-}" ]; then
    cat >> "$cfg" <<YAML
deb:
  signature:
    key_file: ${SIGN_KEY_FILE}
rpm:
  signature:
    key_file: ${SIGN_KEY_FILE}
YAML
    echo ">> assinatura GPG habilitada"
  fi

  for pkg in deb rpm; do
    echo ">> nfpm $pkg ($arch)"
    nfpm package -f "$cfg" -p "$pkg" -t dist/
  done
done

echo "=== pacotes gerados ==="
ls -1 dist/*.deb dist/*.rpm
