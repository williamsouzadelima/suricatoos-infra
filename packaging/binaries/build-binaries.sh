#!/usr/bin/env bash
# Builds RAW, version-stamped agent binaries for every supported platform and an
# auto-update manifest pointing at the GitHub Release assets.
#
#   packaging/binaries/build-binaries.sh [VERSION]
#
# Output (in dist/bin/):
#   suricatoos-agent-<os>-<arch>[.exe]   raw binaries (what the auto-updater swaps in)
#   SHA256SUMS-bin                       checksums of the raw binaries
#   update-manifest.json                 control-plane UPDATE_MANIFEST_FILE (urls + sha256)
#
# The manifest URLs assume the binaries are published on the Release tag
# agent-v<VERSION> of OWNER/REPO (defaults below; override via env).
set -euo pipefail

VERSION="${1:-0.1.0}"
OWNER="${OWNER:-williamsouzadelima}"
REPO="${REPO:-suricatoos-infra}"
TAG="agent-v${VERSION}"
REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="$REPO_ROOT/dist/bin"
BASE_URL="https://github.com/${OWNER}/${REPO}/releases/download/${TAG}"

cd "$REPO_ROOT"
mkdir -p "$OUT"

VER_PKG="github.com/williamsouzadelima/suricatoos-infra/agent/internal/version"
COMMIT="$(git rev-parse --short HEAD 2>/dev/null || echo none)"
BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
LDFLAGS="-s -w -X ${VER_PKG}.Version=${VERSION} -X ${VER_PKG}.Commit=${COMMIT} -X ${VER_PKG}.BuildDate=${BUILD_DATE}"

# os/arch matrix → output filename. Windows gets .exe.
PLATFORMS="linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64"

artifacts_json=""
for plat in $PLATFORMS; do
  os="${plat%/*}"; arch="${plat#*/}"
  name="suricatoos-agent-${os}-${arch}"
  [ "$os" = "windows" ] && name="${name}.exe"
  echo ">> build ${os}/${arch} -> ${name}"
  ( cd agent && GOOS="$os" GOARCH="$arch" CGO_ENABLED=0 GOWORK=off \
      go build -trimpath -ldflags="$LDFLAGS" -o "$OUT/$name" ./cmd/suricatoos-agent/ )
  sha="$(sha256sum "$OUT/$name" | awk '{print $1}')"
  artifacts_json="${artifacts_json}    {\"os\":\"${os}\",\"arch\":\"${arch}\",\"url\":\"${BASE_URL}/${name}\",\"sha256\":\"${sha}\"},
"
done

( cd "$OUT" && sha256sum suricatoos-agent-* > SHA256SUMS-bin )

# update-manifest.json — strip the trailing comma of the last artifact.
artifacts_json="${artifacts_json%,
}"
cat > "$OUT/update-manifest.json" <<JSON
{
  "version": "${VERSION}",
  "artifacts": [
${artifacts_json}
  ]
}
JSON

echo "=== binários crus + manifesto ==="
ls -1 "$OUT"
echo "--- update-manifest.json ---"
cat "$OUT/update-manifest.json"
