#!/bin/sh
# Suricatoos Agent — instalador one-shot (Linux/macOS).
#
# Baixa o binário correto do GitHub Release, verifica o SHA-256, instala,
# enrola no control-plane e registra o serviço nativo. Pensado para ser servido
# pela página de Downloads e executado direto:
#
#   curl -fsSL https://scanner.suricatoos.com/install.sh | sudo sh -s -- \
#     --server https://scanner.suricatoos.com/agent/v1 \
#     --token <TOKEN> --ca-pin <CA-PIN>
#
# Flags: --server URL  --token TOKEN  --ca-pin PIN  [--version X.Y.Z]
#        [--repo owner/repo]  [--no-service]
set -eu

REPO="williamsouzadelima/suricatoos-infra"
SERVER="" TOKEN="" CA_PIN="" VERSION="" NO_SERVICE=0

while [ $# -gt 0 ]; do
  case "$1" in
    --server)   SERVER="$2"; shift 2 ;;
    --token)    TOKEN="$2"; shift 2 ;;
    --ca-pin)   CA_PIN="$2"; shift 2 ;;
    --version)  VERSION="$2"; shift 2 ;;
    --repo)     REPO="$2"; shift 2 ;;
    --no-service) NO_SERVICE=1; shift ;;
    *) echo "flag desconhecida: $1" >&2; exit 2 ;;
  esac
done

[ -n "$SERVER" ] && [ -n "$TOKEN" ] || { echo "uso: install.sh --server URL --token TOKEN [--ca-pin PIN]" >&2; exit 2; }
[ "$(id -u)" = "0" ] || { echo "rode como root (sudo)." >&2; exit 1; }

# --- detecta plataforma ---
os=$(uname -s); arch=$(uname -m)
case "$os" in
  Linux)  OS=linux ;;
  Darwin) OS=darwin ;;
  *) echo "SO não suportado: $os" >&2; exit 1 ;;
esac
case "$arch" in
  x86_64|amd64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) echo "arquitetura não suportada: $arch" >&2; exit 1 ;;
esac
BIN_NAME="suricatoos-agent-${OS}-${ARCH}"

# --- resolve a versão (default: último release agent-v*) ---
if [ -z "$VERSION" ]; then
  VERSION=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases" \
    | grep -o '"tag_name": *"agent-v[^"]*"' | head -1 | sed 's/.*agent-v//; s/"//') || true
fi
[ -n "$VERSION" ] || { echo "não consegui resolver a versão; passe --version" >&2; exit 1; }
TAG="agent-v${VERSION}"
BASE="https://github.com/${REPO}/releases/download/${TAG}"

echo ">> Suricatoos Agent ${VERSION} (${OS}/${ARCH})"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

echo ">> baixando ${BIN_NAME}"
curl -fsSL "${BASE}/${BIN_NAME}" -o "$TMP/agent"
curl -fsSL "${BASE}/SHA256SUMS-bin" -o "$TMP/sums" || true

# --- verifica sha256 ---
if [ -s "$TMP/sums" ]; then
  want=$(grep " ${BIN_NAME}\$" "$TMP/sums" | awk '{print $1}')
  if command -v sha256sum >/dev/null 2>&1; then
    got=$(sha256sum "$TMP/agent" | awk '{print $1}')
  else
    got=$(shasum -a 256 "$TMP/agent" | awk '{print $1}')
  fi
  [ -n "$want" ] && [ "$want" = "$got" ] || { echo "!! sha256 não confere ($got != $want)" >&2; exit 1; }
  echo ">> sha256 verificado"
else
  echo "!! SHA256SUMS-bin indisponível — abortando por segurança" >&2; exit 1
fi

# --- instala o binário ---
if [ "$OS" = "darwin" ]; then DEST=/usr/local/bin; else DEST=/usr/bin; fi
install -m 0755 "$TMP/agent" "${DEST}/suricatoos-agent"
echo ">> instalado em ${DEST}/suricatoos-agent"

STATE=/var/lib/suricatoos-agent
mkdir -p "$STATE"

# --- enroll ---
echo ">> enroll no control-plane"
PIN_ARG=""; [ -n "$CA_PIN" ] && PIN_ARG="--ca-pin $CA_PIN"
# shellcheck disable=SC2086
"${DEST}/suricatoos-agent" enroll --state "$STATE" --server "$SERVER" --token "$TOKEN" $PIN_ARG

# --- serviço ---
if [ "$NO_SERVICE" = "0" ]; then
  echo ">> registrando serviço nativo"
  # --state aponta p/ a identidade recém-enrolada; o install herda dela a URL de
  # ingest (server.url persistido), evitando exigir --ingest manualmente.
  "${DEST}/suricatoos-agent" install --state "$STATE"
  echo ">> pronto — agente instalado, enrolado e rodando."
else
  echo ">> pronto — agente instalado e enrolado (serviço não registrado: --no-service)."
fi
