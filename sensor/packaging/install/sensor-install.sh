#!/bin/sh
# Suricatoos internal scanner sensor — instalador (ADR-0007).
#
# Sobe a stack GVM completa + o sensor-agent DENTRO da rede do cliente. O sensor é
# phone-home (só saída :443 mTLS): no primeiro boot enrola na nuvem (troca o token
# pelo cert mTLS cujo O=tenant), depois puxa jobs, escaneia a rede interna
# autorizada e empurra os achados de volta.
#
# Uso:
#   sudo sh sensor-install.sh \
#     --cloud https://scanner.suricatoos.com \
#     --token <ENROLL_TOKEN> \
#     --scope "10.20.0.0/16,192.168.50.0/24" \
#     [--sensor-id sensor-acme-1] [--image-tarball ./suricatoos-sensor-agent.tar]
#
# Flags:
#   --cloud URL          base da nuvem (deriva /agent/v1/enroll etc.)   [obrigatório]
#   --token TOKEN        bootstrap token (tenant + policy=scanner-sensor) [obrigatório]
#   --scope CIDRS        faixas internas AUTORIZADAS a escanear           [obrigatório]
#   --sensor-id ID       id/CN do sensor (default sensor-<hostname>)
#   --self-deny IPS      IPs a nunca escanear (default: auto-detecta os do host)
#   --image-tarball F    carrega a imagem do sensor-agent via `docker load` (GHCR privado)
#   --state-dir DIR      default /var/lib/suricatoos-sensor
#   --gvm-ref REF        ref do compose.yaml community do Greenbone (default: stable)
set -eu

CLOUD="" TOKEN="" SCOPE="" SENSOR_ID="" SELF_DENY="" IMG_TARBALL="" STATE_DIR="/var/lib/suricatoos-sensor"
GVM_REF="stable"
GVM_COMPOSE_URL="https://greenbone.github.io/docs/latest/_static/docker-compose.yml"

while [ $# -gt 0 ]; do
  case "$1" in
    --cloud)         CLOUD="$2"; shift 2 ;;
    --token)         TOKEN="$2"; shift 2 ;;
    --scope)         SCOPE="$2"; shift 2 ;;
    --sensor-id)     SENSOR_ID="$2"; shift 2 ;;
    --self-deny)     SELF_DENY="$2"; shift 2 ;;
    --image-tarball) IMG_TARBALL="$2"; shift 2 ;;
    --state-dir)     STATE_DIR="$2"; shift 2 ;;
    --gvm-ref)       GVM_REF="$2"; shift 2 ;;
    --gvm-compose-url) GVM_COMPOSE_URL="$2"; shift 2 ;;
    *) echo "flag desconhecida: $1" >&2; exit 2 ;;
  esac
done

[ -n "$CLOUD" ] && [ -n "$TOKEN" ] && [ -n "$SCOPE" ] || {
  echo "uso: sensor-install.sh --cloud URL --token TOKEN --scope CIDRS [...]" >&2; exit 2; }
[ "$(id -u)" = "0" ] || { echo "rode como root (sudo)." >&2; exit 1; }
command -v docker >/dev/null 2>&1 || { echo "docker não encontrado — instale o Docker Engine + compose." >&2; exit 1; }

: "${SENSOR_ID:=sensor-$(hostname | tr 'A-Z' 'a-z')}"

# self-deny: se não informado, nega os IPs não-loopback do próprio host + o IP da
# nuvem (o sensor nunca deve escanear a si mesmo nem o endpoint de nuvem).
if [ -z "$SELF_DENY" ]; then
  host_ips=$(ip -o addr show scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | paste -sd, - || true)
  cloud_host=$(printf '%s' "$CLOUD" | sed -E 's#^https?://##; s#[:/].*$##')
  cloud_ip=$(getent hosts "$cloud_host" 2>/dev/null | awk '{print $1}' | paste -sd, - || true)
  SELF_DENY=$(printf '%s,%s' "$host_ips" "$cloud_ip" | sed 's/^,//; s/,$//')
fi

INSTALL_DIR="/opt/suricatoos-sensor"
mkdir -p "$INSTALL_DIR" "$STATE_DIR"
chmod 700 "$STATE_DIR"

echo "==> Suricatoos sensor: $SENSOR_ID (tenant via token) → $CLOUD"
echo "    escopo autorizado : $SCOPE"
echo "    self-deny (nunca) : $SELF_DENY"

# 1) imagem do sensor-agent (GHCR privado → normalmente via tarball `docker load`).
if [ -n "$IMG_TARBALL" ]; then
  echo "==> carregando imagem do sensor-agent de $IMG_TARBALL"
  docker load -i "$IMG_TARBALL"
fi

# 2) compose.yaml da community edition do Greenbone (a stack GVM completa) +
#    o overlay do sensor (este repo, ao lado deste script).
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
overlay="$here/../../compose/docker-compose.sensor.yml"
[ -f "$overlay" ] || overlay="$here/docker-compose.sensor.yml"   # empacotado plano
cp "$overlay" "$INSTALL_DIR/docker-compose.sensor.yml"

if [ ! -f "$INSTALL_DIR/compose.yaml" ]; then
  echo "==> baixando o compose.yaml da Greenbone Community Edition ($GVM_REF)"
  curl -fsSL "$GVM_COMPOSE_URL" -o "$INSTALL_DIR/compose.yaml" \
    || { echo "falha ao baixar o compose.yaml da Greenbone (egress restrito? forneça --gvm-compose-url ou pré-posicione $INSTALL_DIR/compose.yaml)" >&2; exit 1; }
fi

# 3) sensor.env (host-only, 0600) — senha do gvmd LOCAL gerada por-sensor + config.
LOCAL_GVMD_PW=$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')
umask 077
cat > "$STATE_DIR/sensor.env" <<EOF
ENROLL_TOKEN=$TOKEN
CLOUD_BASE_URL=$CLOUD
SENSOR_ID=$SENSOR_ID
SCAN_SCOPE=$SCOPE
SCAN_SELF_DENY_IPS=$SELF_DENY
SENSOR_GMP_USER=admin
SENSOR_GVM_PASSWORD=$LOCAL_GVMD_PW
EOF
echo "==> sensor.env escrito em $STATE_DIR/sensor.env (0600)"

# 4) sobe a stack: GVM (compose.yaml) + sensor-agent (overlay).
cd "$INSTALL_DIR"
echo "==> subindo a stack (GVM + sensor-agent) — os feeds podem levar um tempo p/ sincronizar"
docker compose -f compose.yaml -f docker-compose.sensor.yml up -d

cat <<EOF

==> Sensor instalado.
    - O sensor-agent enrola na nuvem no primeiro boot (troca o token pelo cert mTLS).
    - Confirme o CN/fingerprint out-of-band antes de habilitar o escopo do tenant na nuvem.
    - Logs:   docker compose -f $INSTALL_DIR/compose.yaml -f $INSTALL_DIR/docker-compose.sensor.yml logs -f sensor-agent
    - Saúde:  o heartbeat aparece na UI de Sensores da nuvem.
    - Kill:   docker compose -f ... down   (revogar o token na nuvem corta o trust de nuvem).
EOF
