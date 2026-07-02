#!/bin/sh
# Entrypoint do container do Suricatoos Agent — auto-enroll no tenant no 1º boot,
# depois roda o daemon (coleta + push). Feito para "docker run e funciona".
#
# Config via env (docker run -e ...):
#   ENROLL_TOKEN      (obrigatório no 1º boot) bootstrap token do tenant (single-use)
#   CLOUD_BASE_URL    (obrigatório no 1º boot) ex: https://scanner.suricatoos.com/agent/v1
#   CA_PIN            (recomendado) "sha256:<hex>" da CA de enrollment (pin out-of-band)
#   AGENT_ID          (recomendado no container) id ESTÁVEL do host — senão usa o
#                     hostname DO CONTAINER (efêmero). Passe -e AGENT_ID=<host> ou
#                     --hostname <host> no docker run.
#   COLLECT_INTERVAL  (opcional) ex: 15m (default do binário: 15m)
#   AGENT_STATE_DIR   (opcional) default /var/lib/suricatoos-agent (persista num volume)
#
# A identidade (cert/chave/CA) + a URL de ingest são gravadas no state no enroll e
# reusadas: um restart do container NÃO re-enrola (o token é single-use).
set -e

STATE="${AGENT_STATE_DIR:-/var/lib/suricatoos-agent}"
mkdir -p "$STATE"

if [ ! -f "$STATE/agent.crt" ]; then
	[ -n "$ENROLL_TOKEN" ] || { echo "erro: defina ENROLL_TOKEN (bootstrap token do tenant) no 1º boot" >&2; exit 1; }
	[ -n "$CLOUD_BASE_URL" ] || { echo "erro: defina CLOUD_BASE_URL (ex: https://scanner.suricatoos.com/agent/v1)" >&2; exit 1; }
	echo "[suricatoos-agent] primeiro boot — enrolando no tenant via $CLOUD_BASE_URL ..."
	# monta os args de forma robusta (preserva valores com espaço; flags opcionais só quando setadas)
	set -- --server "$CLOUD_BASE_URL" --token "$ENROLL_TOKEN" --state "$STATE"
	[ -n "$AGENT_ID" ] && set -- "$@" --agent-id "$AGENT_ID"
	[ -n "$CA_PIN" ]   && set -- "$@" --ca-pin "$CA_PIN"
	suricatoos-agent enroll "$@"
	echo "[suricatoos-agent] enrolado (identidade em $STATE)."
else
	echo "[suricatoos-agent] já enrolado — reusando a identidade em $STATE."
fi

# A ingest URL é herdada do enroll (gravada no state); coleta o HOST via HOST_ROOT.
set -- run --state "$STATE"
[ -n "$COLLECT_INTERVAL" ] && set -- "$@" --interval "$COLLECT_INTERVAL"
echo "[suricatoos-agent] iniciando daemon (coleta + push)…"
exec suricatoos-agent "$@"
