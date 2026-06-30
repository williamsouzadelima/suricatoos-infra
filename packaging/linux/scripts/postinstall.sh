#!/bin/sh
# Suricatoos Agent — pós-instalação (.deb/.rpm).
set -e

# State dir do enrollment (certs + ingest.url). 0700: só root lê os certs.
mkdir -p /var/lib/suricatoos-agent/queue
chmod 700 /var/lib/suricatoos-agent

if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload || true
fi

cat <<'EOF'

Suricatoos Agent instalado. O serviço NÃO foi habilitado (precisa enrolar antes).
Próximos passos:

  suricatoos-agent enroll --state /var/lib/suricatoos-agent \
    --server https://scanner.suricatoos.com/agent/v1 \
    --token <TOKEN-DO-BUNDLE> --ca-pin <CA-PIN>

  systemctl enable --now suricatoos-agent
  systemctl status suricatoos-agent

A URL do ingest é herdada do enrollment (não precisa --ingest).
EOF

exit 0
