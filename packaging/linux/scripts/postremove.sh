#!/bin/sh
# Suricatoos Agent — pós-remoção.
set -e
if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload 2>/dev/null || true
fi
# O state dir (/var/lib/suricatoos-agent: certs + identidade) é PRESERVADO de
# propósito (permite reinstalar sem re-enrolar). Para apagar de vez:
#   rm -rf /var/lib/suricatoos-agent
exit 0
