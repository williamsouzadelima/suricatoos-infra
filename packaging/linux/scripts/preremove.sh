#!/bin/sh
# Suricatoos Agent — pré-remoção: para e desabilita o serviço.
set -e
if command -v systemctl >/dev/null 2>&1; then
  systemctl disable --now suricatoos-agent 2>/dev/null || true
fi
exit 0
