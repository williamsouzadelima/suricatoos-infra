# Container do Suricatoos Agent (endpoint) — auto-enroll no tenant + inventário do HOST.
# O módulo agent é standalone (não importa outros módulos do repo), então o build é
# direto. Build context = REPO ROOT:
#   docker build -f agent/Dockerfile -t suricatoos-agent .
FROM golang:1.25-alpine AS build
WORKDIR /src/agent
COPY agent/ ./
# GOWORK=off: build standalone (sem o go.work da raiz na imagem).
RUN CGO_ENABLED=0 GOOS=linux GOWORK=off \
    go build -trimpath -ldflags="-s -w" -o /suricatoos-agent ./cmd/suricatoos-agent/

FROM debian:stable-slim
# ca-certificates: valida o cert PÚBLICO (Let's Encrypt) do scanner no push mTLS
#   (o agente confia no system trust p/ o servidor; a CA de enroll é só p/ o client cert).
# rpm: inventário de hosts RPM (dpkg status + os-release são lidos como ARQUIVOS,
#   sem binário — só o rpm precisa do executável).
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates rpm \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /suricatoos-agent /usr/local/bin/suricatoos-agent
COPY agent/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh
# HOST_ROOT=/host: o coletor lê o inventário do HOST montado (`-v /:/host:ro`),
# não da imagem (quase vazia) do container.
ENV HOST_ROOT=/host \
    AGENT_STATE_DIR=/var/lib/suricatoos-agent
# Persista a identidade enrolada num volume (evita re-enroll a cada restart).
VOLUME /var/lib/suricatoos-agent
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
