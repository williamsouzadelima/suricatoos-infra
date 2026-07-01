# Build context is the REPO ROOT (the ingest module replaces ../correlation and
# the runtime needs gmp-bridge/bridge.py), so build with:
#   docker build -f ingest/Dockerfile -t suricatoos-ingest .
FROM golang:1.25-alpine AS build
WORKDIR /src
# Bring in both modules so the ingest go.mod "replace => ../correlation" resolves.
COPY correlation/ ./correlation/
COPY ingest/ ./ingest/
WORKDIR /src/ingest
# GOWORK=off: build the ingest module standalone via its replace directive
# (no repo-root go.work in the image). Deps (go-deb-version/go-rpm-version) are
# fetched on demand.
RUN CGO_ENABLED=0 GOOS=linux GOWORK=off GOFLAGS=-mod=mod \
    go build -trimpath -ldflags="-s -w" -o /ingest ./cmd/ingest/

# Runtime carries python3 + python-gvm because the pipeline execs gmp-bridge as a
# subprocess (see ingest/pipeline_sink.go). python:3.12-slim ships ca-certificates.
FROM python:3.12-slim
RUN pip install --no-cache-dir "python-gvm>=27.0.0"
COPY --from=build /ingest /usr/local/bin/ingest
COPY gmp-bridge/bridge.py /usr/local/share/suricatoos/bridge.py
# agents_query.py powers GET /agents (the Agents UI): read-only gvmd posture query.
COPY gmp-bridge/agents_query.py /usr/local/share/suricatoos/agents_query.py
# Defaults wiring the bridge; override the rest (NOTUS_DIR, GMP_SOCKET, GVM_PASSWORD) at deploy.
ENV BRIDGE_SCRIPT=/usr/local/share/suricatoos/bridge.py \
    AGENTS_QUERY_SCRIPT=/usr/local/share/suricatoos/agents_query.py \
    BRIDGE_PYTHON=python3
ENTRYPOINT ["ingest"]
