# Build context is the REPO ROOT: the runtime needs gmp-bridge/{scan_bridge,bridge}.py,
# and the sensor module imports ingest/scanlaunch (which pulls the ingest module, whose
# go.mod requires correlation). Bring all three modules + a minimal go.work so the build
# resolves the intra-repo imports LOCALLY (mirroring the repo-root workspace) — a plain
# GOWORK=off build of only sensor/ cannot resolve ingest/scanlaunch and fails.
#   docker build -f sensor/Dockerfile -t suricatoos-sensor-agent .
FROM golang:1.25-alpine AS build
WORKDIR /src
COPY sensor/ ./sensor/
COPY ingest/ ./ingest/
COPY correlation/ ./correlation/
RUN printf 'go 1.25\n\nuse (\n\t./sensor\n\t./ingest\n\t./correlation\n)\n' > go.work
WORKDIR /src/sensor
RUN CGO_ENABLED=0 GOOS=linux \
    go build -trimpath -ldflags="-s -w" -o /sensor-agent ./cmd/sensor-agent/

# Runtime carries python3 + python-gvm because scanrun execs scan_bridge.py as a
# subprocess against the LOCAL gvmd socket. scan_bridge.py imports bridge.py at
# runtime, so both live in the same dir.
FROM python:3.12-slim
RUN pip install --no-cache-dir "python-gvm>=27.0.0"
COPY --from=build /sensor-agent /usr/local/bin/sensor-agent
COPY gmp-bridge/scan_bridge.py /usr/local/share/suricatoos/scan_bridge.py
COPY gmp-bridge/bridge.py /usr/local/share/suricatoos/bridge.py
# The sensor drives the LOCAL gvmd; task names use the suricatoos-sensor prefix.
ENV SCAN_BRIDGE_SCRIPT=/usr/local/share/suricatoos/scan_bridge.py \
    BRIDGE_PYTHON=python3 \
    GMP_SOCKET=/run/gvmd/gvmd.sock \
    SENSOR_STATE_DIR=/var/lib/suricatoos-sensor
ENTRYPOINT ["sensor-agent"]
