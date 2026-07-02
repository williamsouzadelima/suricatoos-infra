# Build context is the REPO ROOT (the runtime needs gmp-bridge/{scan_bridge,bridge}.py),
# so build with:
#   docker build -f sensor/Dockerfile -t suricatoos-sensor-agent .
FROM golang:1.25-alpine AS build
WORKDIR /src
COPY sensor/ ./sensor/
WORKDIR /src/sensor
# GOWORK=off: build the sensor module standalone (no repo-root go.work in the image).
RUN CGO_ENABLED=0 GOOS=linux GOWORK=off GOFLAGS=-mod=mod \
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
