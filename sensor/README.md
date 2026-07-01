# Suricatoos — Sensor de scanner interno (ADR-0007)

Um appliance (container) implantado **dentro** da rede do cliente que roda a stack
GVM completa + o `sensor-agent`. No boot, enrola na nuvem (troca o bootstrap token
pelo cert mTLS cujo `O=tenant`), puxa jobs de scan, escaneia a rede interna
**autorizada** e empurra os achados de volta — tudo **phone-home** (só saída :443).

Ver o design completo em [`docs/adr/0007-sensor-scanner-interno.md`](../docs/adr/0007-sensor-scanner-interno.md).

## Componentes

- `cmd/sensor-agent` — supervisor: enroll → poll job → scan local (scope-gated) →
  push report → heartbeat.
- `internal/scope` — allowlist baked (faixas internas autorizadas − self-protection).
- `internal/scanrun` — dirige `scan_bridge.py` contra o gvmd **local**.
- `internal/cloud` — cliente mTLS (poll/ack/report/heartbeat).
- `internal/enroll` — keygen + CSR + troca do token pelo cert.
- `internal/supervisor` — o loop de controle.
- `Dockerfile` — imagem do `sensor-agent` (Go + python-gvm + `scan_bridge.py`).
- `compose/docker-compose.sensor.yml` — overlay sobre o `compose.yaml` da Greenbone.
- `packaging/install/sensor-install.sh` — instalador.

## Requisitos de host (GVM completa é pesada)

Piso recomendado por sensor: **4 vCPU / 8 GB RAM / 25–30 GB disco** (postgres + redis
+ openvas + feeds). Docker Engine + compose. Egress **só de saída** para
`https://<nuvem>:443`.

## Instalação

```sh
sudo sh sensor-install.sh \
  --cloud https://scanner.suricatoos.com \
  --token <ENROLL_TOKEN> \
  --scope "10.20.0.0/16,192.168.50.0/24" \
  --image-tarball ./suricatoos-sensor-agent.tar   # GHCR privado → docker load
```

O token é mintado na nuvem **via API admin-bearer** (`POST /api/v1/tokens` com
`tenant` + `policy=scanner-sensor`). Confirme o CN/fingerprint do sensor
**out-of-band** antes de habilitar o escopo do tenant na nuvem.

## Segurança

- **Sem porta inbound.** Sockets gvmd/openvasd só na rede do compose.
- **Escopo duplo**: a nuvem só despacha jobs dentro do escopo do tenant, e o sensor
  **re-valida** cada alvo contra seu allowlist baked (self-protection sempre nega
  loopback/metadata/o próprio sensor/a nuvem).
- **Integridade**: a nuvem descarta a severity/CVE que o sensor afirma e re-atesta
  do feed central por OID — um sensor comprometido não forja nem suprime achados.
- **Kill**: revogar o token corta o trust de nuvem (despacho + import) em ≤5min;
  parar o scan local exige teardown operacional (`docker compose down`).
