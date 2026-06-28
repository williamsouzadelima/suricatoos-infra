# Correlation engine

Aplica as advisories **Notus** (rpm/deb) ao inventário do agente, **server-side**, atrás de uma
interface plugável (`Correlator`). Produz achados conforme
[`schema/finding.schema.json`](../schema/finding.schema.json) — cada achado **rastreável** ao pacote
coletado + OID da advisory (não-fabricação).

- v1: **Linux/Notus** (Decisão D1 — ver [ADR-0001](../docs/adr/0001-modelo-de-coleta.md)).
- Windows/macOS: fonte de correlação plugada depois (CPE→NVD ou Local Security Checks de Windows do
  feed Greenbone). **Sem fabricar achado onde não há advisory.**

Reusa o feed Greenbone mantido fresco pelo feed-updater. **Fase 2.**
