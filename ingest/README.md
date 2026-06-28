# Ingest (data plane)

Recebe os inventários dos agentes via mTLS — assinados e idempotentes por `cycle_hash`. É o plano de
**dados**, separado do control plane (split-plane). Valida contra
[`schema/inventory.schema.json`](../schema/inventory.schema.json) e entrega à correlação.

Go (ver [ADR-0003](../docs/adr/0003-linguagem-do-agente.md)). **Fase 1** (stub) · **Fase 2**
(liga na correlação + bridge). Ver [`docs/PLAN.md`](../docs/PLAN.md).
