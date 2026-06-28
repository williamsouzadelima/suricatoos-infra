# Control plane

Orquestração do parque de agentes — o plano de **autoridade** (split-plane: separado do plano de
dados). Outbound-only do ponto de vista do agente. Ver [`docs/PLAN.md`](../docs/PLAN.md).

- `tokens/` — geração / validação / revogação de **bootstrap tokens**: assinados, TTL curto, uso
  único **ou** deployment token (cap + janela), **scoped** (tenant/policy), revogáveis e auditáveis.
  Ver brief §6.A.
- `distribution/` — download autenticado do agente + montagem do **bundle de enrollment** (binário
  genérico assinado + token + endpoint + CA pinada). **Segredo nunca em query string** — attachment
  autenticado ou handle de uso único.

Responsabilidades: registro de agentes, policy/escopo, comandos (rescan/update/kill/uninstall) e o
canal de auto-update. Linguagem: Go (ver [ADR-0003](../docs/adr/0003-linguagem-do-agente.md)).
**Fase 1** (tokens + enroll) · **Fase 2** (distribuição web).
