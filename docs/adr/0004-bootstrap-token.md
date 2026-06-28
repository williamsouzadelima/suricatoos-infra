# 0004 — Formato do bootstrap token

- **Status:** ACEITO (2026-06-28)
- **Deciders:** William (mantenedor), Claude Code
- **Relacionado:** [0002-destino-dos-resultados](0002-destino-dos-resultados.md); brief §6.A

## Contexto e problema

O download do agente carrega um **bootstrap token** consumido uma vez no enrollment (CSR → cert
mTLS). Requisitos do brief §6.A: **verificável**, **TTL curto**, **uso único OU deployment** (cap +
janela), **scoped** (tenant/policy, opcionalmente OS/arch), **revogável** e **auditável**.

## Opções consideradas

- **JWT assinado.** Claims no token, verificação stateless.
  - 👍 Ubíquo. 👎 Footguns (alg confusion, `alg:none`); e mesmo assim precisa de estado server-side
    para uso-único/cap/revogação (claims não bastam).
- **PASETO v4.local.** Claims cifrados/autenticados (XChaCha20-Poly1305), sem alg confusion.
  - 👍 Cripto moderna, claims confidenciais. 👎 Ainda precisa de estado para cap/revogação;
    complexidade extra para benefício marginal no nosso caso.
- **Opaque + estado server-side (recomendado).** Token = segredo aleatório de alta entropia; o servidor
  guarda só o **hash** do segredo + metadata (o `Record`).
  - 👍 Simples e seguro (padrão de PAT/enroll-secret); o servidor é a **única fonte de verdade**; nada
    de claims para vazar. 👎 Exige o servidor online para validar (sempre verdade no enrollment).

## Decisão

**Token opaco `st_<id>.<secret>`** (id público de 72 bits para lookup O(1); secret de 256 bits). O
servidor persiste **apenas `sha256(secret)`** + metadata; o secret é mostrado ao operador **uma vez** e
nunca gravado. Como **uso-único, deployment-cap e revogação EXIGEM estado server-side**, um token
stateless (JWT/PASETO) seria redundante — o `Record` já é a fonte de verdade.

Validação = parse → lookup por `id` → **compare em tempo constante** de `sha256(secret)` → checagem de
`revoked`/`expirado`/`uses` → (para Consume) **incremento atômico** sob lock. Segredo errado e id
inexistente retornam o **mesmo erro** (não vaza existência).

## Consequências

- 👍 Atende todas as propriedades do §6.A com o mínimo de superfície criptográfica.
- 👍 Revogação imediata (flag no `Record`); trilha de auditoria (`Enrollments[]`, `CreatedBy`, `RevokedBy`).
- 👎 Validação depende do store online — aceitável (enrollment é online por natureza).
- **PASETO v4.local** fica documentado como alternativa se um dia houver control plane distribuído que
  precise de verificação stateless/federada.

## Notas de segurança (mitigações do threat model §6.A)

- *Vazamento via URL* → o secret nunca vai em query string (download autenticado por attachment/handle
  único — control-plane/distribution, Fase 2).
- *Replay/reuso* → uso-único/cap + TTL + revogação; **CSR (prova de posse de chave)** no enrollment.
- *Confused-deputy / multi-tenant* → tenant/policy são **atribuídos pelo token** (o enrollee não os
  escolhe); OS/arch esperados são **verificados** (`Scope.permits`).
