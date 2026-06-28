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
  escolhe), e **Tenant é obrigatório** no Mint. OS/arch esperados são **defesa em profundidade**
  (auto-declarados pelo enrollee, não atestados — barram erro de config, não adversário); `Scope.permits`
  rejeita valor vazio quando o token fixa um.

## Hardening pós-review adversarial (2026-06-28)

Uma review adversarial multi-agente (5 lentes: X.509/CA, cripto/PoP, mTLS, authz/token, leak/DoS)
endureceu o fluxo. **Aplicado:**

- **Ordem do enrollment:** `Validate` (read-only, barato) → CSR (PoP + CN) → `Sign` → `Consume`
  (commit). Falha de assinatura **não queima** um token de uso único; o gate barato primeiro mitiga DoS
  de parse de CSR pré-autenticação.
- **Scope OS/arch:** apresentar vazio **não** satisfaz um token pinado (bypass corrigido); a mensagem de
  erro não revela o valor esperado.
- **Política de chave** na CA: só Ed25519 / ECDSA P-256·384·521 / RSA ≥ 2048.
- **Tenant obrigatório** no Mint + **cap de MaxUses** (`MaxDeploymentUses`).
- **agent_id** validado (charset/comprimento; sem caracteres especiais de DN).
- **Agente:** `Enroll` exige **https** + recusa redirect cross-scheme (anti-downgrade); `verify()` confere
  cadeia → CA pinada + leaf ≡ chave privada; **pin opcional de fingerprint** da CA (`--ca-pin`); chave
  salva com **0600 forçado** (mesmo sobre arquivo pré-existente).
- **Erros do handler** genéricos ao cliente (não vazam escopo nem strings do x509).

**Diferido (precisa de registro/DB ou wiring de servidor — Fase 2/4):**

- **Unicidade de `agent_id` por tenant** + binding do agent_id ao token (precisa de registro) — hoje há
  colisão intra-tenant possível.
- **Revogação de certs já emitidos** (CRL/OCSP/denylist) — `Revoke` só barra enrollments futuros;
  mitigar com TTL de cert curto até lá.
- **Atomicidade multi-réplica:** o `Store` precisará de um *consume condicional atômico*
  (`UPDATE … WHERE used_count < max_uses`) quando virar DB com mais de uma réplica; hoje o cap depende
  do mutex de processo.
- **Rate-limit + timeouts** de `http.Server` no wiring do endpoint (nginx + `ReadHeaderTimeout`/`IdleTimeout`).
- Entrega do **fingerprint da CA out-of-band** no bundle de enrollment (Fase 2 distribution).
