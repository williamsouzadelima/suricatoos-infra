# 0009 — Hardening CIS Nível 1 (Windows)

- **Status:** PROPOSTO (F1a — coleta de postura neutra — implementada)
- **Data:** 2026-10-08
- **Deciders:** William (mantenedor), Claude Code
- **Relacionado:** [0001-modelo-de-coleta](0001-modelo-de-coleta.md), [0008-correlacao-windows-msrc](0008-correlacao-windows-msrc.md), [0010-executor-remediacao-windows](0010-executor-remediacao-windows.md)

## Contexto e problema

A correlação por pacote (Notus) e a correlação de patch (MSRC, [ADR-0008](0008-correlacao-windows-msrc.md))
pegam **vulnerabilidade de software**, mas não pegam **misconfiguração** — contas sem política de
senha, auditoria desligada, SMBv1/NTLM fracos, UAC frouxo. O dono definiu que o hardening da
plataforma é **CIS Nível 1 + remediação dos achados do scanner**. O [ADR-0001](0001-modelo-de-coleta.md)
rejeitou um mini-scanner no endpoint ("checks tipo CIS só depois da v1, como plugin") e exige
não-fabricação: nenhum achado sem evidência rastreável.

## Decisão

1. **Coleta de estado NEUTRA no endpoint, julgamento no SERVIDOR.** O agente lê a configuração de
   segurança e reporta `facts.cis_state[] {source, key, value}` — **só o valor medido**, sem
   pass/fail e **sem mapear regra CIS**. Fontes: `secedit /export` (política de conta/senha/bloqueio
   e *Privilege Rights*), `auditpol /get /category:* /r` (política de auditoria por subcategoria),
   um conjunto semente de valores de **registro** de política e de **start-type de serviços**. O
   endpoint continua burro: não sabe o que é "conforme".
2. **O ruleset vive no servidor e é AUTORAL (F1b).** O mapeamento `(source,key) → valor esperado +
   severidade + descrição/remediação` é escrito **por nós**, citando apenas o **número** da regra CIS
   por referência (um número é fato, não texto copiável), com base técnica em fontes livres
   (Microsoft Security Baseline, SCAP, STIG). **Não copiar a prosa do benchmark CIS.** Confirmar a
   linha exata com a mesma política `LICENCA_CIS` do produto "reports".
3. **Não-fabricação.** O achado de hardening sai da comparação `valor medido × valor esperado da
   regra publicada`. A **severidade é propriedade fixa da regra** (`severity_origin:
   "suricatoos-hardening-baseline"`), nunca calculada por host e **nunca por IA**. Evidência =
   `{current_value, expected_value, rule_ref, source}`. Renderiza como **Mitigation** na caixa
   "Solução/Remediação" do relatório premium (patches = VendorFix).
4. **Minimização LGPD.** *Privilege Rights* do `secedit` enumeram contas locais por SID. O coletor
   **redige para SIDs well-known** (`Administrators`, `Guests`, `AuthenticatedUsers`, …); um SID
   específico do host vira `custom-sid` e um nome de conta vira `custom-account`, ordenados e
   de-duplicados. Nenhum nome de usuário ou SID arbitrário deixa a máquina. O nome da máquina do
   `auditpol` é descartado. Registrado em `docs/data-inventory.md`.

## Consequências

- 👍 O parque Windows passa a ter achados de hardening com evidência, sem scanner ativo no endpoint
  e sem vazar identidade de conta.
- 👍 A maior parte do CIS L1 (senha/bloqueio/auditoria/privilégios) vem de `secedit`+`auditpol`, que
  são **dumps completos e neutros** — não uma seleção curada (menos superfície de "conteúdo CIS" no
  endpoint). Registro e serviços usam uma lista semente modesta (pontos de config públicos do SO).
- ⚠️ O bump de contrato é aditivo (`schema_version` 1.2.0, campo opcional) — o ingest aceita `1.x`;
  vale a mesma ordem de deploy do ADR-0008 (ingest antes dos agentes).
- ⚠️ O `cis_state` é coletado mas **só vira achado quando o ruleset do servidor (F1b) existir** —
  até lá é dado inerte no inventário (o ingest nem o lê).

## Opções rejeitadas

- **Julgar conformidade no endpoint.** Poria o ruleset CIS (conteúdo + severidade) na máquina do
  cliente e violaria o ADR-0001 (endpoint passivo/burro). Rejeitado: julgamento é server-side.
- **Enviar o `secedit`/`auditpol` cru sem redigir.** Vazaria contas locais (LGPD). Rejeitado: SID
  scrub obrigatório antes de sair do host.
- **Copiar a prosa do benchmark CIS no ruleset.** Problema de licença. Rejeitado: descrição autoral,
  só o número da regra por referência.

## Rollout

- **F1a (este PR):** contrato `cis_state` (schema 1.2.0) + coletores (secedit/auditpol/registro/
  serviço) com redação de SID + parsers portáveis golden-testados + LGPD. **Zero escrita, zero
  achado.**
- **F1b:** ruleset autoral server-side + `HardeningCorrelator` (compõe com o MSRC no dispatch
  Windows) + mapeamento no `gmp-bridge` (achado como Mitigation, severidade da regra) → achados de
  hardening no gvmd.
