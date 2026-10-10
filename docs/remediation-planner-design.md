# Remediation Planner — desenho do serviço de IA (Fase 4)

> **Status:** DESENHO (não implementado). A **decisão** já está no [ADR-0010](adr/0010-executor-remediacao-windows.md) §6;
> este documento detalha o **como**. Reusa a governança de IA já provada em outro produto da casa
> (contrato pago OpenRouter, UE, ZDR, pseudonimização, consentimento por finalidade, orçamento).
>
> **Regra de ouro:** a IA **redige**, o humano **decide**. O planner nunca origina achado, nunca
> define severidade, nunca aprova, nunca assina, nunca aplica.

## 1. Objetivo e não-objetivos

**Objetivo.** A partir de um `Finding` **já atestado** (origem autoritativa: Notus/MSRC/baseline CIS +
evidência — [ADR-0001](adr/0001-modelo-de-coleta.md)), redigir um **rascunho revisável** de:
explicação do achado, plano de correção proposto, consideração de prioridade e notas de rollback/risco.
Esse rascunho acompanha o achado e **antecede** o `PENDING_APPROVAL`; um humano revisa, edita e só então
aprova (o que dispara a assinatura do job — [ADR-0010](adr/0010-executor-remediacao-windows.md)).

**Não-objetivos (proibições duras):**
- ❌ **Não origina achado nem severidade/CVE** — essas vêm *verbatim* da fonte atestada e entram no
  prompt como **contexto imutável**, nunca como algo a calcular.
- ❌ **Não aprova, não assina, não enfileira, não aplica** — não tem acesso às chaves nem às rotas de
  operador; a saída é texto consultivo anexado ao achado.
- ❌ **Não recebe dado pessoal nem identidade real do host** (ver §5).
- ❌ **Não é bloqueante** — se o planner estiver desligado, fora do orçamento ou indisponível, o fluxo
  segue com o humano redigindo manualmente (§8).

## 2. Posição no fluxo

```
Finding ATESTADO (severity/CVE da fonte, evidência)
   │
   ├──► remediation-planner (IA)  ── rascunho {explicação, plano, prioridade, rollback, ressalvas}
   │         (sem chaves; entrada pseudonimizada; saída = texto consultivo)
   ▼
operador REVISA/edita o rascunho ──► aprova  ──►  control-plane ASSINA o job (PENDING_APPROVAL→APPROVED)
                                                   (§6 do ADR-0010; a IA não participa daqui em diante)
```

O planner é um **produtor de rascunho**, lateral ao caminho de decisão. Remover o planner não muda a
corretude do pipeline — só tira a ajuda de redação.

## 3. Contrato de entrada/saída

**Entrada (allowlist estrita, pseudonimizada).** Apenas campos técnicos do achado + a postura técnica
relevante do host; **nunca** o inventário cru. Exemplo do que PODE entrar:

- Tipo do achado (`package_patch` | `config_hardening`), `oid`/`cve` (identificadores públicos já
  atestados), **severidade da fonte (como contexto fixo)**, `source`/`severity_origin`.
- Alvo técnico: KB/`update_id` (patch) **ou** nº da regra CIS + `key` + `current_value`/`expected_value`
  (hardening).
- Postura técnica que muda o plano: `os.build`/`os.ubr`, flags de `facts.management`
  (domain_joined/wsus/intune) — para o rascunho já avisar "gerido por GPO, trate na política".
- Um **id opaco do host** (pseudônimo estável) para agrupar achados do mesmo host — **nunca** hostname/IP.

**Saída (estruturada, `output_config` json_schema — Claude 5).** Texto consultivo, sem severidade:

```json
{
  "explanation": "string — por que o achado importa, em linguagem de operador",
  "plan_steps": ["string — passos propostos, REVISÁVEIS, não executáveis automaticamente"],
  "prioritization": { "suggested_rank": "int", "rationale": "string — NÃO altera a severidade da fonte" },
  "rollback_notes": "string — como reverter / o que capturar antes",
  "caveats": "string — efeitos colaterais, alto raio (SMBv1/NTLM/LSA/UAC/RDP), dependências de reboot"
}
```

A saída é anexada ao achado como **"rascunho de IA — revisar"**. Campos como `severity`/`cve` **não
existem na saída**: se o modelo tentar inventá-los, não há onde gravá-los.

## 4. Governança (padrão de IA da casa)

- **Contrato OpenRouter pago**, **região UE**, **ZDR** (zero data retention), *only regional*.
- **Orçamento mensal** (~US$50) com corte: acima do teto, o planner **desliga** (não degrada silenciosamente).
- **Consentimento por finalidade, por tenant** (default **off**; só admin+MFA liga). Sem consentimento,
  nenhum dado do tenant é enviado.
- **Regras Claude 5:** sem `temperature`, sem prefill, resposta via `output_config` json_schema.
- Serviço **nasce DARK** (flag global desligada), como todo o resto da remediação.

## 5. Pseudonimização e minimização

Antes de qualquer chamada ao provedor, um **mapa server-side** substitui identidade por referência
opaca: `hostname/IP/usuário/tenant → id opaco`. O modelo só vê **referências opacas + dado técnico do
achado**. O mapa fica na nuvem e **não** é enviado. Allowlist explícita de campos (§3): qualquer campo
fora dela é descartado por omissão, não por bloqueio (fail-closed de dado). Se um segredo aparecer num
valor de config (ex.: string de conexão), ele é **redigido** antes do envio e marcado para revisão
humana.

## 6. Isolamento de chaves

O `remediation-planner` roda como serviço separado e **não monta `/data/*.key`** — só o control-plane
tem as chaves de assinatura (feed/update/CA/remediação). O `OPENROUTER_API_KEY` vive em
`/var/lib/suricatoos-cp/remediation-planner.env` (0600, `required:false`). Assim, comprometer o planner
**não** dá poder de assinar jobs nem de forjar achados — ele não tem a 4ª chave nem acesso à fila.

## 7. Não-fabricação e não-decisão (como é imposto, não só prometido)

- A **severidade/CVE entram como contexto** e **não há campo de saída** para elas → o modelo não pode
  "promover" um achado.
- O planner **não tem credencial** para as rotas de operador (enqueue/approve) nem para a fila → não
  pode enfileirar/aprovar mesmo que "quisesse".
- O rascunho é inerte até um humano agir; a aprovação (que dispara a assinatura) é **sempre** humana.
- A saída é rotulada como rascunho de IA na UI; o operador vê que precisa revisar.

## 8. Modos de falha (nunca bloquear)

| Situação | Comportamento |
|---|---|
| Planner desligado (flag/consentimento off) | Sem rascunho; operador redige manualmente. Fluxo segue. |
| Orçamento estourado | Planner corta; sem rascunho; alerta ao admin. |
| Provedor indisponível / timeout | Sem rascunho; o achado continua aprovável sem ajuda de IA. |
| Saída não valida no json_schema | Rascunho descartado; sem rascunho (nunca texto livre não-estruturado). |

## 9. LGPD

O canal de remediação já é registrado em [data-inventory](data-inventory.md) (sem dado pessoal). O planner
**estreita** ainda mais: allowlist técnica + pseudonimização + ZDR + UE + consentimento. Nenhum dado
pessoal, nenhum inventário cru, nenhuma identidade real do host deixa a nuvem rumo ao provedor.

## 10. Rollout

- **Pré-requisito:** Fase 3 (executor + canário em LAB) estável; sem ela não há o que planejar aplicar.
- **Dark primeiro:** serviço implantado desligado; ligado por tenant só após consentimento.
- **Entra entre** o achado atestado e o `PENDING_APPROVAL`, como produtor de rascunho; a UI `/remediation`
  (Fase 4) mostra o rascunho ao lado do "aprovar por ação".
- Reusa o cliente/governança de IA já provado em outro produto da casa para não reinventar
  pseudonimização/consentimento/orçamento.
