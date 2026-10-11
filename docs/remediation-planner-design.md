# Remediation Planner — desenho do serviço de IA (Fase 4)

> **Status:** DESENHO, implementado em fatias no control-plane (`planner/`, `aiproviders/`), tudo **DARK**.
> A **decisão** já está no [ADR-0010](adr/0010-executor-remediacao-windows.md) §6;
> este documento detalha o **como**. Reusa a governança de IA já provada em outro produto da casa
> (contrato pago OpenRouter, UE, ZDR, pseudonimização, consentimento por finalidade, orçamento). O
> scanner roda por padrão só com **modelos gratuitos** (custo zero) — ver §11.
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
- **Caminho gratuito (padrão do scanner, `AI_FREE_MODELS_ONLY=true`):** só modelos **gratuitos** do
  OpenRouter/UnoRouter (custo zero). Modelo gratuito **não garante ZDR** — o provedor grátis pode
  registrar/treinar com o prompt —, então habilitar exige a **ciência explícita da política de dados**
  (`data_policy_ack`, com quem/quando gravados pelo servidor). Régua para habilitar um provedor:
  `(UE && ZDR) || (modelo gratuito && ciência)`. Detalhes no §11.
- **Orçamento mensal** (~US$50) com corte: acima do teto, o planner **desliga** (não degrada silenciosamente).
  Chamada a modelo gratuito custa 0 (não consome o teto).
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
| Provedor responde 429/5xx, timeout ou erro de rede | Tenta o próximo provedor da lista (§11); outro 4xx é erro do pedido e para. Todos falhando → sem rascunho. |
| Provedor recusa `response_format` json_schema (400 citando o formato) | Re-tenta UMA vez com `json_object` e, se de novo, sem `response_format` (§11); a saída continua tendo de passar no `parseDraft`. |
| Modelo não gratuito com `AI_FREE_MODELS_ONLY=true` | Recusado antes de qualquer rede (403 na rota do planner); sem rascunho. |
| Saída não valida no json_schema | Rascunho descartado; sem rascunho (nunca texto livre não-estruturado). |

## 9. LGPD

O canal de remediação já é registrado em [data-inventory](data-inventory.md) (sem dado pessoal). O planner
**estreita** ainda mais: allowlist técnica + pseudonimização + ZDR + UE + consentimento. Nenhum dado
pessoal, nenhum inventário cru, nenhuma identidade real do host deixa a nuvem rumo ao provedor.

No **caminho gratuito** (§11) não há ZDR nem garantia de região: o provedor pode registrar e usar o
prompt. O que sai continua sendo **só** o allowlist técnico **pseudonimizado**, e só com consentimento
(`AI_PLANNER_CONSENT`, default off) e a ciência do operador registrada no provedor (`data_policy_ack`).
Registrado em [data-inventory](data-inventory.md) (seção da IA de planejamento).

## 10. Rollout

- **Pré-requisito:** Fase 3 (executor + canário em LAB) estável; sem ela não há o que planejar aplicar.
- **Dark primeiro:** serviço implantado desligado; ligado por tenant só após consentimento.
- **Entra entre** o achado atestado e o `PENDING_APPROVAL`, como produtor de rascunho; a UI `/remediation`
  (Fase 4) mostra o rascunho ao lado do "aprovar por ação".
- Reusa o cliente/governança de IA já provado em outro produto da casa para não reinventar
  pseudonimização/consentimento/orçamento.

## 11. Modelos gratuitos (OpenRouter/UnoRouter) — `AI_FREE_MODELS_ONLY`

> Implementado no control-plane (`aiproviders/`, `planner/`) e **DARK** como o resto:
> `AI_CONFIG_ENABLED`, `AI_PLANNER_ENABLED` e `AI_PLANNER_CONSENT` seguem com default desligado.

**Regra.** Modelo gratuito ⇔ id termina em `:free` (com algo antes do sufixo) **ou** é o roteador
`openrouter/free` num provedor do tipo `openrouter`. Com `AI_FREE_MODELS_ONLY=true` (default), o
registro só aceita os tipos `openrouter` e `unorouter` e só modelo gratuito — mesmo para guardar
desabilitado (fora disso → HTTP 422 com mensagem em pt-BR) — e o planner **recusa** chamar modelo não
gratuito antes de qualquer rede (defesa em profundidade, caso um registro pago antigo siga habilitado).

**Presets.** Com `AI_CONFIG_ENABLED=true`, o boot garante `openrouter-free` ("OpenRouter — modelos
gratuitos", modelo `openrouter/free`) e `unorouter-free` ("UnoRouter — modelos gratuitos", modelo
`deepseek-v4-flash:free`), na base padrão do tipo, **desabilitados e sem chave**. Só cria o id que não
existe — nunca sobrescreve a edição do operador (um preset apagado volta no boot seguinte,
desabilitado). Pronto para uso = colar a chave + marcar a ciência + habilitar.

**Governança / privacidade.** Os provedores gratuitos **não garantem ZDR**: podem registrar e usar os
prompts, inclusive para treino. Por isso:
- habilitar exige `(UE && ZDR) || (modelo gratuito && data_policy_ack)`. A ciência guarda
  `data_policy_ack_by`/`data_policy_ack_at`, preenchidos pelo **servidor** a partir do operador da
  requisição (nunca do corpo). Retirar a ciência apaga o registro; editar mantendo-a não reescreve
  quem/quando.
- o que sai continua sendo **só** o allowlist pseudonimizado do §3/§5 (`host-1`, `agent-1`…; tenant e
  IP não entram como campo e, se aparecerem no título/evidência, viram pseudônimo), e **nada** sai sem
  `AI_PLANNER_CONSENT=true` (default off).

**Lista viva de modelos.** `GET /ai/providers/{id}/models` (sessão: portão gsad do nginx + marca do
`sessiongate`) e `GET /api/v1/ai/providers/{id}/models` (bearer) consultam `<base_url>/models` no
servidor, com a chave guardada se houver (o OpenRouter lista sem chave; sem chave no UnoRouter → 409
"cole a chave para listar os modelos", sem ir à rede). Timeout de 10 s, corpo ≤ 8 MB, redirect não é
seguido, cache de 10 min por provedor (invalidado ao trocar chave ou endpoint; erro não fica em cache).
Devolve só os gratuitos, primeiro os que declaram `structured_outputs`. Erro do provedor → 502 com
mensagem curta, sem repassar o corpo dele (que pode ecoar a chave). `GET /ai/policy` e
`GET /api/v1/ai/policy` informam a regra e os presets para a UI.

**Planner.**
- `AI_PLANNER_PROVIDER_ID` aceita lista separada por vírgula (ordem = prioridade). Vazio = todos os
  habilitados, `openrouter-free` antes de `unorouter-free` e o resto por nome. Em 429, 5xx, timeout ou
  erro de rede tenta o próximo; outro 4xx é erro do pedido e para.
- Formato: pede `response_format` json_schema; se o provedor responder 400 citando
  response_format/json_schema/structured, re-tenta UMA vez com `{"type":"json_object"}` e, se de novo,
  sem `response_format`. Nesses dois casos o schema vai no prompt de **sistema** (nunca como prefill).
  Em todos os casos a saída só vale se passar no `parseDraft` — nada de afrouxar a validação.
- Orçamento: chamada a modelo gratuito custa 0 — não consome o teto nem é barrada por ele.
- Regras Claude 5 em todas as tentativas: sem `temperature`, sem prefill.
