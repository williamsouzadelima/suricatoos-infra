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
- ❌ **Não recebe a identidade real do host como campo** — host, agente, tenant e IP do achado vão
  pseudonimizados; título e evidência, porém, seguem como vieram e podem conter nomes de conta ou de
  host (ver §5: fechar isso antes de ligar `AI_PLANNER_CONSENT=true`).
- ❌ **Não é bloqueante** — se o planner estiver desligado, fora do orçamento ou indisponível, o fluxo
  segue com o humano redigindo manualmente (§8).

## 2. Posição no fluxo

```
Finding ATESTADO (severity/CVE da fonte, evidência)
   │
   ├──► remediation-planner (IA)  ── rascunho {explicação, plano, prioridade, rollback, ressalvas}
   │         (sem chaves; identificadores do achado pseudonimizados; saída = texto consultivo)
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
- Um **id opaco do host** (pseudônimo por pedido) para agrupar os passos do mesmo host — o hostname/IP
  **do achado** nunca vai como campo; título e evidência, porém, seguem como vieram (§5).

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
  (`data_policy_ack`; o servidor registra QUANDO; QUEM fica pendente da propagação da identidade do
  gsad — atrás do nginx o valor é o marcador `operator`). Régua para habilitar um provedor — e para o
  planner usá-lo, conferida de novo na hora do uso: com a regra ligada, modelo gratuito no endpoint
  oficial **com** ciência, sempre (UE/ZDR autodeclarados não a substituem); com a regra desligada,
  `(UE && ZDR) || (modelo gratuito no endpoint oficial && ciência)`. Detalhes no §11.
- **Orçamento mensal** (~US$50) com corte: acima do teto, o planner **desliga** (não degrada silenciosamente).
  Chamada a modelo gratuito custa 0 (não consome o teto).
- **Consentimento por finalidade, por tenant** (default **off**; só admin+MFA liga). Sem consentimento,
  nenhum dado do tenant é enviado.
- **Regras Claude 5:** sem `temperature`, sem prefill, resposta via `output_config` json_schema.
- Serviço **nasce DARK** (flag global desligada), como todo o resto da remediação.

## 5. Pseudonimização e minimização

Antes de qualquer chamada ao provedor, um **mapa server-side** (só em memória, por pedido) troca os
identificadores **do achado** por referências opacas: host, agente, tenant e IP do pedido viram
`host-1`, `agent-1`, `tenant-1`, `ip-1` — inclusive quando aparecem no título ou na evidência — e o
mapa **não** é enviado. Host e agente vão como campo; tenant e IP, não. Allowlist explícita de campos
(§3): qualquer campo fora dela é descartado por omissão, não por bloqueio (fail-closed de dado).

**Limite atual (o que o código faz hoje, `planner/pseudonym.go`):** só esses 4 identificadores do
pedido são trocados. **Título e evidência seguem como vieram** e podem conter nomes de conta ou de host
— por exemplo, na regra CIS "renomear a conta de administrador" a evidência é o próprio nome da conta;
outro hostname, IP ou domínio citado no texto também vai como está. A redação de segredo em valor de
config (ex.: string de conexão) é desenho, ainda não implementado. **Fechar o pseudonimizador
(conta/usuário, outros hosts/IPs/domínios, segredos no texto) é pré-requisito para ligar
`AI_PLANNER_CONSENT=true`.**

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
| Provedor responde qualquer não-2xx (depois do fallback de formato dele), timeout ou erro de rede | Tenta o próximo provedor da lista (§11). Todos falhando → sem rascunho; o erro lista cada tentativa (status + trecho curto e saneado do corpo, nunca a chave). |
| Provedor recusa `response_format` json_schema (400 citando o formato) | Re-tenta UMA vez com `json_object` e, se de novo, sem `response_format` (§11); a saída continua tendo de passar no `parseDraft`. |
| Modelo não gratuito com `AI_FREE_MODELS_ONLY=true` | Recusado antes de qualquer rede (403 na rota do planner); sem rascunho. |
| Provedor fora do endpoint oficial com `AI_FREE_MODELS_ONLY=true` (registro antigo) | Recusado antes de qualquer rede (403 se for o único); salvar o provedor de novo fixa a base oficial — sem chave nova, só se a base antiga já estava no host oficial do tipo; senão, cole a chave de novo. |
| Provedor habilitado mas fora da régua na hora do uso (ex.: sem a ciência depois de reverter para uma imagem anterior a ela) | Pulado antes de qualquer rede, com o motivo no log; o próximo é tentado (403 se nenhum serve). |
| Tempo total do rascunho esgotado (`AI_PLANNER_TIMEOUT`, default 5 min) | A tentativa em curso é cancelada e nenhuma outra começa; 504 em JSON; sem rascunho. Atrás do nginx, a location própria do planner lê por 360 s (§11). |
| Saída não valida no json_schema | Rascunho descartado; sem rascunho (nunca texto livre não-estruturado). |

## 9. LGPD

O canal de remediação já é registrado em [data-inventory](data-inventory.md) (sem dado pessoal). O planner
**estreita**: allowlist técnica + pseudonimização dos identificadores do achado + consentimento (+ UE e
ZDR no caminho pago). Inventário cru não sai. **Hoje** título e evidência seguem como vieram e podem
conter nomes de conta ou de host (§5) — fechar o pseudonimizador antes de `AI_PLANNER_CONSENT=true`.

No **caminho gratuito** (§11) não há ZDR nem garantia de região: o provedor pode registrar e usar o
prompt. O que sai é **só** o allowlist técnico (host, agente, tenant e IP do achado pseudonimizados;
título e evidência como vieram), e só com consentimento (`AI_PLANNER_CONSENT`, default off) e a ciência
do operador registrada no provedor (`data_policy_ack`). Registrado em [data-inventory](data-inventory.md)
(seção da IA de planejamento).

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
`openrouter/free` num provedor do tipo `openrouter` — **e** o provedor está no endpoint **oficial** do
roteador: fora dele (gateway genérico, endpoint próprio) `:free` não quer dizer custo zero e o modelo
conta como pago, na governança e no orçamento, com a regra ligada ou não. Com
`AI_FREE_MODELS_ONLY=true` (default), o registro só aceita os tipos `openrouter` e `unorouter` e só
modelo gratuito — mesmo para guardar desabilitado (fora disso → HTTP 422 com mensagem em pt-BR) — e o
planner **recusa** chamar modelo não gratuito antes de qualquer rede (defesa em profundidade, caso um
registro pago antigo siga habilitado).

**Endpoint fixo.** Com a regra ligada, a `base_url` é fixada no endpoint **oficial** do tipo
(`https://openrouter.ai/api/v1`, `https://api.unorouter.com/v1`): a enviada no upsert é **ignorada**
e a resposta mostra a efetiva. Assim, quem pode salvar um provedor não consegue repontar um provedor que
já tem chave para um host seu e fazer o servidor mandar a chave para lá. Registro antigo com outra base
(salvo antes da regra ou com ela desligada) é recusado pelo planner antes de qualquer rede e pela lista de
modelos (422) até ser salvo de novo — o que fixa a base oficial (sem chave nova, só se a base antiga já
estava no host oficial do tipo; senão, cole a chave de novo). Com a regra desligada, endpoint próprio
continua aceito no cadastro e no planner (comportamento anterior).

**A chave é do destino para o qual foi colada.** A chave guardada (e a ciência) valem para o par
tipo + endpoint. Num update **sem** `api_key` nova, trocar o tipo — ou mudar o endpoint efetivo para
qualquer coisa que não seja o oficial do **mesmo** tipo — dá **422** ("cole a chave de novo ao trocar o
tipo/endpoint") e nada muda no registro, com a regra ligada ou desligada. A única exceção é salvar de
novo, no **mesmo** tipo, um registro cuja base antiga já estava no **host** oficial desse tipo (mesmo
host e porta; ex.: outro caminho em `openrouter.ai`): o servidor só fixa o caminho oficial e a chave
fica. Vindo de qualquer outro host — um proxy, o host do outro roteador (ex.: registro `unorouter` em
`openrouter.ai` com a chave do OpenRouter) — é 422: cole a chave de novo. Com `api_key` nova, a troca
passa, a chave é substituída e a ciência recomeça (outro destinatário, outra ciência): o provedor só
fica habilitado se o mesmo pedido trouxer a ciência.

**Presets.** Com `AI_CONFIG_ENABLED=true`, o boot garante `openrouter-free` ("OpenRouter — modelos
gratuitos", modelo `openrouter/free`) e `unorouter-free` ("UnoRouter — modelos gratuitos", modelo
`deepseek-v4-flash:free`), na base padrão do tipo, **desabilitados e sem chave**. Só cria o id que não
existe — nunca sobrescreve a edição do operador (um preset apagado volta no boot seguinte,
desabilitado). Pronto para uso = colar a chave + marcar a ciência + habilitar.

**Governança / privacidade.** Os provedores gratuitos **não garantem ZDR**: podem registrar e usar os
prompts, inclusive para treino. Por isso:
- com a regra ligada, habilitar um modelo gratuito exige **sempre** a ciência (`data_policy_ack`) — as
  marcações autodeclaradas `eu_region`/`zdr` não a substituem, porque um endpoint `:free` de roteador
  não garante ZDR. Com a regra desligada, vale `(UE && ZDR) || (modelo gratuito no endpoint oficial &&
  data_policy_ack)`.
- a ciência é gravada pelo **servidor** (nunca a partir do corpo): o servidor registra **QUANDO**
  (`data_policy_ack_at`); **QUEM** fica pendente da propagação da identidade do gsad — atrás do nginx
  `data_policy_ack_by` é sempre o marcador `operator`, que a tela não mostra como nome. Retirar a
  ciência apaga o registro; editar mantendo-a não reescreve quem/quando; trocar o destino (tipo ou
  endpoint, com chave nova) recomeça a ciência.
- o que sai é o allowlist do §3/§5: host, agente, tenant e IP do achado são pseudonimizados; **título e
  evidência seguem como vieram e podem conter nomes de conta ou de host** (§5). **Nada** sai sem
  `AI_PLANNER_CONSENT=true` (default off) — e ligá-lo pede, antes, fechar o pseudonimizador.
- **Conta do OpenRouter:** confira em `openrouter.ai/settings/privacy` a configuração de privacidade
  para **modelos gratuitos**, coerente com a ciência. Para "colar a chave e funcionar", a conta precisa
  permitir, nos modelos gratuitos, os provedores que podem registrar/treinar com os prompts — que é o
  que a ciência registra. Se ela recusar, o OpenRouter pode não ter endpoint gratuito para o modelo
  (relatos citam o erro "No endpoints found matching your data policy") e o planner passa ao provedor
  seguinte. O planner não manda `provider.data_collection: "deny"`: com modelos `:free` isso tende a
  não deixar endpoint nenhum.

**Lista viva de modelos.** `GET /ai/providers/{id}/models` (sessão: portão gsad do nginx + marca do
`sessiongate`) e `GET /api/v1/ai/providers/{id}/models` (bearer) consultam no servidor **só** o
`/models` do endpoint **oficial** do tipo — com a regra ligada ou não: provedor com outra base (ou
gateway genérico) → 422 sem ir à rede, para a rota de sessão nunca levar a chave (nem um pedido do
servidor) a um host escolhido pela API. Usa a chave guardada se houver (o OpenRouter lista sem chave;
sem chave no UnoRouter → 409 "cole a chave para listar os modelos", sem ir à rede). Timeout de 10 s,
corpo ≤ 8 MB, redirect não é
seguido, cache de 10 min por provedor (invalidado ao trocar chave ou endpoint; erro não fica em cache).
Devolve só os gratuitos, primeiro os que declaram `structured_outputs`. Erro do provedor → 502 com
mensagem curta, sem repassar o corpo dele (que pode ecoar a chave). `GET /ai/policy` e
`GET /api/v1/ai/policy` informam a regra e os presets para a UI.

**Planner.**
- `AI_PLANNER_PROVIDER_ID` aceita lista separada por vírgula (ordem = prioridade). Vazio = com a regra
  ligada, **só os presets** (`openrouter-free`, depois `unorouter-free`) — os demais provedores são
  ignorados, como diz a tela; com a regra desligada, todos os habilitados, os presets primeiro e o resto
  por nome. Em **qualquer** resposta não-2xx (depois do fallback de formato do próprio provedor),
  timeout ou erro de rede tenta o próximo: um 4xx de um roteador (modelo fora do catálogo, política de
  dados da conta) não diz nada do outro. Todos falhando, o erro lista cada tentativa — status e um
  trecho curto e saneado do corpo, nunca a chave. Resposta 2xx sem conteúdo útil para.
- Régua na hora do uso: antes de qualquer rede, cada provedor passa de novo pela **mesma** régua do
  registro (habilitado e com chave; com a regra ligada, tipo do roteador, endpoint oficial, modelo
  gratuito e ciência; com ela desligada, UE + ZDR ou modelo gratuito no endpoint oficial com ciência).
  Quem falha é **pulado**, com o motivo no log (sem segredo). Ex.: reverter para uma imagem anterior à
  ciência apaga `data_policy_ack*` na primeira gravação; ao voltar, o preset segue habilitado, mas sem
  ciência — e o planner não o usa.
- Formato: pede `response_format` json_schema; se o provedor responder 400 citando
  response_format/json_schema/structured, re-tenta UMA vez com `{"type":"json_object"}` e, se de novo,
  sem `response_format`. Nesses dois casos o schema vai no prompt de **sistema** (nunca como prefill).
  Em todos os casos a saída só vale se passar no `parseDraft` — nada de afrouxar a validação.
- Orçamento: chamada a modelo gratuito custa 0 — não consome o teto nem é barrada por ele.
- Tempo total: um rascunho inteiro (todos os provedores e formatos) cabe em `AI_PLANNER_TIMEOUT`
  (default 5 min). Esgotado, a tentativa em curso é cancelada, nenhuma outra começa e a rota responde
  504. A rota do planner ganha prazo de escrita próprio (tempo total + 30 s), porque um modelo gratuito
  lento passa fácil do `WriteTimeout` geral do servidor (30 s), que não muda para as outras rotas.
- nginx: o `/agent/api/` lê do control-plane por só 30 s, então o planner tem location própria,
  `location = /agent/api/v1/remediation/plan` (`compose/nginx/default.conf`), cópia exata do
  `/agent/api/` com `proxy_read_timeout 360s` (o tempo total de 5 min + os 30 s do prazo de escrita).
  **Se `AI_PLANNER_TIMEOUT` subir acima de 330 s, o `proxy_read_timeout` dessa location tem de subir
  junto** — senão o nginx corta antes e o operador recebe o 504 em HTML do nginx, não o do planner.
  Confira também que o nginx do host (passthrough em modo stream) não corta uma conexão parada antes
  disso (o `proxy_timeout` padrão do stream é 10 min). O `standalone.conf` herda o
  `proxy_read_timeout 1h` do bloco `server`.
- Regras Claude 5 em todas as tentativas: sem `temperature`, sem prefill.
