# Suricatoos Agent — Inventário de Dados (LGPD)

> Documento de **minimização e finalidade**. Lista EXATAMENTE o que o agente coleta, o que
> **não** coleta, a finalidade e a base legal. Atualizar em conjunto com `schema/inventory.schema.json`.

## Princípio

Coletamos apenas o mínimo necessário para **correlação de vulnerabilidade baseada em pacote**
(modelo Notus). Nada de telemetria comportamental, conteúdo do usuário ou credenciais.

## Dados coletados

| Dado | Campo (schema) | Finalidade | Sensibilidade |
|---|---|---|---|
| Pacotes instalados (nome, versão, arch) | `packages[]` | correlação Notus | baixa (software, não pessoal) |
| SO / distro / release / arch / kernel | `os` | seleção de produto/advisory | baixa |
| Portas em escuta **locais** + serviços | `facts.listening_ports_local`, `facts.services` | contexto de exposição local | baixa |
| Identidade do agente (machine-id derivado) | `agent.agent_id` | rastrear o host enrolado | média (pseudônimo) |
| Versão do agente, hostname | `agent.agent_version`, `agent.hostname` | operação/suporte | baixa |
| Escopo (tenant/policy) | `agent.scope` | multi-tenant / segmentação | baixa |
| Build/UBR do Windows | `os.build`, `os.ubr` | nível exato de patch p/ correlação MSRC | baixa (estado técnico) |
| KBs instalados (Windows) | `facts.installed_kbs[]` | evidência de supersedência de update | baixa (estado técnico) |
| Updates faltantes (Windows) | `facts.missing_updates[]` | detecção de vulnerabilidade (fonte MSRC/WUA) | baixa (estado técnico) |
| Postura de gestão central | `facts.management` | evitar propor correção que GPO/MDM reverteria | baixa (flags de configuração) |
| Postura CIS L1 (registro/secedit/auditpol/serviço) | `facts.cis_state[]` | avaliação de hardening (ADR-0009) | baixa (config técnica; contas → SIDs well-known) |

> **Windows (ADR-0008/0009):** todos os campos acima são **estado técnico do SO**, não dado pessoal.
> A severidade/CVE dos `missing_updates` vem **verbatim da fonte autoritativa** (Windows Update
> Agent/MSRC); o agente nunca a julga. O coletor de postura CIS (`cis_state`) reporta **só o valor
> medido** (sem pass/fail e sem mapeamento de regra CIS — o servidor é dono do ruleset, ADR-0009), e
> as contas em *Privilege Rights* (`secedit`) são **redigidas para SIDs well-known** (`Administrators`,
> `Guests`, …): um SID específico do host vira `custom-sid` e um nome de conta vira `custom-account` —
> nenhum nome de usuário/SID arbitrário deixa a máquina.

## Dados que **NÃO** coletamos (proibido)

- Conteúdo de arquivos do usuário.
- Histórico de navegação, URLs, queries.
- Credenciais, chaves, tokens, senhas.
- Teclas digitadas, telemetria comportamental, screenshots.
- Dados pessoais (nome, e-mail, documentos) — exceto a identidade técnica do host (hostname/agent_id).

## Canal de remediação (ADR-0010)

> Fluxo **inverso** (nuvem→agente) mais o relatório de volta (agente→nuvem), separado da coleta acima.
> Nasce **DARK**: só existe dado aqui quando o recurso é ligado por tenant e um humano aprova o job.

| Dado | Campo (schema) | Direção | Finalidade | Sensibilidade |
|---|---|---|---|---|
| Job assinado (id/correlação/tenant/agent, janela, nonce, assinatura) | `remediation-job.schema.json` | nuvem→agente | aplicar UMA correção aprovada | baixa (metadado operacional) |
| Payload `package_patch` (engine, id do update, KB, versão) | `remediation-payload-package-patch.schema.json` | nuvem→agente | qual update instalar | baixa (estado técnico) |
| Payload `config_hardening` (nº da regra CIS, source, chave, valor) | `remediation-payload-config-hardening.schema.json` | nuvem→agente | qual setting aplicar | baixa (config técnica) |
| Resultado (status, detalhe, before/after técnico, rollback_token) | `remediation-result.schema.json` | agente→nuvem | atestar aplicação + permitir rollback | baixa (estado técnico) |

> **Nenhum dado pessoal** trafega no canal de remediação: o job carrega identificadores opacos
> (`job_id`/`nonce`) e o alvo técnico (KB/UpdateID/regra/chave); o resultado carrega **estado técnico
> do SO** (ex.: valor de registro antes/depois), nunca conteúdo de usuário ou identidade de conta. A
> redação de SID da coleta CIS (ADR-0009) continua valendo para o achado que origina o job. A IA de
> planejamento (Fase 4) recebe os identificadores do achado **pseudonimizados** (título e evidência
> como vieram — ver a seção abaixo) e **nunca decide/aprova** (ADR-0010).

## IA de planejamento (Fase 4) — envio a provedor de LLM

> Fluxo **nuvem→provedor de LLM** (OpenRouter/UnoRouter), só quando um operador pede um rascunho de
> plano de remediação. Nasce **DARK** (`AI_CONFIG_ENABLED`/`AI_PLANNER_ENABLED` desligados) e **nada é
> enviado** sem o consentimento por finalidade `AI_PLANNER_CONSENT` (default **off**). Desenho:
> [remediation-planner-design](remediation-planner-design.md).

| Dado | Origem | Direção | Finalidade | Sensibilidade |
|---|---|---|---|---|
| Fatos técnicos do achado atestado (tipo, título, severidade, CVEs, regra CIS, KB, evidência, SO) | achado atestado | nuvem→provedor de LLM | redigir rascunho de plano | baixa a média: estado técnico, mas título e evidência seguem como vieram e podem conter nomes de conta ou de host |
| Host e agente **pseudonimizados** (`host-1`, `agent-1`) | achado atestado | nuvem→provedor de LLM | agrupar passos por host | baixa (pseudônimo por pedido; o mapa fica só na memória do control-plane) |

> **Pseudonimizados:** host, agente, tenant e IP **do achado** (os do pedido) — inclusive quando
> aparecem no título ou na evidência; tenant e IP nem entram como campo. **Fora do envio:** inventário
> cru. **Não pseudonimizados (limite atual):** título e evidência seguem como vieram e podem conter
> nomes de conta ou de host (ex.: na regra CIS "renomear a conta de administrador" a evidência é o nome
> da conta); outro hostname, IP ou domínio citado no texto também vai como está. Fechar o
> pseudonimizador é pré-requisito para ligar `AI_PLANNER_CONSENT=true`.

> **Modelos gratuitos (padrão do scanner, `AI_FREE_MODELS_ONLY=true`):** os provedores gratuitos **não
> garantem ZDR nem região** — podem **registrar e usar os prompts, inclusive para treino**. Mitigações:
> (1) só sai o allowlist técnico acima, com os identificadores do achado pseudonimizados (título e
> evidência como vieram); (2) consentimento `AI_PLANNER_CONSENT` default **off**; (3) habilitar um
> provedor gratuito exige **sempre** a **ciência explícita** do operador (`data_policy_ack`) — UE/ZDR
> autodeclarados não a substituem — e o planner confere a régua de novo na hora do uso. O servidor
> registra **quando** (`data_policy_ack_at`); **quem** (`data_policy_ack_by`) fica pendente da
> propagação da identidade do gsad: atrás do nginx o valor é o marcador `operator`; (4) modelo pago só
> fora da regra de gratuitos e sob a régua UE + ZDR; (5) na conta do OpenRouter, a configuração de
> privacidade para modelos gratuitos (`openrouter.ai/settings/privacy`) deve ser coerente com a
> ciência: se recusar provedores que podem treinar com os prompts, o OpenRouter pode ficar sem endpoint
> gratuito para o modelo, e o planner passa ao provedor seguinte.

> **Chaves de API dos provedores:** cifradas em repouso (AES-256-GCM, KEK do host), write-only pela API
> (só os 4 últimos caracteres aparecem) e usadas só server-side, no envio ao próprio provedor. Com
> `AI_FREE_MODELS_ONLY=true` a `base_url` fica fixa no endpoint oficial do roteador; com a regra ligada
> ou não, trocar o tipo ou o endpoint de um provedor que tem chave exige colar a chave de novo (sem
> chave nova → 422 e nada muda). A única exceção é salvar de novo, no mesmo tipo, um registro cuja base
> antiga já estava no host oficial desse tipo (mesmo host e porta): o servidor só fixa o caminho
> oficial. Assim a chave guardada só vai ao host para o qual foi colada. A lista de modelos (rota de
> sessão) só consulta endpoints oficiais, com a regra ligada ou não.

## Base legal e finalidade

- **Finalidade única:** gestão de vulnerabilidade do parque (segurança da informação).
- **Base legal (LGPD Art. 7º):** legítimo interesse do controlador em proteger seus ativos
  e/ou execução de contrato de segurança — a fixar por engajamento/cliente.
- **Minimização (Art. 6º, III):** apenas os campos acima; nenhuma expansão sem revisão deste documento
  **e** do schema.

## Integridade e retenção

- Cada ciclo é hasheado na origem (`cycle_hash`) e o transporte é assinado (mTLS) — integridade e
  não-fabricação.
- Retenção definida pelo controlador; a fila offline do agente tem teto de disco + expurgo (Fase 1).
- Em repouso no plano de dados: política definida na Fase 2.

## Transparência no endpoint

- O serviço é detectável e identificável (marca Suricatoos) e **desinstalável de forma limpa**.
