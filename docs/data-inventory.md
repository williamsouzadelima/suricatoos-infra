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
> planejamento (Fase 4) recebe dado **pseudonimizado** e **nunca decide/aprova** (ADR-0010).

## Canal de gestão da frota (ADR-0011)

> Canal **nó↔hub** do commandcenter (console central da frota), separado da coleta do agente e do canal de
> remediação. Nasce **DARK** (`FLEET_ENABLED=false`, profile `fleet`): só existe dado aqui depois que o
> operador do nó faz o enroll. Toda conexão parte do nó (HTTPS de saída + mTLS); o hub nunca alcança o nó.
> Atualizar em conjunto com `schema/fleet-*.schema.json` — os schemas fecham os campos
> (`additionalProperties: false`), então um dado novo exige mudar o schema **e** esta seção.

| Dado | Campo (schema) | Direção | Finalidade | Sensibilidade |
|---|---|---|---|---|
| Identidade do nó (`node_id`, `node_kind`, CSR, `schema_versions`; certificado `CN=<node_id> O=<org> OU=fleet-node`, CA da frota, chave pública de comando) | `fleet-enroll.schema.json` | nó→hub (enroll/renew); hub→nó (certificado e chaves públicas) | autenticar o nó (mTLS) e fixar a chave que assina comandos | baixa (identificador técnico) |
| Token de enroll da frota (`ft_…`) | `fleet-enroll.schema.json#/$defs/enroll_request` (`token`) | nó→hub, uma vez | autorizar a entrada do nó | alta enquanto válido (segredo de uso único; descartado após o enroll, nunca logado) |
| Heartbeat (versão do conector, versões do contrato anunciadas, piso de replay, hashes de estado, contadores de fila; o corpo do `426` traz só as versões do hub) | `fleet-heartbeat.schema.json` | nó→hub (resposta hub→nó) | vivacidade, sincronização e negociação de versão | baixa |
| Estado `node` (versões, feeds e idade, saúde, capacidades, política local, piso de replay) | `fleet-state.schema.json#/$defs/data_node` | nó→hub | operar a frota | baixa |
| Estado `tasks`, `schedules`, `reports` (ids, nomes, status, agendas, contagens por severidade) | `fleet-state.schema.json#/$defs/data_tasks`, `data_schedules`, `data_reports` | nó→hub | gerenciar varreduras | baixa (metadado operacional; **sem achados**) |
| Estado `targets` e `scope` (entradas IP/CIDR literais dos alvos, CIDRs autorizados por tenant) | `fleet-state.schema.json#/$defs/data_targets`, `data_scope` | nó→hub | gerenciar alvos dentro do escopo | média (topologia da rede do cliente) |
| Estado `agents` (agent_id, tenant, SO/arch/versão do agente, último contato, online) | `fleet-state.schema.json#/$defs/data_agents` | nó→hub | operar agentes | **média/alta: o `agent_id` é, por padrão, o hostname** e pode conter nome de pessoa; também sai em `remediation`, em `agent.*` e em `remediation.pending_approval`. Base legal: execução do serviço de segurança contratado; recomenda-se id não pessoal no enroll do agente |
| Estado `tokens`, `sensors`, `scan_requests`, `remediation` (ids, tenant, estados, contagens) | `fleet-state.schema.json#/$defs/data_tokens`, `data_sensors`, `data_scan_requests`, `data_remediation` | nó→hub | operar enroll, sensores e fila de varredura; acompanhar remediação (só leitura) | média: o `remediation` leva o `agent_id`, que por padrão é o hostname (ver a linha `agents`); sem segredo, sem alvos, sem payload de remediação |
| Estado `audit_tail` (caudas verbatim dos dois fluxos da auditoria local: `exec` e `reject`) | `fleet-state.schema.json#/$defs/data_audit_tail` | nó→hub | testemunha das cadeias de auditoria | média (contém `issued_by`, ids de objeto, hosts IP/CIDR dos alvos e os parâmetros dos exports — nunca segredo) |
| Eventos (status de tarefa, report concluído com contagens, agente online/offline, feed, remediação pendente, rejeição por política) | `fleet-event.schema.json` | nó→hub | atividade da frota | média: `agent.*` e `remediation.pending_approval` levam o `agent_id`, por padrão o hostname |
| Comando assinado (tipo, tenant, payload, `issued_by`, janela, nonce, assinatura) | `fleet-command.schema.json` | hub→nó | executar UMA ação do catálogo | baixa/média (`issued_by` identifica o operador do hub) |
| Ack e resultado (decisão e motivo, status, ids, valores anteriores dos campos alterados, contagens) | `fleet-result.schema.json` | nó→hub | estado do comando e rollback manual | média (`before.hosts` traz IPs de clientes) |
| Resumo de report (`report.summary`: só contagens — por severidade, por faixa de QoD, nº de hosts e por IP; sem NVT, OID, nome, CVE ou porta; filtro montado pelo nó) | `fleet-result.schema.json#/$defs/output_report_summary` | nó→hub, **sob comando**, orçado | priorização | média (revela quais IPs têm quantas vulnerabilidades por severidade) |
| Relatório (`report.export`: edição `technical`, `client` ou `executive`; completo, ou delta quando há `delta_report_id`) | artefato gzip + `fleet-result.schema.json#/$defs/artifact` | nó→hub, **só sob comando explícito** | entregar o relatório | **alta** (vulnerabilidades detalhadas por host do cliente; a edição `executive` é sumário, mas segue sob a mesma regra) |
| Segredo de token do scanner (`enroll_token.create`, só `agent-endpoint`) | `fleet-result.schema.json#/$defs/output_enroll_token_create` (`token`) | nó→hub, uma vez, `contains_secret: true` | instalar um agente de endpoint | **alta** (segredo) |

**O que NÃO sai do nó por este canal:**

- Achados detalhados (descrição, evidência, solução, porta por host) — exceto por `report.export` explícito.
- Entradas não-literais (hostnames) de alvos — só contadas. **Atenção:** não existe campo de hostname de agente,
  mas o próprio `agent_id` é, por padrão, o hostname (ver a linha `agents`).
- `comment` de objetos GVM (texto livre do operador local).
- Inventário de pacotes e postura CIS dos agentes; payload, assinatura e resultado técnico (before/after) de
  remediação.
- Usuários e senhas gvmd, admin-bearer, bearer da frota, chaves privadas (do nó, das CAs, de assinatura) e
  segredos de token — exceto o segredo de `enroll_token.create`, uma vez e marcado.
- Conteúdo de feeds.

> **`report.export` é o ÚNICO caminho de achado detalhado:** exige comando assinado, permitido pela política
> **local** (o operador do nó pode removê-lo), conta no orçamento local de comandos sensíveis (30/h, somado
> com `report.summary` e os opt-in) e no global de aceitos (120/h), e fica na auditoria local. O
> `report.summary` não carrega achado: só contagens, com filtro que o hub não escolhe.
>
> **Artefatos:** gzip, ≤ 64 MiB comprimido e ≤ 1 GiB descomprimido (o hub descomprime em streaming com teto
> próprio), com sha256 do gzip e do original. O nó grava o export num arquivo temporário
> `0600` no `FLEET_STATE_DIR` e o apaga quando o hub aceita o upload (ou quando o comando termina em falha); a
> retenção no hub é política do controlador (questão aberta do ADR-0011).
>
> **Segredo de `enroll_token.create`:** só em memória no nó — nunca em disco, log ou auditoria. O hub não o
> loga, cifra em repouso e o mostra uma vez. Reinício antes da entrega ⇒ o nó revoga localmente só o token (os
> certificados já emitidos com ele não caem) e reporta `secret_lost`.
>
> **Texto livre (normativo):** os campos de texto livre que saem do nó são só **nomes** de objeto GVM (tarefa,
> target, agenda), escritos por um operador — o local, na GSA, ou o do hub, num comando de criação — e as
> mensagens curtas que o próprio conector gera (`detail`, `error.message`). O nó **nunca** insere dado de achado
> (OID, nome de NVT, CVE, porta, evidência) em texto livre; `comment` de objeto não sai.
>
> **`issued_by`:** é **obrigatoriamente** um identificador pseudônimo do operador do hub — o schema recusa `@` e
> espaço; o hub guarda o mapeamento para a pessoa. Um e-mail aqui seria dado pessoal replicado na auditoria de
> cada nó.
>
> **Auditoria local:** dois fluxos append-only encadeados por hash (`FLEET_STATE_DIR/audit-exec.jsonl` com o
> que foi aceito e executado; `audit-reject.jsonl` com rejeições, adiamentos e contagens de envelopes não
> autenticados), cada um com `seq` e rotação próprios (32 MiB × 8 e × 4). As linhas guardam o "quê" de forma
> limitada (ids de objeto, até 64 hosts, parâmetros do export, sha256 e tamanho do artefato) e **nunca segredo**.
> Visíveis ao operador local; as caudas (≤ 200 linhas de cada fluxo) vão ao hub como testemunha.
>
> **Transporte:** HTTPS de saída + mTLS; no canário, hub alcançado só por rede privada (tailnet), fora da
> internet. Os papéis LGPD (controlador/operador) entre o cliente e quem opera o hub seguem a base legal abaixo,
> fixados por contrato/engajamento.

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
