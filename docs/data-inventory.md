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

## Dados que **NÃO** coletamos (proibido)

- Conteúdo de arquivos do usuário.
- Histórico de navegação, URLs, queries.
- Credenciais, chaves, tokens, senhas.
- Teclas digitadas, telemetria comportamental, screenshots.
- Dados pessoais (nome, e-mail, documentos) — exceto a identidade técnica do host (hostname/agent_id).

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
