# Glossário da UI (GSA) — inglês → pt-BR → es

> Vale para os catálogos `public/locales/gsa-pt_BR.json` e `gsa-es.json` que o
> `patches/gsa-v27.4.1.patch` controla e para toda string nova das telas da
> Suricatoos. A chave é sempre o texto em **inglês** (padrão do GSA); pt-BR e es
> são os valores. O CI (`gsa-pr-build`, passo "Chaves das telas da Suricatoos")
> falha se uma chave das telas da Suricatoos faltar em pt_BR ou es, tiver valor
> vazio ou não estiver em inglês, e se um catálogo guardar chave órfã.

## Idioma padrão

- **pt-BR** é o idioma da UI quando o usuário não escolheu um e o navegador não
  pede um idioma com catálogo. O navegador é mapeado para o catálogo que o
  atende: `pt`, `pt-BR`, `pt-PT` → pt_BR; `es-*` → es; `en-*` → en.
- A escolha explícita do usuário (configurações ou seletor de idioma) continua
  valendo; o idioma detectado ao abrir a página não vira configuração salva.
- Chave sem tradução cai no **inglês** (o texto da chave), nunca no padrão.
- A primeira pintura espera o catálogo do idioma detectado (no máximo 2 s) e o
  `<html lang>` acompanha o idioma da UI (`pt-BR`, `es`, `en`).

## Termos

| Inglês (chave) | pt-BR | es | Observação |
|---|---|---|---|
| Result, Finding | Achado | Hallazgo | o resultado do GVM é um achado. Exceção: "Results per page" (linhas por página de qualquer lista) segue "Resultados por página"/"Resultados por página", e a expressão "as a result" segue "como resultado" |
| Scan (substantivo) | Varredura | Escaneo | verbo: varrer / escanear ("Scan now" → "Varrer agora" / "Escanear ahora") |
| Scan Config | Configuração de varredura | Configuración de escaneo | |
| Scanner | Scanner | Escáner | |
| Task | Tarefa | Tarea | |
| Target | Alvo | Objetivo | |
| Schedule | Agendamento | Programación | |
| Report | Relatório | Informe | |
| Report Format | Formato de relatório | Formato de informe | |
| Override | Exceção | Excepción | feminino: "nova exceção", "exceções habilitadas". O verbo "override" (sobrepor um padrão) segue "Sobrepor"/"Sobrescribir" |
| Note | Nota | Nota | |
| Alert | Alerta | Alerta | |
| Asset | Ativo | Activo | |
| Port List | Lista de portas | Lista de puertos | |
| Credential | Credencial | Credencial | |
| Filter | Filtro | Filtro | |
| Tag | Tag | Etiqueta | |
| Permission | Permissão | Permiso | |
| Role | Papel | Rol | |
| Group / User | Grupo / Usuário | Grupo / Usuario | |
| Dashboard | Painel | Panel | |
| Trashcan | Lixeira | Papelera | |
| Audit / Policy | Auditoria / Política | Auditoría / Política | |
| Compliance | Conformidade | Cumplimiento | |
| Severity | Severidade | Severidad | classes: Critical/High/Medium/Low/Log → Crítica/Alta/Média/Baixa/Log (feminino, concorda com "severidade") e Crítica/Alta/Media/Baja/Registro |
| Vulnerability | Vulnerabilidade | Vulnerabilidad | |
| Operating System | Sistema operacional | Sistema operativo | |
| Remediation | Remediação | Remediación | |
| Agent / Endpoint agent | Agente / Agente de endpoint | Agente / Agente de endpoint | |
| Activate Agent | Ativar agente | Activar agente | |
| Deployment token | Token de implantação | Token de despliegue | |
| Single-use token | Token de uso único | Token de un solo uso | |
| Check-in (do agente) | check-in | check-in | |
| Online / Offline | Online / Offline | En línea / Fuera de línea | |
| Refresh | Atualizar | Actualizar | |
| Feed | feed | feed | substantivo comum no meio da frase: "Status do feed", "Atualização do feed" |
| AI provider / Acknowledgement | Provedor de IA / Ciência | Proveedor de IA / Aceptación | |

**Mantidos como estão (termos técnicos consagrados e nomes):** CVE, CVSS, QoD,
NVT, CPE, OVAL, CERT-Bund, DFN-CERT, IP, TLS, SSH, SMB, GMP, LLM, ZDR, host,
tenant, ticket, log, endpoint, prompt, preset, Docker, Linux, macOS, Windows,
PowerShell. "Port" é traduzido como palavra comum: porta / puerto; "EU" (União
Europeia) é UE nos dois idiomas.

## Regras de escrita

- **Frase inteira com interpolação**, não fragmentos concatenados: a ordem das
  palavras muda entre idiomas. Fragmento só quando o layout exige (ex.: parte
  em negrito), e então cada fragmento é uma chave.
- **Texto livre interpolado vai em `{{- x}}`** (datas, hosts, nomes, mensagens
  do servidor): `{{x}}` escapa HTML e uma data `11/10/2026` apareceria como
  `11&#x2F;10&#x2F;2026`. `{{x}}` só para números.
- Contagem: o padrão do GSA, `(s)` (`{{count}} relatório(s)`), com o número
  passado como texto.
- Caixa: frase (sentence case) nas strings novas — "Agentes de endpoint",
  "Ativar agente".
- Acentuação completa em pt-BR e es (o CI não pega acento faltando: revisar).

## "Greenbone" × "Suricatoos"

- **Suricatoos** só em nome de produto nas strings visíveis que o patch
  controla (ex.: título, telas da Suricatoos, "Suricatoos Vulnerability
  Manager"). O nome de produto é o mesmo nos três idiomas: quando a string do
  upstream nomeia o produto (ex.: o erro de login "The Suricatoos Vulnerability
  Manager service is not responding…"), muda a chave em inglês e os valores
  pt_BR/es junto.
- **"Greenbone Sensor" fica "Greenbone Sensor"** em todos os idiomas: é o tipo de
  scanner do upstream (gvmd), não o sensor da Suricatoos (ADR-0007), e trocar o
  nome confundiria os dois.
- **Greenbone fica** em licença, copyright, atribuição, "sobre"/créditos, avisos
  legais, na origem de dados que vêm do feed da Greenbone (ex.: a origem de
  severidade "Greenbone", o formato "Greenbone Compliance Report"), na licença e
  no suporte Greenbone Enterprise, em URLs da Greenbone e em todo código e
  comentário do upstream (AGPL: a atribuição é obrigatória).

## Datas

- Data/hora absoluta: os formatadores do próprio GSA
  (`web/utils/user-setting-time-date-formatters`), que usam o fuso e o formato
  de data/hora do usuário — nas telas da Suricatoos, por
  `web/utils/suricatoosDate` (`formatApiDate`). Data sem fuso (ex.: `last_run`
  do feed-updater) é formatada sem conversão de fuso; valor que não é data
  aparece como veio, nunca "Invalid Date".
- Tempo relativo ("há 5 minutos"): o dayjs do GSA (`formatApiRelativeTime`,
  `fromNow()`).
- O locale do dayjs acompanha o idioma da UI desde a primeira detecção
  (`pt_BR` → `pt-br`, `es` → `es`, `en` → `en`).
