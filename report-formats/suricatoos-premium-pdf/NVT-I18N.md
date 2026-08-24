# Glossário — tradução dos NVTs para pt-BR

Contrato de consistência: doze agentes traduzem lotes diferentes do mesmo
catálogo. Sem isso, "remote attacker" vira cinco coisas distintas no mesmo PDF.

## Termos fixos

| inglês | pt-BR |
|---|---|
| remote attacker | atacante remoto |
| attacker | atacante |
| vulnerability | vulnerabilidade |
| flaw | falha |
| finding | achado |
| host | host (não traduzir) |
| target | alvo |
| scan | varredura (verbo: varrer) |
| service | serviço |
| endpoint | endpoint (não traduzir) |
| issue | problema |
| disclosure | exposição (information disclosure = exposição de informação) |
| denial of service (DoS) | negação de serviço (DoS) |
| privilege escalation | elevação de privilégio |
| arbitrary code execution | execução de código arbitrário |
| buffer overflow | estouro de buffer |
| cross-site scripting | cross-site scripting (não traduzir; sigla XSS) |
| SQL injection | injeção de SQL |
| man-in-the-middle | man-in-the-middle (não traduzir) |
| cleartext / plaintext | texto claro |
| eavesdrop | interceptar |
| bypass | contornar (subst.: contorno) |
| mitigation | mitigação |
| workaround | contorno temporário |
| vendor fix | correção do fornecedor |
| patch (subst.) | correção |
| update (verbo) | atualizar |
| upgrade (verbo) | atualizar |
| deprecated | obsoleto |
| end of life (EOL) | fim de vida (EOL) |
| enabled / disabled | habilitado / desabilitado |
| supported | suportado |
| affected | afetado |
| unauthenticated | não autenticado |
| credentials | credenciais |
| default (adj.) | padrão |
| request / response | requisição / resposta |
| header | cabeçalho |
| payload | payload (não traduzir) |
| cipher suite | conjunto de cifras |
| certificate | certificado |
| key exchange | troca de chaves |
| timestamp | timestamp (não traduzir) |
| banner | banner (não traduzir) |
| listening | escutando |
| open port | porta aberta |

## O que NÃO se traduz, nunca

- Identificadores: CVE-…, CWE-…, USN-…, DSA-…, RHSA-…, OID, QoD.
- Vetores CVSS (`CVSS:3.1/AV:N/…`) e números de versão.
- Nomes de produto, protocolo e RFC: OpenSSH, Apache, TLSv1.2, HTTP, SMB, LDAP.
- Nomes de arquivo, caminhos, diretivas de configuração, comandos, código.
- URLs.
- Saída literal de ferramenta (o campo `detection` costuma ser isso).

## Registro

Português do Brasil, **impessoal e direto**, como laudo técnico. Evite "você".
Prefira "permite que um atacante execute" a "poderia permitir que um atacante
pudesse executar". Mantenha o comprimento próximo do original — o texto vai para
dentro de cards com largura fixa.

Não invente conteúdo: se o original é vago, a tradução é vaga. Não acrescente
recomendação que o original não faz.

---

## Como o catálogo entra no relatório

`nvt-i18n-<lang>.xml`, indexado pelo OID do NVT. O `latex.xsl` carrega com
`document()` e consulta em `nvt-i18n` no template `nvt-i18n`; OID ausente cai
para o texto original do feed, e o card ganha o chip **ORIGINAL DO FORNECEDOR** —
mas só quando o catálogo daquele idioma existe e é o NVT específico que falta.
Idioma sem catálogo (hoje: `es`) usa um XML vazio, para o `document()` resolver
sem aviso e o relatório sair inteiro no idioma do fornecedor, sem carimbar todos
os cards.

**Não traduzimos `detection`** (RESULTADO DA DETECÇÃO): é saída literal da
ferramenta. É a maior parte do inglês que sobra no PDF, e sobra de propósito.

## Espanhol

Catálogo próprio (`nvt-i18n-es.xml`), 666/666 OIDs, glossário em `NVT-I18N-ES.md`.
Resultado medido: **36% → 15%** de linhas em inglês. Mesmos gates: zero
divergência de identificador, tortura de 666 entradas limpa (123 páginas).

## Dívida conhecida

Sete termos de alta recorrência não têm entrada acima e convergiram por acaso,
não por contrato: `is prone to` (→ "está sujeito a"), `sanitize` (→ "sanitizar"),
`Active Check` (→ "Verificação ativa"), `HTTP based detection of X`
(→ "Detecção do X (HTTP)"), `scanner` (mantido), `directory traversal`
(→ "travessia de diretório") e o desdobramento de `disclosure`
(*information disclosure* = exposição de informação; *disclosure* de
vulnerabilidade = divulgação). **Adicione-os antes de estender o catálogo**,
senão os lotes divergem de novo.

67 títulos usam ordem de produto diferente do original ("Plugin Pretty Link do
WordPress: …" contra a ordem do original). Não perde identificador; é
inconsistência visual entre famílias de título. Correção é passe manual.

## Como regerar

O catálogo cobre os NVTs que já produziram achado (`SELECT DISTINCT nvt FROM
results`), não o feed inteiro — são ~670 contra 185 mil. Extraia de `nvts`
(name, summary, insight, impact, affected, solution), traduza, e **desescape as
quebras de linha**: a coluna do banco guarda `\n` como dois caracteres, enquanto
o XML do relatório entrega quebra real; sem isso o `\n` sai impresso no PDF.

Antes de publicar, confira por script que nenhum identificador mudou entre
origem e tradução — CVE, CWE, USN/DSA/RHSA, vetores CVSS, URLs e números de
versão. Um CVE trocado num relatório de cliente é pior que o inglês.

## Teste de tortura (obrigatório ao estender o catálogo)

Um relatório real toca ~100 dos ~670 NVTs. Compilar um relatório de verdade prova
pouco: um caractere não escapado nas outras entradas só apareceria quando um
cliente batesse nela.

`tools/build-torture-fixture.py <lang>` monta um relatório sintético com **um
achado por OID do catálogo**. Compilou limpo = toda a tradução está provada segura
no LaTeX. Resultado da primeira rodada pt-BR: 666 entradas, 184 páginas, **0 erro,
0 `Font shape undefined`, 0 overfull hbox, 0 fonte Type 3, 0 macro vazada**.

Gate obrigatório, e não é opcional: `pdflatex` em `batchmode` **produz PDF mesmo
com erro**. Contar `^! ` no log é o que vale; "saiu PDF" não prova nada.

## Pipeline de geração do catálogo

Três ferramentas, nesta ordem:

1. **traduzir** em lotes (agentes paralelos, sobre o glossário do idioma) →
   `traduzido-<lang>/*.json`;
2. `tools/canonicalize-catalog.py catalogo.json nvts-source.json` — **uniformiza
   o boilerplate**: centenas de NVTs compartilham frases idênticas, e cada lote as
   traduz do seu jeito. No pt-BR uma frase saiu com **dez** redações; no espanhol,
   sete. Critério: mais frequente → mesma contagem de quebras da fonte →
   lexicográfico (determinístico e idempotente);
3. `tools/build-nvt-catalog.py catalogo.json <lang>` — JSON → XML, desescapando a
   quebra de linha.

Depois: verificar identificadores por script (CVE/CWE/advisory/CVSS/URL/versão,
conjunto a conjunto contra a origem) e rodar `tools/build-torture-fixture.py`.
