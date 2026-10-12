# report-formats — Suricatoos Premium PDF

O relatório PDF do scanner (LaTeX gerado por XSLT dentro do gvmd) em **3 edições**
(`technical`, `client`, `executive`) × **3 idiomas** (`en`, `pt_BR`, `es`) = **9 report
formats** no dropdown *Download report* do GSA.

```
suricatoos-premium-pdf/   o bundle: latex.xsl, .sty, generate, catálogos de NVT, logos, fontes
build-feed-xml.py         gera os 9 objetos de feed, o manifest.json e o descritor de referência
manifest.json             (versionado) format/lang/variant -> UUID: o conector da frota lê
Dockerfile                a imagem de feed (copia os 9 XMLs para cada diretório de release)
ci/                       portões e scripts do CI (compile.sh, gates.sh, check-*.py, lib.sh)
tests/                    fixtures, test_*.py (rodam no CI), mutantes-*.py (ferramentas de dev)
sample/sample-report.xml  a entrada de amostra (só dado inventado)
```

## O feed é gerado, não versionado

Os 9 `pdf-suricatoos-<uuid>.xml` e `suricatoos-premium-pdf/report_format.xml` (o descritor
de referência) são **saída do build** e estão no `.gitignore`: cada mudança de relatório
regerava ~21 MB no histórico do repo público. O CI e o publish rodam o build antes de usá-los.
Localmente: `python3 report-formats/build-feed-xml.py` (o log traz o sha256 de cada objeto:
dois commits com a mesma lista entregam o mesmo feed).

`manifest.json` é o único gerado que fica no repo (o conector da frota o lê para anunciar
`capabilities.report_formats`): o build tem de reescrevê-lo igual, e ele **não traz VERSION**.

**Imagem local:** rode `python3 report-formats/build-feed-xml.py` **logo antes** do `docker build`.
Os XMLs ignorados sobrevivem à troca de branch, e um `docker build` sem o build antes empacota os de
outro branch. A guarda do `Dockerfile` é o `RUN` (exige exatamente 9 objetos; o `COPY` de um curinga
vazio não falha sob o BuildKit) e **não distingue um conjunto velho de um novo**: o CI e o publish
partem de um checkout limpo e rodam o `check-manifest`, que compara cada objeto com o bundle.

## VERSION por conteúdo

Ninguém sobe a VERSION: o build a **deriva do conteúdo** — `sha256-` + 12 hex do sha256 dos 9
objetos renderizados com um marcador no lugar da VERSION. Mesmo conteúdo, mesma VERSION em
qualquer máquina (sem data de build, git, caminho ou mtime); um byte a mais em qualquer
membro do feed ou nos textos do `build-feed-xml.py`, outra VERSION; arquivo da pasta do bundle
que não vai no feed (`FONTS.md`, `tools/`, `main.tex`) não conta.
`python3 report-formats/build-feed-xml.py --print-version` a imprime.

Ela é só texto (resumo e descrição de cada report format): o gvmd reimporta um report format
quando o arquivo do feed é mais novo que o `modification_time` dele, e o feed-updater compara o
ID da imagem — nenhum dos dois lê a VERSION. Prova: `tests/test_feed.py`
(`python3 -m unittest discover -s report-formats/tests -p 'test_*.py' -v`) e o modo `versao` de
`tests/mutantes-variantes.py`.

## CI e publish

- **`report-formats-ci`** (PR e push na `main`): `feed-sync` (gera, confere manifesto, bytes do
  bundle e VERSION em cada objeto, roda `test_feed.py`, `test_stable_gate.py` e
  `test_gvmd_drift.py`), `compile` (9 jobs, todas as fixtures, na imagem do gvmd), `previas` e
  `measure` (os dois não bloqueiam). O CI da `main` não cancela o de outro commit; só PR cancela.
- **`report-formats-gvmd-stable`** (toda segunda-feira, e a mão depois do merge): vigia a deriva
  entre o gvmd fixado e a `stable` (abaixo). Não bloqueia nada.
- **`report-formats-publish`** roda **depois do `report-formats-ci`**: só quando o CI de um push na
  `main` termina com `success` (`workflow_run`), e constrói a imagem do commit que o CI aprovou. O
  disparo manual (`workflow_dispatch`) continua e não espera o CI (o log avisa).
- **A tag `stable` só anda para o commit mais novo do relatório na `main`**
  (`ci/stable-gate.sh`, decidido na hora do push): o commit tem de ser ancestral da `main` e nenhum
  commit da `main` depois dele pode tocar `report-formats/` nem os workflows do relatório
  (`report-formats-ci.yml`, `report-formats-publish.yml`). Um re-run de CI antigo, um CI lento que
  termina depois de um mais novo e um disparo manual de outro branch empurram **só `:<sha12>`** (o
  resumo do job diz por quê): senão a frota voltaria a um relatório velho no sync seguinte, e o GSA
  não mostra nada (a VERSION é um hash). Se o commit mais novo que toca o relatório reprovar no CI,
  a `stable` espera: a próxima correção que passar a move (ou um disparo manual da ponta da `main`).
  O disparo manual roda o workflow do branch escolhido, então a guarda só protege os branches que já
  a contêm.
- A imagem vira `ghcr.io/williamsouzadelima/suricatoos-report-formats:stable` (e `:<sha12>`); o
  feed-updater a puxa e o gvmd reimporta. Os CIs da `main` não se cancelam entre si (um grupo por
  commit) e o publish também é uma fila por commit: a ordem entre commits é do portão, não da fila.

## Imagem do gvmd do CI: fixada por digest

O CI e a medição rodam na imagem de produção do gvmd **fixada por digest em `ci/lib.sh`**
(`GVMD_IMAGE`), porque a tag `stable` muda sozinha. Origem: `gvmd:stable` resolvida em
2026-10-12 (v26.41.0). **Para atualizar**, num PR próprio: resolva o digest da `stable`, troque
em `ci/lib.sh` (e a data/versão no comentário) e leia uma reprovação como "a imagem nova mudou
algo". O comentário de `ci/lib.sh` tem os comandos, com e sem docker. `GVMD_IMAGE` no ambiente
vence o padrão (para experimentar a `stable` de hoje).

A produção puxa a `stable` (`compose/compose.yaml`), então fixar o CI tem um custo: quando a
`stable` anda, o CI deixa de testar o gvmd da produção. Por isso **toda segunda-feira**
`report-formats-gvmd-stable.yml` (`ci/gvmd-drift.sh`) resolve a `stable` de hoje e compara com o
pin: digest igual, "sem deriva"; diferente, **avisa no resumo** (com a versão do gvmd) e compila
uma combinação (`en/technical`, todas as fixtures e portões) nela, dizendo se passou ou
reprovou. Não bloqueia nada: sai 0 sempre e o veredito fica no resumo do job. O workflow só roda
(agendado ou manual) depois do merge na `main`.

## Prévias visuais (para revisão humana)

O repo não guarda PDF nem PNG de amostra (ficavam velhos). O CI publica, de cada edição ×
idioma, o PNG das 12 primeiras páginas do PDF da fixture `v27-cliente-falso-positivo`:
artefato **`previas`** (uma pasta por idioma e edição) e `previas-<idioma>-<edição>` por job.
Pela linha de comando: `gh run download <run-id> -n previas`. Mais PDFs, `.tex` e logs de
todas as fixtures em `report-formats-<idioma>-<edição>`.

## Provas de mutação (dev, fora do CI)

`python3 report-formats/tests/mutantes-variantes.py [xslt|tex|feed|versao|todos]` (precisa de
`lxml`): cada defeito que um portão deve pegar, reprovado; os controles passam.
