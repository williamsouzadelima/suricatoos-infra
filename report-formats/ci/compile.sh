#!/usr/bin/env bash
# Compila o Suricatoos Premium PDF de UM objeto de feed (idioma x edicao) na
# imagem de PRODUCAO do gvmd, como uid 1001, e aplica os portoes (gates.sh) a
# cada fixture. Edicoes: technical (o relatorio completo), client (sem falso
# positivo, o Log so' como contagem) e executive (resumo, prioridades e escopo).
#
# Uso: report-formats/ci/compile.sh <lang> <variant> <dir-de-artefatos>
#
# Fixtures (sinteticas):
#   sample   report-formats/sample/sample-report.xml
#   tortura  saida do tools/build-torture-fixture.py: um achado por OID do
#            catalogo de traducao do idioma, prova de que TODO o texto
#            traduzido compila. O catalogo en e' vazio de proposito (o relatorio
#            em ingles nao traduz NVT) e o script recusa catalogo vazio, entao
#            em en a tortura usa os OIDs e nomes do catalogo pt_BR, compilados em
#            ingles: exercita o caminho do texto do FORNECEDOR com centenas de
#            achados de nome acentuado.
#   v*       report-formats/tests/fixtures/*.xml: uma fixture por defeito de
#            veracidade ja' corrigido (numeracao, indicadores vazios, ...),
#            mais a v10-navegacao (caminhos de navegacao que as outras nao
#            percorrem), as v11..v20 da secao 7 (escopo, metodologia e
#            limitacoes: autenticacao, erros de scan, tarefa que nao iniciou,
#            tabelas acima do teto, scan interrompido, inventario do agente,
#            import do sensor, o veto do comentario do bridge) e as v21..v26 da
#            secao 2 (prioridades e proximos passos: a ordem do plano com
#            empate em cada nivel e EPSS, grupos consolidados e os textos da
#            coluna de acao, sem critico nem alto e sem EPSS, exatamente 20
#            acoes, uma acao so', mais de 20 acoes por card com cards
#            consolidados dentro e fora das 20), mais as v27..v28 das
#            edicoes (v27 falso positivo em toda parte: card misto, porta e
#            NVT so' de falso positivo, grupo que encolhe e grupo que se
#            desfaz, confirmacao so' por falso positivo, Log e nota da linha
#            geral; v28 so' Log, com o bloco de indicadores so' de Log); o
#            cabecalho de cada uma diz qual. Toda fixture roda nas tres
#            edicoes. A v20a..v20i e' a TABELA DE ESTADOS: um relatorio sem
#            host por scan_run_status, para que cada estado das listas de
#            $scan-never-started e $scan-unfinished do latex.xsl tenha a sua
#            fixture (o alerta da secao 1 e a nota da secao 7 mudam):
#              iniciou e nao terminou (alerta "nao terminou"): v20a Running,
#                v20b Stop Requested, v20c Stopped; Interrupted e' a v14 (com
#                hosts: so' a nota);
#              nunca iniciou (alerta "nao chegou a rodar"): v20d New,
#                v20e Requested, v20f Queued, v20g Stop Requested, v20h Stopped,
#                v20i Interrupted; sem o elemento, a v12;
#              terminou sem host (alerta do alive test): v17 Done.
#            Pequenas: segundos cada.
#
# Para cada fixture:
#   1. ponta a ponta: `sh ./generate <xml> > generate.pdf`, cwd = bundle montado
#      pelo stage-bundle.py (o que o objeto de feed instala) -- como o gvmd faz;
#   2. diagnostico: diag-compile.sh (xsltproc + 2x pdflatex com os mesmos
#      parametros) guardando .tex e .log;
#   3. previews (pdftoppm -r 60, 3 primeiras paginas) e gates.sh -- que tambem
#      roda o check-veracity.py sobre o .tex do diagnostico, contra o XML, e o
#      check-navigation.py (sumario e arvore de marcadores, no PDF entregue).
# Artefatos em <dir-de-artefatos>/<lang>/<variant>/<fixture>/.
set -euo pipefail

. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

lang=${1:?uso: compile.sh <lang> <variant> <dir-de-artefatos>}
variant=${2:?uso: compile.sh <lang> <variant> <dir-de-artefatos>}
art="${3:?uso: compile.sh <lang> <variant> <dir-de-artefatos>}/$lang/$variant"
mkdir -p "$art"

gvmd_pull

work=$(new_workdir)
log "diretorio de trabalho: $work"
mkdir -p "$work/fixtures" "$work/ci" "$work/diag"
stage_bundle "$lang" "$variant" "$work/bundle"
cp "$CI_DIR/diag-compile.sh" "$work/ci/"

cp "$RF_DIR/sample/sample-report.xml" "$work/fixtures/sample.xml"
torture_src=$lang
if [ "$lang" = en ]; then torture_src=pt_BR; fi
( cd "$BUNDLE_SRC" && python3 -X utf8 tools/build-torture-fixture.py "$torture_src" ) \
  > "$work/fixtures/tortura.xml"
fixtures="sample tortura"
for f in "$RF_DIR"/tests/fixtures/*.xml; do
  [ -f "$f" ] || continue
  fx=$(basename "$f" .xml)
  cp "$f" "$work/fixtures/$fx.xml"
  fixtures="$fixtures $fx"
done
log "fixtures: $fixtures"
open_perms "$work"

log "ambiente dentro da imagem:"
gvmd_run "$work" /work -c '
  echo "id: $(id)"
  echo "/bin/sh -> $(readlink -f /bin/sh)"
  xsltproc --version 2>&1 | head -n 1
  pdflatex --version 2>&1 | head -n 1
' | tee "$art/ambiente.txt"
docker image inspect --format 'imagem: {{join .RepoDigests ", "}}' "$GVMD_IMAGE" | tee -a "$art/ambiente.txt"

overall=0
for fx in $fixtures; do
  d="$art/$fx"
  mkdir -p "$d"

  log "[$lang/$variant/$fx] ponta a ponta: sh ./generate (uid $GVMD_UID, cwd = bundle)"
  e2e_rc=0
  t0=$SECONDS
  gvmd_run "$work" /work/bundle ./generate "/work/fixtures/$fx.xml" \
    > "$d/generate.pdf" 2> "$d/generate.stderr.txt" || e2e_rc=$?
  log "[$lang/$variant/$fx] generate: exit $e2e_rc, $(wc -c < "$d/generate.pdf" | tr -d ' ') bytes no stdout, $((SECONDS - t0)) s"

  log "[$lang/$variant/$fx] diagnostico: xsltproc + 2x pdflatex (mesmos parametros do generate)"
  t0=$SECONDS
  diag_rc=0
  gvmd_run "$work" /work/bundle /work/ci/diag-compile.sh "/work/fixtures/$fx.xml" "/work/diag/$fx" || diag_rc=$?
  log "[$lang/$variant/$fx] diagnostico: exit $diag_rc, $((SECONDS - t0)) s"
  # report.aux (rotulos de pagina do sumario) e report.out (a arvore de
  # marcadores que o hyperref escreveu) vao junto: sao o que se le quando o
  # portao de navegacao reprova.
  for f in report.tex report.log report.pass1.log xsltproc.stderr report.aux report.out variant; do
    if [ -f "$work/diag/$fx/$f" ]; then cp "$work/diag/$fx/$f" "$d/"; fi
  done

  if [ "$(head -c 4 "$d/generate.pdf" | tr -d '\0')" = "%PDF" ]; then
    pdftoppm -r 60 -f 1 -l 3 -png "$d/generate.pdf" "$d/pagina" || log "[$lang/$variant/$fx] pdftoppm falhou"
  fi

  if ! "$CI_DIR/gates.sh" "$lang" "$variant" "$fx" "$d" "$work/diag/$fx" "$e2e_rc" "$work/fixtures/$fx.xml"; then
    overall=1
  fi
done

if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  {
    echo "### Suricatoos Premium PDF no gvmd fixado por digest — $lang / $variant"
    echo
    echo "| idioma | edição | fixture | veredito | páginas | erros TeX | Font shape undefined | Type 3 | links / alvos (+corte) | Overfull \\hbox (base) | veracidade | navegação |"
    echo "|---|---|---|---|---|---|---|---|---|---|---|---|"
    cat "$art"/*/summary.row 2>/dev/null || true
    echo
    sed 's/^/    /' "$art/ambiente.txt"
  } >> "$GITHUB_STEP_SUMMARY"
fi

if [ "$overall" -ne 0 ]; then
  log "REPROVADO: ao menos um portao falhou em $lang/$variant (detalhes acima e em gates.txt no artefato)"
fi
exit "$overall"
