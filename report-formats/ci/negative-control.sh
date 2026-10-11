#!/usr/bin/env bash
# CONTROLE NEGATIVO: prova que o `generate` falha ALTO.
#
# Cada caso entrega ao generate um bundle (ou uma entrada) quebrado de proposito
# e o roda como o gvmd roda: `sh ./generate <xml>`, uid 1001, imagem de
# producao. O caso passa se, e somente se, o generate:
#   - sair com erro (exit 1..124; 125+ seria o docker, nao o generate);
#   - NAO escrever nada no stdout -- logo, nenhum %PDF;
#   - disser no stderr o que houve: a CAUSA esperada do caso (uma ERE do
#     grep -E), e nao so' o prefixo de erro do generate.
#
# Casos:
#   sem-blocks    bundle sem suricatoos-blocks.sty (o caso pedido na fatia);
#   erro-tex      copia do bundle com um erro de TeX injetado num .sty. O
#                 pdflatex em batchmode AINDA escreve um PDF nesse caso -- era o
#                 PDF mutilado que saia com exit 0 --, e o generate tem de
#                 recusar entrega-lo. O diagnostico confirma a premissa (o PDF
#                 existe) e reporta;
#   xml-quebrado  XML malformado: o xsltproc falha;
#   xml-vazio     invólucro <report extension="xml"> sem relatorio dentro: o
#                 xsltproc sai 0 com saida VAZIA.
#
# Uso: report-formats/ci/negative-control.sh <lang> <dir-de-artefatos>
set -euo pipefail

. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

lang=${1:?uso: negative-control.sh <lang> <dir-de-artefatos>}
art="${2:?uso: negative-control.sh <lang> <dir-de-artefatos>}/$lang/controle-negativo"
mkdir -p "$art"

gvmd_pull

work=$(new_workdir)
mkdir -p "$work/fixtures" "$work/ci"
cp "$CI_DIR/diag-compile.sh" "$work/ci/"
cp "$RF_DIR/sample/sample-report.xml" "$work/fixtures/sample.xml"
printf '<report id="00000000-0000-0000-0000-000000000000"><results>' \
  > "$work/fixtures/quebrado.xml"
printf '<report extension="xml" id="00000000-0000-0000-0000-000000000000"/>\n' \
  > "$work/fixtures/vazio.xml"

stage_bundle "$lang" "$work/sem-blocks" --omit suricatoos-blocks.sty
stage_bundle "$lang" "$work/erro-tex"
# No INICIO do .sty: todos terminam em \endinput, e o que vier depois dele nao
# e' lido. O \AtBeginDocument dispara no \begin{document}: erro "Undefined
# control sequence", recuperavel em batchmode -- o documento sai inteiro.
{
  printf '%s\n' '\AtBeginDocument{\SuricatoosCiControleNegativo}'
  cat "$work/erro-tex/suricatoos-report.sty"
} > "$work/erro-tex/suricatoos-report.sty.new"
mv "$work/erro-tex/suricatoos-report.sty.new" "$work/erro-tex/suricatoos-report.sty"
stage_bundle "$lang" "$work/integro"
open_perms "$work"

failures=0
rows=()

# caso <nome> <bundle> <fixture> <causa-esperada-no-stderr (ERE)>
caso() {
  local name=$1 bundle=$2 fixture=$3 expect=$4
  local out="$art/$name.stdout" err="$art/$name.stderr.txt"
  local rc=0 size n_pdf n_expect verdict=OK why=
  gvmd_run "$work" "/work/$bundle" ./generate "/work/fixtures/$fixture" > "$out" 2> "$err" || rc=$?
  size=$(wc -c < "$out" | tr -d ' ')
  n_pdf=$({ grep -a -c -e '%PDF' -- "$out" 2>/dev/null || true; } | tr -d ' ')
  n_expect=$({ grep -a -c -E -e "$expect" -- "$err" 2>/dev/null || true; } | tr -d ' ')
  if [ "$rc" -lt 1 ] || [ "$rc" -gt 124 ]; then why="$why; exit $rc (esperado 1..124)"; fi
  if [ "${n_pdf:-0}" -ne 0 ]; then why="$why; %PDF no stdout"; fi
  if [ "$size" -ne 0 ]; then why="$why; stdout com $size bytes (esperado vazio)"; fi
  # ("|" da ERE vira " ou ": a frase vai para uma tabela markdown no resumo.)
  if [ "${n_expect:-0}" -eq 0 ]; then why="$why; stderr nao menciona '${expect//|/ ou }'"; fi
  if [ -n "$why" ]; then
    verdict="FALHA: ${why#; }"
    failures=$((failures + 1))
  fi
  log "[$lang/controle-negativo/$name] exit $rc, stdout $size bytes, %PDF no stdout: ${n_pdf:-0} -> $verdict"
  sed -n '1,25p' "$err" | sed 's/^/           | /'
  rows+=("| $lang | $name | $rc | $size | $verdict |")
}

caso sem-blocks   sem-blocks sample.xml   'suricatoos-blocks\.sty'
caso erro-tex     erro-tex   sample.xml   'Undefined control sequence'
caso xml-quebrado integro    quebrado.xml 'xsltproc'
# Aqui o generate pega o .tex vazio antes do pdflatex; se um dia o xsltproc
# devolver um "\n" em vez de nada, quem falha e' o pdflatex (Emergency stop) --
# alto do mesmo jeito, e o generate diz "TeX errors" / "report.pdf missing".
# Qualquer uma das tres causas serve; um "generate: ERROR" por OUTRO motivo
# (bundle incompleto, catalogo, permissao) nao prova este caso e reprova.
caso xml-vazio    integro    vazio.xml    'empty \.tex|TeX errors|report\.pdf missing'

# Premissa do erro-tex: sem o generate no meio, o pdflatex entrega mesmo um PDF
# com o erro no log? (Informativo -- e' o que torna o caso significativo.)
gvmd_run "$work" /work/erro-tex /work/ci/diag-compile.sh /work/fixtures/sample.xml /work/diag-erro-tex \
  || log "[$lang/controle-negativo] diag-compile.sh do erro-tex saiu $?"
d="$work/diag-erro-tex"
if [ -s "$d/report.pdf" ]; then
  log "[$lang/controle-negativo] premissa CONFIRMADA: o pdflatex escreveu report.pdf ($(wc -c < "$d/report.pdf" | tr -d ' ') bytes, exit $(cat "$d/pdflatex.rc" 2>/dev/null)) com $({ grep -a -c '^!' "$d/report.log" 2>/dev/null || true; } | tr -d ' ') erro(s) TeX no log; o generate recusou entrega-lo"
else
  log "[$lang/controle-negativo] premissa NAO reproduzida: o pdflatex nao escreveu PDF com o erro injetado (o caso continua provando a recusa, mas nao o PDF mutilado)"
fi

if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  {
    echo "### Controle negativo do generate — $lang"
    echo
    echo "| idioma | caso | exit | bytes no stdout | veredito |"
    echo "|---|---|---|---|---|"
    printf '%s\n' "${rows[@]}"
    echo
  } >> "$GITHUB_STEP_SUMMARY"
fi

if [ "$failures" -ne 0 ]; then
  log "REPROVADO: $failures caso(s) do controle negativo nao falharam alto"
  exit 1
fi
log "controle negativo OK: o generate falhou alto nos 4 casos"
