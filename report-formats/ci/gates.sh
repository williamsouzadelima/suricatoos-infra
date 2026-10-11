#!/usr/bin/env bash
# Portoes do Suricatoos Premium PDF para UMA combinacao (idioma x fixture).
#
# Uso: gates.sh <lang> <fixture> <dir-artefatos> <dir-diag> <exit-do-generate> [<fixture.xml>]
#
#   <dir-artefatos>  tem generate.pdf e generate.stderr.txt (o `sh ./generate`
#                    ponta a ponta); recebe gates.txt e summary.row;
#   <dir-diag>       saida do diag-compile.sh (report.tex, report.log, ...);
#   <fixture.xml>    o relatorio de entrada: liga o portao de veracidade e diz
#                    se a fixture tem achados (portao de links).
#
# Todos os portoes rodam (um nao esconde o outro); o veredito sai no fim, com
# exit 1 se qualquer um reprovar:
#   generate     exit 0; stdout comeca com %PDF, termina com %%EOF e o pdfinfo
#                le o arquivo;
#   xsltproc     exit 0 e .tex nao vazio (diagnostico);
#   pdflatex     2a passada com exit 0 (diagnostico);
#   erros TeX    zero linhas `^!` no report.log;
#   Font shape   zero `Font shape .* undefined` no report.log;
#   destinos     zero "has been referenced but does not exist" no report.log:
#                e' o proprio pdfTeX dizendo que um link do PDF nao tem destino
#                (o portao de links abaixo olha o .tex; este, o documento);
#   Type 3       zero fonte Type 3 no PDF do generate (pdffonts): Type 3 e'
#                bitmap -- a face de verdade sumiu e o pdftex desenhou pixels;
#   links/alvos  zero \hyperlink para alvo inexistente e
#                #\hypertarget == #\hyperlink + soma dos cortes declarados
#                (ver a nota abaixo); e, se o XML tem <result>, ao menos UM
#                link: 0 links com 0 alvos fecha a conta e passaria em vazio
#                justamente quando o sumario ou os cards sumissem;
#   overfull     #`Overfull \hbox` <= linha de base de (idioma, fixture);
#   paridade     paginas do PDF do generate == paginas do diagnostico, ou seja,
#                os portoes de log mediram o MESMO documento que o generate
#                entrega;
#   veracidade   check-veracity.py: o .tex diz a verdade sobre o XML
#                (numeracao, secoes, consolidado, instancias, acao, VULNS
#                UNICAS, faixas, ancoras, nome do projeto).
#
# Nota sobre links/alvos. A regua historica e' "#\hyperlink == #\hypertarget no
# .tex", e ela vale enquanto o Sumario de Achados lista todos os achados (caso
# da sample). Com o orcamento do sumario ($summary-max no latex.xsl) as linhas
# informativas (Log) do fim da tabela sao cortadas e o corte e' DECLARADO num
# \findingtrunc{\suriEllip\ + N ...}; os cards desses N achados continuam no
# documento, com \hypertarget e sem \hyperlink. Medido com libxslt sobre a
# tortura (catalogo pt_BR): 178 links, 215 alvos, cortes 31 + 6 = 37. A conta
# exata e' portanto alvos == links + soma(N) -- que vira a igualdade quando nao
# ha corte --, e o defeito que a regua existe para pegar (link para ancora que
# nao existe) e' checado diretamente.
set -euo pipefail
export LC_ALL=C

lang=${1:?uso: gates.sh <lang> <fixture> <dir-artefatos> <dir-diag> <exit-do-generate> [<fixture.xml>]}
fx=${2:?}
art=${3:?}
diag=${4:?}
e2e_rc=${5:?}
xml=${6:-}
ci_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

# ---------------------------------------------------------------------------
# Linha de base de `Overfull \hbox` por (idioma, fixture): o portao reprova
# ACIMA dela.
#
# PROVISORIA: 0 em tudo, que e' o que o tools/build-torture-fixture.py declara
# como portao da tortura. A primeira execucao deste CI mede o valor real no
# gvmd:stable; se for outro, ele e' fixado AQUI com a data e o run que o mediu.
# Depois disso e' catraca: baixou, abaixe junto; subiu, e' regressao de layout
# a corrigir no XSLT/.sty -- nao na linha de base, salvo decisao registrada.
# ---------------------------------------------------------------------------
overfull_baseline() {
  case "$1/$2" in
    en/sample)     echo 0 ;;
    pt_BR/sample)  echo 0 ;;
    es/sample)     echo 0 ;;
    en/tortura)    echo 0 ;;
    pt_BR/tortura) echo 0 ;;
    es/tortura)    echo 0 ;;
    # Fixtures de veracidade (report-formats/tests/fixtures/), nos 3 idiomas:
    # nascem com 0, a mesma regua das outras.
    */v1-numeracao | */v2-indicadores-vazios | */v3-consolidado-qod | \
    */v4-instancias | */v5-acao-traduzida | */v6-vulns-unicas | \
    */v7a-faixas | */v7b-lowconf | */v8-ancora | */v9-nome-capa) echo 0 ;;
    *) return 1 ;;
  esac
}

pdf="$art/generate.pdf"
err="$art/generate.stderr.txt"
tex="$diag/report.tex"
logf="$diag/report.log"
dpdf="$diag/report.pdf"
report="$art/gates.txt"
tmpd=$(mktemp -d)
trap 'rm -rf "$tmpd"' EXIT
: > "$report"

failures=0
# valores do resumo (summary.row); "?" = nao medido
pages='?'; n_err='?'; n_font='?'; n_t3='?'; links_cell='?'; over_cell='?'; ver_cell='?'

say() { printf '%s\n' "$*" | tee -a "$report"; }
indent() { sed 's/^/           | /' | tee -a "$report"; }
gate() { # gate <ok|falha> <nome> <detalhe>
  if [ "$1" = ok ]; then
    say "  OK     $2: $3"
  else
    say "  FALHA  $2: $3"
    failures=$((failures + 1))
  fi
}
# Linhas que casam (grep -c imprime 0 e sai 1 quando nada casa; arquivo
# ausente vira 0 -- quem chama confere a existencia antes).
count_lines() {
  local n
  n=$(grep -a -c -e "$1" -- "$2" 2>/dev/null) || true
  printf '%s\n' "${n:-0}"
}
# Ocorrencias (nao linhas) de uma BRE.
count_matches() {
  { grep -a -o -e "$1" -- "$2" 2>/dev/null || true; } | wc -l | tr -d ' '
}
pdf_pages() {
  { pdfinfo "$1" 2>/dev/null || true; } | awk '/^Pages:/ { print $2 }'
}
size_of() {
  if [ -f "$1" ]; then wc -c < "$1" | tr -d ' '; else echo 0; fi
}

say "== portoes: $lang / $fx"

# --- ponta a ponta: o que o gvmd recebe ---------------------------------------
if [ "$e2e_rc" -eq 0 ]; then
  gate ok "generate exit" "0"
else
  gate falha "generate exit" "$e2e_rc$([ "$e2e_rc" -ge 125 ] && echo ' (>= 125: falha do docker, nao do generate)')"
fi
if [ -s "$err" ]; then
  say "         stderr do generate (primeiras linhas):"
  sed -n '1,40p' "$err" | indent
fi
magic=$(head -c 4 "$pdf" 2>/dev/null | tr -d '\0' || true)
if [ "$magic" = "%PDF" ]; then
  gate ok "stdout e' PDF" "comeca com %PDF ($(size_of "$pdf") bytes)"
else
  gate falha "stdout e' PDF" "nao comeca com %PDF ($(size_of "$pdf") bytes)"
fi
tail -c 1024 "$pdf" > "$tmpd/tail" 2>/dev/null || : > "$tmpd/tail"
if [ "$(count_lines '%%EOF' "$tmpd/tail")" -gt 0 ]; then
  gate ok "PDF inteiro" "%%EOF no fim"
else
  gate falha "PDF inteiro" "sem %%EOF no ultimo 1 KB (vazio ou truncado)"
fi
pages=$(pdf_pages "$pdf")
if [ -n "$pages" ] && [ "$pages" -ge 1 ]; then
  gate ok "pdfinfo" "$pages paginas"
else
  gate falha "pdfinfo" "nao conseguiu ler o PDF do generate"
  pages=0
fi

# --- diagnostico: xsltproc e pdflatex ------------------------------------------
x_rc=$(cat "$diag/xsltproc.rc" 2>/dev/null || echo '?')
if [ "$x_rc" = 0 ] && [ -s "$tex" ]; then
  gate ok "xsltproc (diag)" "exit 0, .tex com $(size_of "$tex") bytes"
else
  gate falha "xsltproc (diag)" "exit $x_rc, .tex com $(size_of "$tex") bytes"
fi
if [ -s "$diag/xsltproc.stderr" ]; then
  say "         stderr do xsltproc (primeiras linhas):"
  sed -n '1,20p' "$diag/xsltproc.stderr" | indent
fi
p1='?'; p2='?'
if [ -f "$diag/pdflatex.rc" ]; then read -r p1 p2 < "$diag/pdflatex.rc" || true; fi
if [ "$p2" = 0 ]; then
  gate ok "pdflatex 2a passada (diag)" "exit 0 (1a passada: $p1)"
else
  gate falha "pdflatex 2a passada (diag)" "exit $p2 (1a passada: $p1)"
fi

# --- log do TeX: erros, fontes, overfull --------------------------------------
if [ -f "$logf" ]; then
  n_err=$(count_lines '^!' "$logf")
  if [ "$n_err" -eq 0 ]; then
    gate ok "erros TeX (^!)" "0"
  else
    gate falha "erros TeX (^!)" "$n_err linha(s); as primeiras, com contexto:"
    awk '/^!/ { n = 3 } n > 0 { print; n-- }' "$logf" | sed -n '1,30p' | indent
  fi

  n_font=$(count_lines 'Font shape .* undefined' "$logf")
  if [ "$n_font" -eq 0 ]; then
    gate ok "Font shape undefined" "0"
  else
    gate falha "Font shape undefined" "$n_font (a face pedida nao existe; o LaTeX trocou por outra):"
    grep -a -e 'Font shape .* undefined' -- "$logf" | sort | uniq -c | sort -rn | sed -n '1,10p' | indent
  fi

  # O TeX quebra o .log em 79 colunas e o aviso, com o nome da ancora dentro,
  # passa disso: a frase pode cair partida entre duas linhas. Sem as quebras
  # ela volta inteira (e nenhuma outra linha do log forma a frase toda).
  tr -d '\n' < "$logf" > "$tmpd/log.flat"
  n_dest=$(count_matches 'has been referenced but does not exist' "$tmpd/log.flat")
  if [ "$n_dest" -eq 0 ]; then
    gate ok "destinos do PDF" "0 link sem destino (pdfTeX)"
  else
    gate falha "destinos do PDF" "$n_dest aviso(s) 'has been referenced but does not exist' do pdfTeX:"
    { grep -a -o -e 'name{[^}]*} has been referenced' -- "$tmpd/log.flat" || true; } \
      | sed -n '1,10p' | indent
  fi

  n_over=$(count_lines '^Overfull \\hbox' "$logf")
  n_vbox=$(count_lines '^Overfull \\vbox' "$logf")
  if base=$(overfull_baseline "$lang" "$fx"); then
    over_cell="$n_over ($base)"
    if [ "$n_over" -le "$base" ]; then
      gate ok "Overfull \\hbox" "$n_over (linha de base $base)"
      if [ "$n_over" -lt "$base" ]; then
        say "         (catraca) abaixo da linha de base: baixe-a para $n_over no gates.sh"
      fi
    else
      gate falha "Overfull \\hbox" "$n_over, acima da linha de base $base; os primeiros:"
    fi
    if [ "$n_over" -gt 0 ]; then
      awk '/^Overfull \\hbox/ { n = 2 } n > 0 { print; n-- }' "$logf" | sed -n '1,12p' | indent
    fi
  else
    over_cell="$n_over (sem base)"
    gate falha "Overfull \\hbox" "$n_over, e nao ha linha de base para $lang/$fx no gates.sh"
  fi
  say "         (info) Overfull \\vbox: $n_vbox"
else
  gate falha "report.log" "o diagnostico nao gerou report.log"
fi

# --- links/alvos no .tex --------------------------------------------------------
if [ -s "$tex" ]; then
  n_links=$(count_matches '\\hyperlink{' "$tex")
  n_targets=$(count_matches '\\hypertarget{' "$tex")
  { grep -a -o -e '\\hyperlink{[^}]*}' -- "$tex" || true; } \
    | sed 's/^\\hyperlink{//; s/}$//' | sort -u > "$tmpd/links"
  { grep -a -o -e '\\hypertarget{[^}]*}' -- "$tex" || true; } \
    | sed 's/^\\hypertarget{//; s/}$//' | sort > "$tmpd/targets.all"
  sort -u "$tmpd/targets.all" > "$tmpd/targets"
  comm -23 "$tmpd/links" "$tmpd/targets" > "$tmpd/dangling"
  n_dangling=$(wc -l < "$tmpd/dangling" | tr -d ' ')
  n_dup=$(uniq -d "$tmpd/targets.all" | wc -l | tr -d ' ')
  trunc=$({ grep -a -o -e '\\findingtrunc{\\suriEllip\\ + [0-9][0-9.,]*' -- "$tex" || true; } \
    | sed 's/.*+ //; s/[.,]//g' | awk '{ s += $1 } END { print s + 0 }')
  links_cell="$n_links / $n_targets (+$trunc)"
  detail="$n_links \\hyperlink, $n_targets \\hypertarget, corte declarado no sumario: $trunc, links sem alvo: $n_dangling"
  # A conta acima fecha com 0 = 0: sem este piso, um sumario que sumisse
  # inteiro passaria. Fixture com <result> tem de ter ao menos um link.
  n_results=0
  if [ -n "$xml" ] && [ -f "$xml" ]; then
    n_results=$(count_matches '<result[ >]' "$xml")
  fi
  if [ "$n_results" -gt 0 ] && [ "$n_links" -eq 0 ]; then
    gate falha "links/alvos" "$detail -- e o XML tem $n_results <result>: sumario sem nenhum link"
  elif [ "$n_dangling" -eq 0 ] && [ "$n_targets" -eq $((n_links + trunc)) ]; then
    gate ok "links/alvos" "$detail"
  else
    gate falha "links/alvos" "$detail"
    if [ "$n_dangling" -gt 0 ]; then
      say "         links sem alvo (primeiros):"
      sed -n '1,10p' "$tmpd/dangling" | indent
    fi
  fi
  if [ "$n_dup" -gt 0 ]; then
    say "         (info) $n_dup alvo(s) repetido(s) -- o pdftex fica com o primeiro:"
    uniq -d "$tmpd/targets.all" | sed -n '1,5p' | indent
  fi
else
  gate falha "links/alvos" "sem .tex para contar"
fi

# --- fontes no PDF entregue -----------------------------------------------------
if pdffonts "$pdf" > "$tmpd/fonts" 2>&1; then
  n_t3=$(count_lines 'Type 3' "$tmpd/fonts")
  if [ "$n_t3" -eq 0 ]; then
    gate ok "fontes Type 3 (pdffonts)" "0"
  else
    gate falha "fontes Type 3 (pdffonts)" "$n_t3 (bitmap no lugar da face Type 1)"
  fi
  n_nonplex=$(awk 'NR > 2 && $1 !~ /Plex/' "$tmpd/fonts" | wc -l | tr -d ' ')
  say "         (info) fontes no PDF ($n_nonplex fora da familia Plex):"
  indent < "$tmpd/fonts"
else
  gate falha "fontes Type 3 (pdffonts)" "pdffonts nao leu o PDF do generate"
fi

# --- paridade generate x diagnostico -------------------------------------------
dpages=$(pdf_pages "$dpdf")
if [ -n "$dpages" ] && [ "$dpages" = "$pages" ]; then
  gate ok "paridade generate x diag" "$pages paginas nos dois"
else
  gate falha "paridade generate x diag" "generate: $pages paginas, diagnostico: ${dpages:-sem PDF}"
fi

# --- veracidade: o .tex diz a verdade sobre o XML -------------------------------
# Roda no runner (python3 da imagem do Ubuntu, so' biblioteca padrao) sobre o
# MESMO .tex que o xsltproc do gvmd:stable gerou no diagnostico.
if [ -z "$xml" ]; then
  gate falha "veracidade" "sem o XML da fixture (6o argumento do gates.sh)"
elif [ ! -s "$tex" ]; then
  gate falha "veracidade" "sem .tex para checar"
else
  v_rc=0
  python3 -X utf8 "$ci_dir/check-veracity.py" --lang "$lang" --xml "$xml" --tex "$tex" \
    > "$tmpd/veracity" 2>&1 || v_rc=$?
  n_vfail=$(count_lines '^  FALHA ' "$tmpd/veracity")
  if [ "$v_rc" -eq 0 ]; then
    ver_cell=OK
    gate ok "veracidade" "$(count_lines '^  OK ' "$tmpd/veracity") checagens"
    # Cada checagem fica no gates.txt; no log do job, so' o veredito.
    sed 's/^/           | /' "$tmpd/veracity" >> "$report"
  else
    ver_cell="FALHA ($n_vfail)"
    gate falha "veracidade" "exit $v_rc, $n_vfail checagem(ns) reprovada(s):"
    sed -n '1,60p' "$tmpd/veracity" | indent
  fi
fi

if [ "$failures" -eq 0 ]; then verdict=OK; else verdict="FALHA ($failures)"; fi
printf '| %s | %s | %s | %s | %s | %s | %s | %s | %s | %s |\n' \
  "$lang" "$fx" "$verdict" "$pages" "$n_err" "$n_font" "$n_t3" "$links_cell" "$over_cell" "$ver_cell" \
  > "$art/summary.row"
say "VEREDITO $lang/$fx: $verdict"
[ "$failures" -eq 0 ]
