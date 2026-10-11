#!/bin/sh
# Compilacao de DIAGNOSTICO do Suricatoos Premium PDF, DENTRO da imagem do gvmd.
#
# Os mesmos passos e parametros do `generate` (xsltproc com o idioma lido do
# PROPRIO generate; duas passadas do pdflatex em batchmode, em foreground; os
# mesmos TEXINPUTS/TEXMFHOME/TEXMFVAR/HOME), mas SEM julgar nada e guardando
# .tex, .log e .pdf para os portoes (gates.sh) -- o generate apaga o temporario
# e, de proposito, nao entrega nada quando falha.
#
# Uso (cwd = bundle montado pelo stage-bundle.py; sh POSIX, uid 1001):
#   sh diag-compile.sh <report.xml> <dir-de-saida>
#
# Grava em <dir-de-saida>: report.tex, report.log (2a passada),
# report.pass1.log, report.pdf, xsltproc.stderr, xsltproc.rc, pdflatex.rc
# ("<exit 1a> <exit 2a>") e lang.
set -eu

xml=$1
out=$2

lang=$(sed -n 's/^xsltproc --stringparam lang \([A-Za-z_]*\) .*/\1/p' ./generate)
if [ -z "${lang}" ]; then
  echo "diag-compile: linha do xsltproc com o idioma nao encontrada no ./generate" >&2
  exit 2
fi

mkdir -p "${out}"
work=$(mktemp -d)
trap 'rm -rf "${work}"' EXIT

# Como no generate: logos e .sty ao lado do .tex (que e' o -output-directory),
# e a arvore IBM Plex em TEXMFHOME, com HOME/TEXMFVAR dentro do temporario.
cp ./suricatoos-*.pdf ./*.sty "${out}/"
mkdir -p "${work}/texmf" "${work}/tv"
tar xzf ./plex-min.tar.gz -C "${work}/texmf"
TEXINPUTS="${out}:"; export TEXINPUTS
TEXMFHOME="${work}/texmf"; export TEXMFHOME
TEXMFVAR="${work}/tv"; export TEXMFVAR
HOME="${work}"; export HOME

echo "${lang}" > "${out}/lang"
rc=0
xsltproc --stringparam lang "${lang}" ./latex.xsl "${xml}" > "${out}/report.tex" 2> "${out}/xsltproc.stderr" || rc=$?
echo "${rc}" > "${out}/xsltproc.rc"
if [ "${rc}" -ne 0 ]; then
  # Sem .tex completo nao ha o que compilar; o gates.sh reporta o xsltproc.
  echo "- -" > "${out}/pdflatex.rc"
  exit 0
fi

rc1=0
pdflatex -interaction batchmode -output-directory "${out}" "${out}/report.tex" > /dev/null 2>&1 || rc1=$?
if [ -f "${out}/report.log" ]; then
  cp "${out}/report.log" "${out}/report.pass1.log"
fi
rm -f "${out}/report.pdf"
rc2=0
pdflatex -interaction batchmode -output-directory "${out}" "${out}/report.tex" > /dev/null 2>&1 || rc2=$?
echo "${rc1} ${rc2}" > "${out}/pdflatex.rc"
exit 0
