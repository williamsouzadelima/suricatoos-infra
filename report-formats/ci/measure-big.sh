#!/usr/bin/env bash
# Medicao NAO bloqueante do Suricatoos Premium PDF num export GRANDE: o tempo e
# o pico de memoria do `generate` da edicao tecnica e da edicao do cliente,
# na imagem de producao do gvmd, sobre um relatorio sintetico com dezenas de
# milhares de resultados (ci/big-report.py, so' dado inventado). Responde a
# pergunta da revisao da R5: quanto custa a COPIA do relatorio que a edicao
# do cliente faz (exsl:node-set) num export grande. Nao ha limite ainda: so'
# relata, no resumo do job e em <dir-de-saida>/medida.md, e sai 0 sempre (o
# job tambem e' continue-on-error). Um idioma so', para ficar barato.
#
# Uso: measure-big.sh <lang> <dir-de-saida> [opcoes do big-report.py]
set -uo pipefail
# shellcheck source=report-formats/ci/lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

lang=${1:?uso: measure-big.sh <lang> <dir-de-saida> [opcoes do big-report.py]}
out=${2:?uso: measure-big.sh <lang> <dir-de-saida> [opcoes do big-report.py]}
shift 2
mkdir -p "$out"
report="$out/medida.md"

finish() {
  if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    cat "$report" >> "$GITHUB_STEP_SUMMARY"
  fi
  cat "$report"
  exit 0
}

# valor <arquivo de medidas> <chave>
valor() { sed -n "s/^$2=//p" "$1" 2>/dev/null | head -n 1; }
mb() { awk -v k="${1:-0}" 'BEGIN { printf "%.0f MB", k / 1024 }'; }
seg() { awk -v c="${1:-0}" 'BEGIN { printf "%.1f s", c / 100 }'; }

{
  echo "## Medicao de um export grande (nao bloqueante, sem limite)"
  echo
} > "$report"

if ! gvmd_pull > "$out/pull.log" 2>&1; then
  echo "Imagem do gvmd indisponivel: medicao nao feita (veja pull.log)." >> "$report"
  finish
fi
work=$(new_workdir)
if ! stats=$(python3 -X utf8 "$CI_DIR/big-report.py" "$work/big.xml" "$@"); then
  echo "O gerador do relatorio sintetico falhou: medicao nao feita." >> "$report"
  finish
fi
for ed in technical client; do
  if ! stage_bundle "$lang" "$ed" "$work/b-$ed" > /dev/null; then
    echo "stage-bundle falhou para $lang/$ed: medicao nao feita." >> "$report"
    finish
  fi
done
cp "$CI_DIR/measure-run.sh" "$work/"
open_perms "$work"

for ed in technical client; do
  log "medindo $lang/$ed"
  gvmd_run "$work" "/work/b-$ed" /work/measure-run.sh /work/big.xml "/work/$ed.pdf" \
    "/work/$ed.stderr.txt" "/work/$ed.medidas" || log "gvmd_run de $ed saiu $?"
  cp "$work/$ed.medidas" "$work/$ed.stderr.txt" "$out/" 2> /dev/null || true
done

{
  echo "Relatorio sintetico: $stats."
  echo "Imagem: \`$(docker image inspect --format '{{join .RepoDigests ", "}}' "$GVMD_IMAGE" 2>/dev/null)\`;"
  echo "runner: $(nproc) CPU, $(awk '/^MemTotal:/ { printf "%.0f GB", $2 / 1048576 }' /proc/meminfo) de RAM."
  echo "Idioma: \`$lang\`. Pico = VmHWM amostrado a cada 0,05 s (piso, com essa folga)."
  echo
  echo "| edicao | exit do generate | tempo total | xsltproc: tempo / pico RSS | pdflatex (2 passadas): tempo / pico RSS | PDF |"
  echo "|---|---|---|---|---|---|"
  for ed in technical client; do
    m="$work/$ed.medidas"
    if [ ! -s "$m" ]; then
      echo "| $ed | (sem medidas) | | | | |"
      continue
    fi
    pages=$(pdfinfo "$work/$ed.pdf" 2> /dev/null | awk '/^Pages:/ { print $2 }')
    echo "| $ed | $(valor "$m" rc) | $(seg "$(valor "$m" parede_cs)") | $(seg "$(valor "$m" xsltproc_cs)") / $(mb "$(valor "$m" xsltproc_pico_kb)") | $(seg "$(valor "$m" pdflatex_cs)") / $(mb "$(valor "$m" pdflatex_pico_kb)") | ${pages:-?} pag., $(awk -v b="$(valor "$m" pdf_bytes)" 'BEGIN { printf "%.1f MB", b / 1048576 }') |"
  done
  echo
  for ed in technical client; do
    rc=$(valor "$work/$ed.medidas" rc)
    if [ -n "$rc" ] && [ "$rc" != 0 ]; then
      echo "stderr do generate ($ed), primeiras linhas:"
      echo
      echo '```'
      head -n 15 "$work/$ed.stderr.txt" 2> /dev/null
      echo '```'
      echo
    fi
  done
} >> "$report"
finish
