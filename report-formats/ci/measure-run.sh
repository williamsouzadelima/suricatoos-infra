#!/bin/sh
# Mede UMA execucao do `generate` DENTRO da imagem do gvmd (sh POSIX, uid
# 1001), para a medicao nao bloqueante do CI (measure-big.sh): o tempo de
# parede e o pico de memoria residente (VmHWM, o maximo que o kernel guarda
# por processo) do xsltproc e do pdflatex, com o tempo em que cada um esteve
# vivo.
#
# Uso (cwd = bundle montado pelo stage-bundle.py):
#   sh measure-run.sh <report.xml> <saida.pdf> <saida.stderr> <medidas.txt>
#
# Amostra o /proc do container a cada 0,05 s, so' com comandos internos do sh
# (nenhum processo novo por amostra, alem do sleep): o pico de um processo que
# ainda cresce nos ultimos 50 ms de vida pode escapar, entao o numero e' um
# piso com essa folga. Os tempos vem do /proc/uptime (centesimos de segundo).
# Grava <medidas.txt> com linhas chave=valor e sai 0 sempre: quem le decide.

xml=$1
pdf=$2
err=$3
out=$4

sh ./generate "$xml" > "$pdf" 2> "$err" &
gen=$!
read -r up _ < /proc/uptime
t0=${up%.*}${up#*.}
x_peak=0; x_first=; x_last=
p_peak=0; p_first=; p_last=
samples=0
while kill -0 "$gen" 2>/dev/null; do
  read -r up _ < /proc/uptime
  t=${up%.*}${up#*.}
  samples=$((samples + 1))
  for st in /proc/[0-9]*/status; do
    [ -r "$st" ] || continue
    name=
    hwm=
    # Name e' a 1a linha: de um processo que nao interessa, so' ela e' lida.
    while IFS= read -r l; do
      case $l in
        Name:*)
          name=${l#Name:}
          name=${name#"${name%%[! 	]*}"}
          case $name in xsltproc|pdflatex|pdftex) ;; *) break ;; esac ;;
        VmHWM:*) hwm=${l#VmHWM:}; hwm=${hwm#"${hwm%%[! 	]*}"}; hwm=${hwm%% *}; break ;;
      esac
    done 2>/dev/null < "$st"
    case $name in
      xsltproc)
        if [ -n "$hwm" ] && [ "$hwm" -gt "$x_peak" ]; then x_peak=$hwm; fi
        [ -n "$x_first" ] || x_first=$t
        x_last=$t ;;
      pdflatex|pdftex)
        if [ -n "$hwm" ] && [ "$hwm" -gt "$p_peak" ]; then p_peak=$hwm; fi
        [ -n "$p_first" ] || p_first=$t
        p_last=$t ;;
    esac
  done
  sleep 0.05
done
wait "$gen"
rc=$?
read -r up _ < /proc/uptime
t1=${up%.*}${up#*.}

{
  echo "rc=$rc"
  echo "parede_cs=$((t1 - t0))"
  echo "xsltproc_pico_kb=$x_peak"
  echo "xsltproc_cs=$(( ${x_last:-0} - ${x_first:-0} ))"
  echo "pdflatex_pico_kb=$p_peak"
  echo "pdflatex_cs=$(( ${p_last:-0} - ${p_first:-0} ))"
  echo "amostras=$samples"
  echo "pdf_bytes=$(wc -c < "$pdf" | tr -d ' ')"
} > "$out"
exit 0
