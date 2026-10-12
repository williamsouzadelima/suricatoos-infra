#!/usr/bin/env bash
# Decide se o publish pode mover a tag `stable' da imagem suricatoos-report-formats
# para o commit SRC. Uma funcao so' do historico git; nao fala com o registro.
#
# Por que existe: a producao puxa `suricatoos-report-formats:stable' direto, e o
# feed-updater recria o container quando o ID da imagem muda. Mover `stable' para um
# commit VELHO faz a frota inteira voltar atras no sync seguinte, e o GSA nao mostra
# nada (a VERSION e' um hash: nao tem ordem). O publish dispara por `workflow_run' e
# por disparo manual, e nenhum dos dois garante que SRC e' o commit mais novo: o re-run
# de um CI antigo (por oscilacao do registro, ou para refazer as previas que vencem em
# 14 dias) republica o commit velho; um CI lento termina depois de um mais novo; um
# disparo manual pode vir de qualquer branch.
#
# `stable' so' anda para o commit mais novo da main que toca o relatorio:
#   1. SRC e' ancestral de <main>: um disparo manual de outro branch, um PR ou uma
#      main reescrita nunca movem `stable';
#   2. o RELATORIO de <main> e' IDENTICO ao de SRC: report-formats/ (o contexto do docker
#      build) e os workflows que o constroem e aprovam (report-formats-ci.yml,
#      report-formats-publish.yml) tem o mesmo conteudo nos dois commits
#      (`git diff --quiet SRC <main> -- <esses caminhos>'). A decisao e' EXATA: nao depende
#      da forma da historia (merges, reverts, branch ja' integrado). Commit que so' toca
#      outra coisa (docs, outro componente) nao muda o relatorio, e dois commits que se
#      anulam tambem nao. Se o conteudo difere, a caminhada pela historia
#      (--full-history, o lado conservador nos merges) so' EXPLICA o bloqueio: lista os
#      commits e os arquivos.
# Quando nao anda, o publish empurra so' a tag <sha12>, que ninguem consome. Se o
# commit mais novo do relatorio reprovou no CI, `stable' espera: a proxima correcao que
# passar a move (ou um disparo manual da ponta da main, decisao de quem o aperta).
#
# Uso:  stable-gate.sh <commit> [ref-completo-da-main]
#       (padrao: refs/remotes/origin/main)
# O ref da main tem de ser um nome COMPLETO (refs/...). Git resolve um nome curto como
# `origin/main' na ordem refs/tags/, refs/heads/, refs/remotes/: uma TAG chamada
# `origin/main' num commit velho sombrearia o ref remoto e o portao liberaria o commit
# velho. Por isso o publish busca para um ref explicito
#   git fetch --no-tags origin '+refs/heads/main:refs/remotes/origin/main'
# logo antes de decidir (a decisao ao lado do push LIMITA a corrida com um publish mais
# novo a segundos: "existe um commit mais novo" so' cresce), com historico completo
# (actions/checkout, fetch-depth: 0; o portao so' le commits e arvores, entao um clone sem
# blobs serve).
#
# Saida (stdout, no formato do $GITHUB_ENV, sem caracteres de controle):
#   MOVE_STABLE=true|false
#   STABLE_REASON=<uma linha>
# Sai 0 com a decisao e 2 em erro (commit ou ref desconhecido, ref nao completo, clone
# raso, fora de um repo): o chamador PARA, nao assume nada. Diagnosticos vao para o stderr.
set -euo pipefail

src_arg=${1:?uso: stable-gate.sh <commit> [ref-completo-da-main]}
main_ref=${2:-refs/remotes/origin/main}

# O que, na main, muda a imagem ou o que a aprova.
RELEVANT=(report-formats .github/workflows/report-formats-ci.yml .github/workflows/report-formats-publish.yml)

erro() { echo "stable-gate: $*" >&2; exit 2; }
# A razao vai para o $GITHUB_ENV e para uma anotacao ::warning:: do workflow, e traz assuntos
# de commit: sem caracteres de controle (CR, ESC, tab...), que o runner poderia tratar como
# quebra de linha ou de comando.
decide() {
  local reason
  reason=$(printf '%s' "$2" | tr -d '\000-\037\177') || erro "tr falhou"
  printf 'MOVE_STABLE=%s\nSTABLE_REASON=%s\n' "$1" "$reason"
  exit 0
}

case $main_ref in
  refs/*) ;;
  *) erro "o ref da main tem de ser um nome COMPLETO (refs/...), nao '$main_ref': um nome curto pode ser uma tag que sombreia o ref remoto (git resolve refs/tags/ antes de refs/remotes/)" ;;
esac
root=$(git rev-parse --show-toplevel 2>/dev/null) || erro "fora de um repositorio git"
cd "$root"
[ "$(git rev-parse --is-shallow-repository)" = false ] \
  || erro "clone raso: a ancestralidade nao e' confiavel (actions/checkout com fetch-depth: 0)"
src=$(git rev-parse --verify --quiet "${src_arg}^{commit}") || erro "commit desconhecido: $src_arg"
git show-ref --verify --quiet "$main_ref" \
  || erro "ref desconhecido: $main_ref (git fetch --no-tags origin '+refs/heads/main:refs/remotes/origin/main'; historico completo?)"
tip=$(git rev-parse --verify --quiet "${main_ref}^{commit}") || erro "ref sem commit: $main_ref"
short=$(git rev-parse --short=12 "$src")

rc=0
git merge-base --is-ancestor "$src" "$tip" || rc=$?
case $rc in
  0) ;;
  1) decide false "$short nao e' ancestral de $main_ref (disparo de outro branch ou PR, ou a main foi reescrita)" ;;
  *) erro "git merge-base --is-ancestor saiu $rc" ;;
esac

# A decisao: o relatorio de <main> tem o mesmo conteudo que o de SRC?
rc=0
git diff --quiet "$src" "$tip" -- "${RELEVANT[@]}" || rc=$?
case $rc in
  0)
    ahead=$(git rev-list --count "$src..$tip") || erro "git rev-list falhou"
    if [ "$ahead" -eq 0 ]; then
      decide true "$short e' a ponta de $main_ref"
    fi
    touching=$(git rev-list --count --full-history "$src..$tip" -- "${RELEVANT[@]}") || erro "git rev-list falhou"
    if [ "$touching" -eq 0 ]; then
      decide true "$short e' o commit mais novo de $main_ref que toca o relatorio ($ahead commit(s) depois dele, nenhum toca)"
    fi
    decide true "o relatorio de $main_ref e' identico ao de $short, embora $touching dos $ahead commit(s) depois dele toquem esses caminhos (se anulam, ou ja' estavam em $short)"
    ;;
  1) ;;                                       # difere: o bloqueio e' explicado abaixo
  *) erro "git diff saiu $rc" ;;
esac

# Bloqueado: explica com os commits e os arquivos. Nada daqui decide; so' conta e amostra, sem
# passar a lista inteira por um pipe que feche cedo (um `head' sob pipefail morreria de SIGPIPE).
n=$(git rev-list --count --full-history "$src..$tip" -- "${RELEVANT[@]}") || erro "git rev-list falhou"
nfiles=$(git diff --name-only "$src" "$tip" -- "${RELEVANT[@]}" | wc -l | tr -d ' ') || erro "git diff falhou"
files=$(git diff --name-only "$src" "$tip" -- "${RELEVANT[@]}" | sed -n '1,3p' | awk 'NR > 1 { printf ", " } { printf "%s", $0 }') || erro "git diff falhou"
fextra=""
if [ "$nfiles" -gt 3 ]; then fextra=" (+$((nfiles - 3)))"; fi
if [ "$n" -eq 0 ]; then
  decide false "o relatorio de $main_ref DIFERE do de $short (arquivos: $files$fextra), sem commit que o explique pelo --full-history"
fi
sample=$(git log -n 3 --full-history --format='%h %s' "$src..$tip" -- "${RELEVANT[@]}") || erro "git log falhou"
lista=$(printf '%s\n' "$sample" | cut -c1-90 | sed 's/ *$//' | awk 'NR > 1 { printf " // " } { printf "%s", $0 }')
extra=""
if [ "$n" -gt 3 ]; then extra=" (+$((n - 3)))"; fi
decide false "o relatorio de $main_ref DIFERE do de $short: $n commit(s) depois dele tocam report-formats/ ou os workflows dele ($lista$extra); arquivos: $files$fextra"
