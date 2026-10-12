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
#   2. nenhum commit de <main> DEPOIS de SRC toca o relatorio: report-formats/ (o
#      contexto do docker build) ou os workflows que o constroem e aprovam
#      (report-formats-ci.yml, report-formats-publish.yml). Commit que so' toca outra
#      coisa (docs, outro componente) nao importa: o relatorio e' o mesmo. Merges
#      entram pelo --full-history, o lado conservador.
# Quando nao anda, o publish empurra so' a tag <sha12>, que ninguem consome. Se o
# commit mais novo do relatorio reprovou no CI, `stable' espera: a proxima correcao que
# passar a move (ou um disparo manual da ponta da main, decisao de quem o aperta).
#
# Uso:  stable-gate.sh <commit> [ref-da-main]     (padrao: origin/main)
# Rode `git fetch origin main' antes (o publish o faz logo antes de empurrar: "existe um
# commit mais novo" so' cresce, entao decidir na hora do push fecha a corrida com um
# publish mais novo) e com historico completo (actions/checkout, fetch-depth: 0).
#
# Saida (stdout, no formato do $GITHUB_ENV):
#   MOVE_STABLE=true|false
#   STABLE_REASON=<uma linha>
# Sai 0 com a decisao e 2 em erro (commit ou ref desconhecido, clone raso, fora de um
# repo): o chamador PARA, nao assume nada. Diagnosticos vao para o stderr.
set -euo pipefail

src_arg=${1:?uso: stable-gate.sh <commit> [ref-da-main]}
main_ref=${2:-origin/main}

# O que, na main, muda a imagem ou o que a aprova.
RELEVANT=(report-formats .github/workflows/report-formats-ci.yml .github/workflows/report-formats-publish.yml)

erro() { echo "stable-gate: $*" >&2; exit 2; }
decide() { printf 'MOVE_STABLE=%s\nSTABLE_REASON=%s\n' "$1" "$2"; exit 0; }

root=$(git rev-parse --show-toplevel 2>/dev/null) || erro "fora de um repositorio git"
cd "$root"
[ "$(git rev-parse --is-shallow-repository)" = false ] \
  || erro "clone raso: a ancestralidade nao e' confiavel (actions/checkout com fetch-depth: 0)"
src=$(git rev-parse --verify --quiet "${src_arg}^{commit}") || erro "commit desconhecido: $src_arg"
tip=$(git rev-parse --verify --quiet "${main_ref}^{commit}") \
  || erro "ref desconhecido: $main_ref (git fetch origin main; historico completo?)"
short=$(git rev-parse --short=12 "$src")

rc=0
git merge-base --is-ancestor "$src" "$tip" || rc=$?
case $rc in
  0) ;;
  1) decide false "$short nao e' ancestral de $main_ref (disparo de outro branch ou PR, ou a main foi reescrita)" ;;
  *) erro "git merge-base --is-ancestor saiu $rc" ;;
esac

newer=$(git log --full-history --format='%h %s' "$src..$tip" -- "${RELEVANT[@]}")
if [ -n "$newer" ]; then
  n=$(printf '%s\n' "$newer" | wc -l | tr -d ' ')
  lista=$(printf '%s\n' "$newer" | head -n 3 | cut -c1-90 | sed 's/ *$//' | awk 'NR > 1 { printf " // " } { printf "%s", $0 }')
  extra=""
  if [ "$n" -gt 3 ]; then extra=" (+$((n - 3)))"; fi
  decide false "a $main_ref tem $n commit(s) depois de $short que tocam o relatorio (report-formats/ ou os workflows dele): $lista$extra"
fi

ahead=$(git rev-list --count "$src..$tip")
if [ "$ahead" -eq 0 ]; then
  decide true "$short e' a ponta de $main_ref"
fi
decide true "$short e' o commit mais novo de $main_ref que toca o relatorio ($ahead commit(s) depois dele, nenhum toca)"
