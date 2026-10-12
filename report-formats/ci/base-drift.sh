#!/usr/bin/env bash
# Vigia a DERIVA da BASE do feed: a imagem de que o report-formats/Dockerfile parte
# (registry.community.greenbone.net/community/report-formats), FIXADA por digest no `FROM',
# contra a tag flutuante dela (`latest') de hoje.
#
# O pin existe para o publish nao trocar, sem ninguem pedir, os report formats padrao da
# Greenbone que a imagem leva (nem quebrar no dia em que o layout deles mudar): a imagem so'
# e' construida no publish, depois do merge. O custo e' o inverso: quando a Greenbone atualiza
# a base, nada avisa que o pin ficou para tras, e um digest antigo pode sair do registro (o
# build com um digest que nao existe mais falha). Este script, agendado toda semana
# (.github/workflows/report-formats-base-drift.yml), confere as duas coisas:
#   - o digest fixado ainda baixa? Senao, AVISA: o proximo publish falharia no build;
#   - a tag flutuante de hoje e' o mesmo digest? Igual: sem deriva. Diferente: AVISA, com a
#     data de criacao da base nova. Trocar o pin e' um PR proprio (procedimento no comentario
#     do Dockerfile);
#   - a tag nao baixou, ou o FROM nao e' um digest: avisa que nao deu para comparar.
#
# NAO BLOQUEIA nada: e' agendado e informativo. Sai 0 sempre; o veredito vai para
# <dir-de-saida>/deriva-base.md, para o resumo do job ($GITHUB_STEP_SUMMARY), para o stdout e
# para anotacoes ::warning::.
#
# Uso: base-drift.sh <dir-de-saida>
# Ambiente: DOCKERFILE (padrao: o Dockerfile do relatorio, ao lado de ci/).
set -uo pipefail

CI_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
out=${1:?uso: base-drift.sh <dir-de-saida>}
DOCKERFILE=${DOCKERFILE:-$(dirname "$CI_DIR")/Dockerfile}
mkdir -p "$out"
report="$out/deriva-base.md"
: > "$report"

say() { printf '%s\n' "$*" >> "$report"; }

# Escreve o relatorio no resumo do job e no stdout. Sai 0 sempre: nao bloqueia nada.
finish() {
  if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then cat "$report" >> "$GITHUB_STEP_SUMMARY"; fi
  cat "$report"
  exit 0
}

# pull <ref> <log>: baixa com nova tentativa (o registry da Greenbone oscila). Sempre vai ao
# registro: o que se quer saber e' o que ele serve hoje, nao o que o runner tem.
pull() {
  local i
  for i in 1 2 3; do
    if docker pull --quiet "$1" >> "$2" 2>&1; then return 0; fi
    if [ "$i" -lt 3 ]; then
      echo "docker pull $1 falhou (tentativa $i/3); nova tentativa em 20 s" >> "$2"
      sleep 20
    fi
  done
  return 1
}

say "## Base do feed (report-formats/Dockerfile) x tag de hoje"
say ""

# O FROM: exatamente um, sem opcoes (--platform...), so' com os caracteres de uma referencia de
# imagem (o texto vai para o resumo e para anotacoes de workflow).
n=0
ref=""
if [ -f "$DOCKERFILE" ]; then
  read -r n ref < <(awk '/^FROM[ \t]/ { n++; ref = $2 } END { print n + 0, ref }' "$DOCKERFILE") || true
fi
if [ "${n:-0}" -ne 1 ] || ! [[ "${ref:-}" =~ ^[A-Za-z0-9][A-Za-z0-9._:/@-]*$ ]]; then
  say "**Sem como comparar:** o Dockerfile do feed tem de ter exatamente um \`FROM <imagem>\` simples (achei ${n:-0}; referencia \`${ref:-vazia}\`)."
  echo "::warning::O Dockerfile do report-formats nao tem exatamente um FROM simples: nada a comparar com a base de hoje."
  finish
fi
if ! [[ "$ref" =~ ^(.+)@(sha256:[0-9a-f]{64})$ ]]; then
  say "**Sem como comparar:** a base do Dockerfile (\`$ref\`) nao esta' fixada por digest."
  echo "::warning::A base do report-formats/Dockerfile nao esta' fixada por digest: nada a comparar com a tag de hoje."
  finish
fi
name_tag=${BASH_REMATCH[1]}
pin_digest=${BASH_REMATCH[2]}
last=${name_tag##*/}                        # a tag e' o que vem depois do ultimo `:' do ULTIMO componente
if [[ "$last" == *:* ]]; then
  tag=${last##*:}
  name=${name_tag%:*}
else
  tag=latest
  name=$name_tag
fi
floating="$name:$tag"
pinned="$name@$pin_digest"

# 1. O digest fixado ainda existe no registro?
pin_ok=true
pull "$pinned" "$out/pull-fixada.log" || pin_ok=false
pin_created=""
if $pin_ok; then pin_created=$(docker image inspect --format '{{.Created}}' "$pinned" 2>/dev/null || true); fi

# 2. O que a tag flutuante serve hoje?
float_ok=true
pull "$floating" "$out/pull-tag.log" || float_ok=false
float_digest=""
float_created=""
if $float_ok; then
  float_ref=$(docker image inspect --format '{{index .RepoDigests 0}}' "$floating" 2>/dev/null || true)
  float_digest=${float_ref##*@}
  float_created=$(docker image inspect --format '{{.Created}}' "$floating" 2>/dev/null || true)
fi

say "| | digest | criada em |"
say "|---|---|---|"
say "| fixada no \`Dockerfile\` | \`$pin_digest\` | ${pin_created:-?} |"
if [[ "$float_digest" =~ ^sha256:[0-9a-f]{64}$ ]]; then
  say "| \`$floating\` hoje | \`$float_digest\` | ${float_created:-?} |"
fi
say ""

if ! $pin_ok; then
  echo "::warning::A base fixada no report-formats/Dockerfile ($pin_digest) nao baixa mais de $name: o proximo publish vai falhar no build."
  say "**O DIGEST FIXADO NAO BAIXA:** \`$pinned\` nao veio do registro (veja \`pull-fixada.log\` no artefato). Se ele saiu do registro, o proximo publish falha no \`FROM\`: troque o pin por um digest que exista (procedimento no comentario do \`Dockerfile\`), num PR proprio."
  say ""
fi

if ! $float_ok; then
  say "**Sem como comparar:** nao consegui baixar \`$floating\` (veja \`pull-tag.log\` no artefato). Tenta de novo na proxima semana, ou dispare o workflow a mao."
  echo "::warning::Nao consegui baixar $floating para comparar com a base fixada."
  finish
fi
if ! [[ "$float_digest" =~ ^sha256:[0-9a-f]{64}$ ]]; then
  say "**Sem como comparar:** \`$floating\` baixou, mas nao consegui ler o digest dela (\`${float_ref:-vazio}\`)."
  echo "::warning::Nao consegui ler o digest de $floating para comparar com a base fixada."
  finish
fi

if [ "$float_digest" = "$pin_digest" ]; then
  say "**Sem deriva:** \`$floating\` de hoje e' a base fixada."
  finish
fi

echo "::warning::A base do feed ($floating, $float_digest, criada em ${float_created:-?}) nao e' mais a fixada no report-formats/Dockerfile ($pin_digest): o proximo publish segue na base fixada ate' o pin ser trocado."
say "**DERIVA:** \`$floating\` ja' nao e' a base fixada no \`Dockerfile\`. O feed publicado segue na base fixada ate' alguem trocar o pin; a base nova so' entra por um PR proprio, que o publish constroi depois do merge (procedimento e comandos no comentario do \`Dockerfile\`)."
finish
