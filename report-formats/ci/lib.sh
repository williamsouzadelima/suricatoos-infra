# shellcheck shell=bash
# Funcoes comuns aos scripts de CI do report format (carregado com `.`, nao
# executado). Bash no runner; o que roda DENTRO da imagem do gvmd e' sh POSIX.

# A imagem de PRODUCAO do gvmd: tem xsltproc + texlive, e e' onde o `generate`
# roda de verdade. FIXADA por DIGEST, aqui e so' aqui (o CI de relatorio e a
# medicao a herdam; o workflow nao a repete): a tag `stable' muda sozinha --
# em 12/10/2026 andou de sha256:fec60184... para sha256:94f00ed5... entre dois
# runs do CI no mesmo dia --, e uma imagem que muda sob o CI faz um portao
# reprovar (ou passar) sem que nada do repo tenha mudado.
#
#   origem:    registry.community.greenbone.net/community/gvmd:stable
#   resolvida: 2026-10-12 -> gvmd v26.41.0 (imagem criada em 2026-10-12T07:11Z,
#              revisao 02a05165 do greenbone/gvmd); indice OCI linux/amd64 +
#              linux/arm64 (os runners sao amd64). E' a imagem em que o CI da R5
#              passou (runs de 931635e e ba4b5cf, em 2026-10-12).
#
# Para ATUALIZAR (imagem nova e' mudanca deliberada, num PR proprio):
#   1. resolva o digest que a `stable' tem agora. Com docker:
#        docker pull registry.community.greenbone.net/community/gvmd:stable
#        docker image inspect --format '{{index .RepoDigests 0}}' \
#          registry.community.greenbone.net/community/gvmd:stable
#      Sem docker (token anonimo + HEAD do manifesto; o digest vem em
#      Docker-Content-Digest):
#        T=$(curl -s 'https://registry.community.greenbone.net/service/token?service=harbor-registry&scope=repository:community/gvmd:pull' | python3 -c 'import sys,json; print(json.load(sys.stdin)["token"])')
#        curl -sI -H "Authorization: Bearer $T" -H 'Accept: application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json' \
#          https://registry.community.greenbone.net/v2/community/gvmd/manifests/stable | grep -i docker-content-digest
#   2. troque o digest abaixo e a data/versao/revisao deste comentario
#      (a versao: label org.opencontainers.image.version da imagem);
#   3. abra o PR: o CI roda todos os portoes na imagem nova. Reprovou? e' a imagem
#      nova que mudou algo (xsltproc, texlive, poppler?): conserte o relatorio ou
#      adie a troca -- nao fixe de novo sem entender.
# Para experimentar a `stable' de hoje sem mexer na fixacao, defina GVMD_IMAGE no
# ambiente (ele vence o valor padrao daqui).
# A deriva em relacao a `stable' -- a que a producao puxa (compose/compose.yaml) -- e'
# vigiada toda semana por .github/workflows/report-formats-gvmd-stable.yml
# (ci/gvmd-drift.sh): avisa no resumo quando o digest da `stable' difere deste e compila
# uma combinacao nela, dizendo se passou. Nao bloqueia nada.
: "${GVMD_IMAGE:=registry.community.greenbone.net/community/gvmd@sha256:94f00ed57c93163756f5c84bd79db5e3de96706be8c051ae201e5c35ffddcfd3}"
# O gvmd chama o `generate` como o usuario gvmd, uid 1001, NAO root.
GVMD_UID=1001

CI_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
RF_DIR=$(dirname "$CI_DIR")                       # report-formats/
BUNDLE_SRC="$RF_DIR/suricatoos-premium-pdf"

log() { printf '[%s] %s\n' "$(date -u +%H:%M:%S)" "$*"; }

# Baixa a imagem (com nova tentativa: o registry da Greenbone oscila) e diz
# qual digest foi usado, para o resultado ser rastreavel.
gvmd_pull() {
  local i
  if ! docker image inspect "$GVMD_IMAGE" >/dev/null 2>&1; then
    for i in 1 2 3; do
      if docker pull --quiet "$GVMD_IMAGE"; then break; fi
      if [ "$i" -eq 3 ]; then
        log "ERRO: nao consegui baixar $GVMD_IMAGE"
        return 1
      fi
      log "docker pull falhou (tentativa $i/3); nova tentativa em 20 s"
      sleep 20
    done
  fi
  log "imagem: $GVMD_IMAGE"
  log "digest: $(docker image inspect --format '{{join .RepoDigests ", "}}' "$GVMD_IMAGE")"
}

# gvmd_run <dir-de-trabalho> <cwd-no-container> <args do /bin/sh>...
# Roda `/bin/sh <args>` na imagem do gvmd como uid 1001, sem rede (o container
# de producao nao tem), com HOME=/nonexistent (como o usuario gvmd) e com
# <dir-de-trabalho> montado em /work. Sem -t: stdout e stderr do comando passam
# separados e intactos (bytes de PDF inclusive). Devolve o exit do comando
# (125-127 = falha do proprio docker, nao do comando).
gvmd_run() {
  local work=$1 cwd=$2
  shift 2
  docker run --rm --network none --user "$GVMD_UID:$GVMD_UID" \
    -e HOME=/nonexistent -v "$work:/work" -w "$cwd" \
    --entrypoint /bin/sh "$GVMD_IMAGE" "$@"
}

# stage_bundle <lang> <variant> <destino> [--omit ARQ]...  (ver stage-bundle.py)
stage_bundle() {
  python3 -X utf8 "$CI_DIR/stage-bundle.py" "$@"
}

# Diretorio de trabalho montado no container: tem de ser gravavel pelo uid
# 1001 seja qual for o uid do runner.
new_workdir() {
  local w
  w=$(mktemp -d "${RUNNER_TEMP:-/tmp}/rf-ci.XXXXXX")
  chmod 0777 "$w"
  printf '%s\n' "$w"
}

# Abre a permissao de tudo que foi preparado no host antes de montar.
open_perms() {
  chmod -R a+rwX "$1"
}
