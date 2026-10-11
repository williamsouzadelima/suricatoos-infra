# shellcheck shell=bash
# Funcoes comuns aos scripts de CI do report format (carregado com `.`, nao
# executado). Bash no runner; o que roda DENTRO da imagem do gvmd e' sh POSIX.

# A imagem de PRODUCAO do gvmd: tem xsltproc + texlive, e e' onde o `generate`
# roda de verdade. Sobrescrevivel pelo ambiente (o workflow a define).
: "${GVMD_IMAGE:=registry.community.greenbone.net/community/gvmd:stable}"
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

# stage_bundle <lang> <destino> [--omit ARQ]...  (ver stage-bundle.py)
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
