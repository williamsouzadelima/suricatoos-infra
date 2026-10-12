#!/usr/bin/env bash
# Vigia a DERIVA entre o gvmd FIXADO do CI (ci/lib.sh, por digest) e a `stable' que a
# producao puxa.
#
# A producao roda registry.community.greenbone.net/community/gvmd:stable
# (compose/compose.yaml) e o CI roda uma versao fixada por digest, para os portoes nao
# mudarem sob um PR. O custo e' o inverso: quando a `stable' anda (andou duas vezes em
# 12/10/2026), o CI deixa de testar o gvmd da producao, e nada avisava. Este script,
# agendado toda semana (.github/workflows/report-formats-gvmd-stable.yml), resolve a
# `stable' de hoje e compara com o pin:
#   - mesmo digest: sem deriva; nao compila (o CI de cada PR ja' e' esse teste);
#   - digest diferente: AVISA (a `stable' mudou, com a versao do gvmd) e compila UMA
#     combinacao (en/technical por padrao: todas as fixtures e todos os portoes do
#     compile.sh) na `stable' de hoje, e diz no resumo se passou ou reprovou. Reprovar
#     aqui quer dizer que o relatorio pode quebrar quando a producao puxar a imagem nova;
#   - a `stable' nao baixou ou o pin nao e' um digest: avisa que nao deu para comparar.
#
# NAO BLOQUEIA nada: e' agendado e informativo. Sai 0 sempre; o veredito vai para
# <dir-de-saida>/deriva.md, para o resumo do job ($GITHUB_STEP_SUMMARY), para o stdout
# e para anotacoes ::warning::. Atualizar o pin e' um PR proprio (procedimento no
# comentario de ci/lib.sh).
#
# Uso: gvmd-drift.sh <dir-de-saida>
# Ambiente: STABLE_IMAGE (padrao: a `stable' do registro da Greenbone),
#           DRIFT_LANG / DRIFT_VARIANT (padrao: en technical).
set -uo pipefail

CI_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
out=${1:?uso: gvmd-drift.sh <dir-de-saida>}
mkdir -p "$out"
STABLE_IMAGE=${STABLE_IMAGE:-registry.community.greenbone.net/community/gvmd:stable}
lang=${DRIFT_LANG:-en}
variant=${DRIFT_VARIANT:-technical}
report="$out/deriva.md"
: > "$report"

say() { printf '%s\n' "$*" >> "$report"; }

# Escreve o relatorio no resumo do job e no stdout. Sai 0 sempre: nao bloqueia nada.
finish() {
  if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then cat "$report" >> "$GITHUB_STEP_SUMMARY"; fi
  cat "$report"
  exit 0
}

say "## gvmd:stable x gvmd fixado (CI do relatorio)"
say ""

# O pin: o padrao de lib.sh, lido com GVMD_IMAGE FORA do ambiente (um GVMD_IMAGE herdado
# esconderia o pin e a comparacao seria da stable com ela mesma).
pin=$(env -u GVMD_IMAGE bash -c '. "$1" && printf %s "$GVMD_IMAGE"' _ "$CI_DIR/lib.sh") || pin=""
if ! [[ "$pin" =~ @sha256:[0-9a-f]{64}$ ]]; then
  say "**Sem como comparar:** o gvmd de \`ci/lib.sh\` nao esta' fixado por digest (\`${pin:-vazio}\`)."
  echo "::warning::O gvmd de report-formats/ci/lib.sh nao esta' fixado por digest: nada a comparar com a stable."
  finish
fi
pin_digest=${pin##*@}

export GVMD_IMAGE="$STABLE_IMAGE"
# shellcheck source=report-formats/ci/lib.sh
. "$CI_DIR/lib.sh"
if ! gvmd_pull > "$out/pull.log" 2>&1; then
  say "**Sem como comparar:** nao consegui baixar \`$STABLE_IMAGE\` (veja \`pull.log\` no artefato). Tenta de novo na proxima semana, ou dispare o workflow a mao."
  echo "::warning::Nao consegui baixar a gvmd:stable para comparar com o gvmd fixado."
  finish
fi

stable_ref=$(docker image inspect --format '{{index .RepoDigests 0}}' "$STABLE_IMAGE" 2>/dev/null || true)
stable_digest=${stable_ref##*@}
version=$(docker image inspect --format '{{index .Config.Labels "org.opencontainers.image.version"}}' "$STABLE_IMAGE" 2>/dev/null || true)
created=$(docker image inspect --format '{{.Created}}' "$STABLE_IMAGE" 2>/dev/null || true)
if ! [[ "$stable_digest" =~ ^sha256:[0-9a-f]{64}$ ]]; then
  say "**Sem como comparar:** a \`$STABLE_IMAGE\` baixou, mas nao consegui ler o digest dela (\`${stable_ref:-vazio}\`)."
  echo "::warning::Nao consegui ler o digest da gvmd:stable para comparar com o gvmd fixado."
  finish
fi

say "| | digest | gvmd |"
say "|---|---|---|"
say "| fixado em \`ci/lib.sh\` | \`$pin_digest\` | veja o comentario de \`ci/lib.sh\` |"
say "| \`$STABLE_IMAGE\` hoje | \`$stable_digest\` | \`${version:-?}\` (criada em ${created:-?}) |"
say ""

if [ "$stable_digest" = "$pin_digest" ]; then
  say "**Sem deriva:** a \`stable\` de hoje e' a imagem fixada. Nada a comparar: o CI de cada PR ja' compila nela."
  finish
fi

echo "::warning::A gvmd:stable (${version:-?}, $stable_digest) nao e' mais o gvmd fixado no CI do relatorio ($pin_digest): o CI deixou de testar o gvmd da producao."
say "**DERIVA:** a \`stable\` que a producao puxa (\`${version:-?}\`) ja' nao e' a imagem em que o CI do relatorio compila: o CI deixou de testar o gvmd da producao. Compilando \`$lang/$variant\` (todas as fixtures e portoes) na \`stable\` de hoje..."
say ""

rc=0
GVMD_IMAGE="$STABLE_IMAGE" "$CI_DIR/compile.sh" "$lang" "$variant" "$out/artefatos" > "$out/compile.log" 2>&1 || rc=$?

if [ "$rc" -eq 0 ]; then
  say "**A compilacao passou** na \`stable\` de hoje: o relatorio nao quebra com a imagem nova. Para o CI voltar a testar o gvmd da producao, atualize o pin (procedimento no comentario de \`report-formats/ci/lib.sh\`), num PR proprio."
else
  echo "::warning::A compilacao do relatorio ($lang/$variant) REPROVOU na gvmd:stable de hoje (exit $rc): a producao pode quebrar ao puxar a imagem nova."
  say "**A COMPILACAO REPROVOU** na \`stable\` de hoje (exit $rc): o relatorio pode quebrar quando a producao puxar a imagem nova. As ultimas linhas do log (\`compile.log\`, e os portoes em \`artefatos/\`, no artefato do job):"
  say ""
  say '```'
  tail -n 25 "$out/compile.log" >> "$report"
  say '```'
fi
finish
