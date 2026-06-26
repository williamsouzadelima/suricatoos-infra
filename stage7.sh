#!/bin/bash
set -e
ROOT=/root/suricatoos
cd "$ROOT"
mkdir -p patches

# --- patches (incluir novo arquivo theme css no diff) ---
cd "$ROOT/src/gsa"
git add -N public/suricatoos-theme.css 2>/dev/null || true
git diff > "$ROOT/patches/gsa-v27.4.1.patch"
cd "$ROOT/src/gsad"
git diff > "$ROOT/patches/gsad-v26.4.0.patch"
echo "patches:"; wc -l "$ROOT/patches/"*.patch

# --- VERSIONS.md ---
cat > "$ROOT/VERSIONS.md" <<'EOF'
# Suricatoos — Pinned Versions

Fork rebrandeado dos **Greenbone Community Containers** (GVM/OpenVAS).
Os feeds permanecem **Greenbone** por decisao de projeto.

## Imagens de aplicacao (rebuildadas do fonte -> suricatoos/*)
| Componente | Repo upstream | Tag | Revision |
|---|---|---|---|
| gsa  | github.com/greenbone/gsa  | v27.4.1 | c9ffa084376c325496c11f929dd03ac077843c6c |
| gsad | github.com/greenbone/gsad | v26.4.0 | ca36fcbd017f95dc4ee8706519f4c43be7fc0682 |

## Imagens reusadas upstream (registry.community.greenbone.net/community)
gvmd:stable (26.31.1), openvas-scanner:stable, ospd-openvas:stable, pg-gvm:stable,
pg-gvm-migrator:stable, redis-server, nginx:latest, gvm-config:latest, gvm-tools,
gvm-libs:stable (base de build do gsad)

## Feed (Greenbone, NAO forkado) — FEED_RELEASE=24.10
vulnerability-tests, notus-data, scap-data, cert-bund-data, dfn-cert-data,
data-objects, report-formats, gpg-data
EOF

# --- README / runbook ---
cat > "$ROOT/README.md" <<'EOF'
# Suricatoos — Fork dos Greenbone Community Containers

Rebrand do stack GVM/OpenVAS (Community Edition 22.4) como **Suricatoos**.
Apenas a aplicacao web (gsa) e o daemon (gsad) sao forkados/rebrandeados;
todo o resto e upstream Greenbone, e os 8 containers de feed permanecem Greenbone.

## Estrutura
- compose/compose.yaml                  compose canonico Greenbone (pinado)
- compose/docker-compose.override.yml   aponta gsa/gsad p/ imagens suricatoos + env do vendor
- assets/                               SVGs de marca Suricatoos + suricatoos-theme.css
- patches/gsa-v27.4.1.patch             mudancas de codigo do gsa
- patches/gsad-v26.4.0.patch            mudancas de codigo do gsad
- VERSIONS.md                           versoes pinadas

## Reproduzir do zero
1. git clone --branch v27.4.1 https://github.com/greenbone/gsa.git  src/gsa
   git clone --branch v26.4.0 https://github.com/greenbone/gsad.git src/gsad
2. (cd src/gsa  && git apply ../../patches/gsa-v27.4.1.patch)
   (cd src/gsad && git apply ../../patches/gsad-v26.4.0.patch)
3. docker build -f src/gsad/.docker/prod.Dockerfile -t suricatoos/gsad:stable src/gsad
   docker build -f src/gsa/.docker/prod.Dockerfile --build-arg BASE_IMAGE=suricatoos/gsad:stable -t suricatoos/gsa:stable src/gsa
4. (cd compose && docker compose up -d)
5. senha admin: docker compose exec -u gvmd gvmd gvmd --user=admin --new-password=SENHA

## Branding (resumo)
- Logo header: mark do suricato (icon/svg/greenbone.svg + Greenbone_white_logo.svg), size 38px
- Login: wordmark navy; favicon/splash: mark; decoracoes de fundo vazias
- Tema: green Greenbone -> teal #0aa4a6 (Theme.tsx) + override Mantine green->teal (suricatoos-theme.css)
- Footer/titulo/versao: via Footer.tsx + env GSA_VENDOR_TITLE/GSA_VENDOR_VERSION

## Upgrade (nova release GVM)
Re-clonar gsa/gsad nas novas tags stable correspondentes, re-aplicar os patches
(resolver conflitos), rebuildar e re-pinar o compose na mesma faixa de feed.
EOF

# --- git init + commit (ignorar src/ clones e logs) ---
cd "$ROOT"
cat > .gitignore <<'EOF'
src/
*.log
EOF
if [ ! -d .git ]; then git init -q; fi
git add -A
git -c user.email=fork@suricatoos.com -c user.name=Suricatoos commit -q -m "Suricatoos fork: rebrand gsa v27.4.1 + gsad v26.4.0, feeds Greenbone (24.10)" || echo "(nada a commitar / ja commitado)"
echo "=== git log ==="; git --no-pager log --oneline -1
echo "=== arvore do repo do fork ==="; git --no-pager ls-files | head -40
