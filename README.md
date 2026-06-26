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
