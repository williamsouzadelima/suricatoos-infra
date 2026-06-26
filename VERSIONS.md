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
