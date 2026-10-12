# Suricatoos — Pinned Versions

Fork rebrandeado dos **Greenbone Community Containers** (GVM/OpenVAS).
Os feeds permanecem **Greenbone** por decisao de projeto.

## Imagens de aplicacao (rebuildadas do fonte -> suricatoos/*)
| Componente | Repo upstream | Tag | Revision |
|---|---|---|---|
| gsa  | github.com/greenbone/gsa  | v27.4.1 | c9ffa084376c325496c11f929dd03ac077843c6c |
| gsad | github.com/greenbone/gsad | v26.4.0 | ca36fcbd017f95dc4ee8706519f4c43be7fc0682 |

## Imagens reusadas upstream (registry.community.greenbone.net/community)
gvmd:stable (tag flutuante: a producao puxa o que ela apontar; 26.31.1 era a versao em 2026-06-26,
ver "CI do relatorio" abaixo), openvas-scanner:stable, ospd-openvas:stable, pg-gvm:stable,
pg-gvm-migrator:stable, redis-server, nginx:latest, gvm-config:latest, gvm-tools,
gvm-libs:stable (base de build do gsad)

## CI do relatorio (report-formats) — gvmd fixado por digest
O CI e a medicao do Suricatoos Premium PDF rodam na imagem do gvmd FIXADA por digest em
`report-formats/ci/lib.sh` (a tag `stable` muda sozinha). Origem `gvmd:stable`, resolvida em
2026-10-12 (gvmd v26.41.0):
`registry.community.greenbone.net/community/gvmd@sha256:94f00ed57c93163756f5c84bd79db5e3de96706be8c051ae201e5c35ffddcfd3`.
Como atualizar: o comentario de `report-formats/ci/lib.sh`. A deriva em relacao a `stable` (a que a
producao puxa) e' vigiada toda semana, sem bloquear, por `.github/workflows/report-formats-gvmd-stable.yml`.

## Feed do relatorio (report-formats/Dockerfile) — base fixada por digest
A imagem `suricatoos-report-formats` parte de `report-formats:latest` da Greenbone FIXADA por digest no
`FROM` de `report-formats/Dockerfile` (a tag flutuante troca os report formats padrao por baixo do publish).
Origem `registry.community.greenbone.net/community/report-formats:latest`, resolvida em 2026-10-12:
`...@sha256:031c67736795d3766731aa89946866cbb0aebba5878cb4df8b989fbc13022198`. Como atualizar: o comentario do
`Dockerfile`. A deriva (a `latest` andou, ou o digest fixado saiu do registro) e' vigiada toda semana, sem
bloquear, por `.github/workflows/report-formats-base-drift.yml`.

## Feed (Greenbone, NAO forkado) — FEED_RELEASE=24.10
vulnerability-tests, notus-data, scap-data, cert-bund-data, dfn-cert-data,
data-objects, report-formats, gpg-data

## Imagens publicadas (GHCR)

| Imagem | Tags |
|---|---|
| `ghcr.io/williamsouzadelima/suricatoos-gsa`  | `stable`, `v27.4.1` |
| `ghcr.io/williamsouzadelima/suricatoos-gsad` | `stable`, `v26.4.0` |

Para usar as imagens do GHCR em vez de buildar local, no `compose/docker-compose.override.yml`:
```yaml
  gsa:
    image: ghcr.io/williamsouzadelima/suricatoos-gsa:stable
  gsad:
    image: ghcr.io/williamsouzadelima/suricatoos-gsad:stable
```
(os packages precisam estar publicos, ou o puller autenticado no ghcr.io)
