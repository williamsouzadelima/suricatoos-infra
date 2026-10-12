# Suricatoos report-formats feed image.
#
# Forks the upstream Greenbone community report-formats feed image (the same
# pattern used for gsa/gsad) and adds the "Suricatoos Premium PDF" report format
# to the feed source.  Because the format is delivered via the feed path, gvmd
# installs it as predefined=1, trust=1 — it appears automatically in the GSA
# "Download report" format dropdown with NO frontend change and NO GPG signing.
#
# The upstream image ships one report-formats source directory per feed release
# under ${STORAGE_PATH} (e.g. .../gvmd/24.10/report-formats/); its /bin/init.sh
# copies ${STORAGE_PATH}/${FEED_RELEASE}/* into the shared data-objects volume
# that gvmd syncs.  We drop our combined feed object into every release dir so
# the format installs regardless of the configured FEED_RELEASE.  All stock
# formats are left untouched (this image is purely additive).
#
# The report ships as NINE objects -- three editions (technical, client,
# executive) in three languages (EN / PT-BR / ES) --, one feed XML each
# (pdf-suricatoos-<uuid>.xml), so all nine appear in the GSA "Download report"
# dropdown and the user picks edition and language there. manifest.json maps
# (format, lang, variant) to each UUID for the fleet connector.
#
# The nine feed XMLs are BUILD OUTPUTS, not versioned (.gitignore): the CI and the
# publish workflow run build-feed-xml.py before `docker build`. manifest.json is the
# only generated file that stays in the repo (the fleet connector reads it).
#
# THE GUARD is the RUN below, which requires exactly nine objects. The COPY is not one:
# under BuildKit (the default `docker build`) a COPY whose wildcard matches nothing does
# NOT fail (AllowEmptyWildcard), so a missing build step only shows up in that RUN. Keep
# the 9 in sync with FORMATS in build-feed-xml.py (tests/test_feed.py checks both the
# number and that the RUN refuses 0, 8 and 10 objects). The count cannot tell a STALE
# set from a fresh one: ignored XMLs survive a branch switch, so a local `docker build`
# without a `python3 build-feed-xml.py` right before it packs the objects of the previous
# branch. The CI and the publish are safe: a clean checkout, the build, and
# ci/check-manifest.py, which compares every object with the bundle byte for byte.
#
# Build:
#   python3 build-feed-xml.py   # GENERATE the nine embedded XMLs (and manifest.json)
#   docker build -t ghcr.io/williamsouzadelima/suricatoos-report-formats:stable \
#       report-formats
#
# THE BASE IS PINNED BY DIGEST (the FROM below, and only there). Its floating tag, `latest' --
# the only one Greenbone publishes for this image --, moves whenever they refresh the stock
# report formats, so two builds of the same commit could ship different stock formats, and an
# upstream layout change would break the publish (the only place this image is built) instead
# of a reviewed pull request. The pin is the digest of the multi-arch manifest list (linux/amd64
# and linux/arm64), which is what `docker pull' reports in RepoDigests.
#
#   origin:    registry.community.greenbone.net/community/report-formats:latest
#   resolved:  2026-10-12 (image created 2026-10-12T05:10Z)
#
# To UPDATE (a pull request of its own: a new base is a deliberate change):
#   1. resolve the digest `latest' has now. With docker:
#        docker pull registry.community.greenbone.net/community/report-formats:latest
#        docker image inspect --format '{{index .RepoDigests 0}}' \
#          registry.community.greenbone.net/community/report-formats:latest
#      Without docker (anonymous token + HEAD of the manifest; the digest comes back in
#      Docker-Content-Digest):
#        T=$(curl -s 'https://registry.community.greenbone.net/service/token?service=harbor-registry&scope=repository:community/report-formats:pull' | python3 -c 'import sys,json; print(json.load(sys.stdin)["token"])')
#        curl -sI -H "Authorization: Bearer $T" -H 'Accept: application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json' \
#          https://registry.community.greenbone.net/v2/community/report-formats/manifests/latest | grep -i docker-content-digest
#   2. replace the digest below and the date above;
#   3. build it BEFORE opening the PR -- nothing in the CI builds this image, the publish does
#      it after the merge:   python3 build-feed-xml.py && docker build report-formats
#   4. the next publish ships the stock report formats of the new base (the layers above it are
#      ours, the rest is Greenbone's): that is what the review of the PR is for.
# Drift is watched every Monday, without blocking anything, by
# .github/workflows/report-formats-base-drift.yml (ci/base-drift.sh): it warns when `latest'
# is no longer this digest and when this digest stops resolving in the registry.
FROM registry.community.greenbone.net/community/report-formats:latest@sha256:031c67736795d3766731aa89946866cbb0aebba5878cb4df8b989fbc13022198

USER root
COPY pdf-suricatoos-*.xml /tmp/suricatoos-formats/

# Install every Suricatoos feed object into every per-release report-formats
# source directory. The count check is the guard described above.
RUN set -eu; \
    count=$(ls -1 /tmp/suricatoos-formats/pdf-suricatoos-*.xml | wc -l); \
    [ "$count" -eq 9 ] || { echo "expected exactly 9 feed XMLs (3 editions x 3 languages), found ${count}: run python3 build-feed-xml.py right before docker build" >&2; exit 1; }; \
    found=0; \
    for d in "${STORAGE_PATH}"/*/report-formats; do \
        [ -d "$d" ] || continue; \
        cp /tmp/suricatoos-formats/pdf-suricatoos-*.xml "$d/"; \
        found=$((found + 1)); \
    done; \
    rm -rf /tmp/suricatoos-formats; \
    echo "Suricatoos: installed ${count} report format(s) into ${found} release dir(s)"; \
    [ "$found" -gt 0 ]
