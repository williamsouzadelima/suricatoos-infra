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
FROM registry.community.greenbone.net/community/report-formats

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
